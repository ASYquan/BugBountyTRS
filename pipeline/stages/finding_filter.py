"""Finding filter and deduplication stage.

Consumes raw findings from vuln_findings stream.
Applies:
1. Deduplication (same vuln + same host = one finding)
2. False positive filtering (configurable rules)
3. Severity enrichment (map Nuclei template_id to CVE if available)
4. Status assignment

Filtered findings are stored in the DB. Noise is marked as false_positive.
"""

import re
import hashlib
import json
import logging

from ..core.worker import BaseWorker
from ..core.config import get_config

log = logging.getLogger(__name__)

# Built-in false positive patterns (Nuclei template IDs that are almost always noise)
BUILTIN_FP_TEMPLATES = {
    # Info-level noise
    "waf-detect",
    "tech-detect",
    "favicon-detect",
    "robots-txt",
    "security-txt",
    "sitemap-detect",
    "options-method",
    "trace-method",
    "http-missing-security-headers",
    "missing-x-frame-options",
    "missing-content-type-header",
    "missing-strict-transport-security",
    "missing-x-content-type-options",
    "x-powered-by-header",
    "server-header",
    "cookies-without-secure",
    "cookies-without-httponly",
    "cookies-without-samesite",
}

# Visma-specific out-of-scope findings per their RoE
VISMA_OOS_PATTERNS = [
    r"missing.*security.*header",
    r"weak.*ssl",
    r"expired.*ssl",
    r"csrf.*unauthenticated",
    r"self[_-]xss",
    r"clickjacking",
    r"spf.*dkim.*dmarc",
    r"email.*best.practice",
    r"server.*version.*banner",
    r"non[_-]sensitive.*data.*disclosure",
    r"content.*spoofing.*without",
    r"text.*injection.*without",
    r"csv.*injection",
    r"formula.*injection",
    r"flash.*based",
    r"google.*maps.*api.*key",
    r"host.*header.*injection",
    r"rate.*limit.*non.*auth",
]


class FindingFilterWorker(BaseWorker):
    """Filters, deduplicates, and enriches findings."""

    name = "finding_filter"
    input_stream = "vuln_findings"
    output_streams = []  # Terminal stage — writes to DB

    def on_start(self):
        """Load FP rules from DB on startup."""
        self._fp_rules = self.storage.get_fp_rules()
        self._compiled_visma_oos = [
            re.compile(p, re.IGNORECASE) for p in VISMA_OOS_PATTERNS
        ]
        log.info(f"[filter] Loaded {len(self._fp_rules)} custom FP rules + "
                 f"{len(BUILTIN_FP_TEMPLATES)} built-in + "
                 f"{len(VISMA_OOS_PATTERNS)} Visma OOS patterns")

    def dedup_key(self, data: dict) -> str | None:
        # Don't use the worker-level dedup — we handle it ourselves with DB-level dedup
        return None

    def process(self, data: dict) -> list[dict]:
        program = data.get("program")
        program_id = data.get("program_id")
        subdomain_id = data.get("subdomain_id")
        tool = data.get("tool", "unknown")
        template_id = data.get("template_id", "")
        severity = data.get("severity", "info")
        title = data.get("title", "")
        url = data.get("url", "")
        cve_id = data.get("cve_id")
        cvss_score = data.get("cvss_score")

        # 1. Check false positive rules
        fp_reason = self._check_false_positive(template_id, title, url, severity)
        if fp_reason:
            log.debug(f"[filter] FP filtered: {title} ({fp_reason})")
            # Still store it, but mark as FP for audit trail
            dedup_hash = self._make_dedup_hash(template_id, url, title)
            self.storage.add_finding_deduped(
                program_id,
                dedup_hash=dedup_hash,
                subdomain_id=subdomain_id,
                tool=tool,
                template_id=template_id,
                severity=severity,
                title=title,
                description=data.get("description", fp_reason),
                url=url,
                matched_at=data.get("matched_at", url),
                evidence=data.get("evidence"),
                cve_id=cve_id,
                cvss_score=cvss_score,
                raw=data.get("raw"),
            )
            # Mark as FP
            with self.storage._conn() as conn:
                conn.execute(
                    "UPDATE findings SET false_positive=1 WHERE dedup_hash=?",
                    (dedup_hash,),
                )
            return []

        # 2. Extract CVE from Nuclei template_id if present
        if not cve_id and template_id:
            cve_match = re.search(r"(CVE-\d{4}-\d+)", template_id, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(1).upper()

        # 3. Enrich severity from CVSS if we have a CVE
        if cve_id and not cvss_score:
            cve_record = self.storage.get_cve(cve_id)
            if cve_record:
                cvss_score = cve_record.get("cvss_score")
                if cvss_score:
                    severity = self._cvss_to_severity(cvss_score)

        # 4. Deduplicate: same template + same host = one finding
        dedup_hash = self._make_dedup_hash(template_id or title, url, cve_id or "")
        finding_id = self.storage.add_finding_deduped(
            program_id,
            dedup_hash=dedup_hash,
            subdomain_id=subdomain_id,
            tool=tool,
            template_id=template_id,
            severity=severity,
            title=title,
            description=data.get("description"),
            url=url,
            matched_at=data.get("matched_at", url),
            evidence=data.get("evidence"),
            cve_id=cve_id,
            cvss_score=cvss_score,
            raw=data.get("raw"),
        )

        if finding_id:
            # Link CVE if we have one
            if cve_id:
                self.storage.link_finding_cve(finding_id, cve_id)

            log.info(f"[filter] New finding #{finding_id}: [{severity}] {title} @ {url}"
                     + (f" ({cve_id} CVSS:{cvss_score})" if cve_id else ""))
        else:
            log.debug(f"[filter] Duplicate skipped: {title} @ {url}")

        return []

    def _check_false_positive(self, template_id: str, title: str, url: str, severity: str) -> str | None:
        """Check if a finding matches any FP rule. Returns reason or None."""
        # Built-in template FP list
        if template_id and template_id.lower() in BUILTIN_FP_TEMPLATES:
            return f"Built-in FP: {template_id}"

        # Visma OOS patterns (from their RoE)
        combined = f"{template_id} {title}".lower()
        for pattern in self._compiled_visma_oos:
            if pattern.search(combined):
                return f"Visma OOS: {pattern.pattern}"

        # Custom DB rules
        for rule in self._fp_rules:
            rtype = rule["rule_type"]
            pattern = rule["pattern"]

            try:
                if rtype == "template_id" and template_id:
                    if re.search(pattern, template_id, re.IGNORECASE):
                        return f"Custom rule #{rule['id']}: {rule.get('reason', pattern)}"
                elif rtype == "title" and title:
                    if re.search(pattern, title, re.IGNORECASE):
                        return f"Custom rule #{rule['id']}: {rule.get('reason', pattern)}"
                elif rtype == "url_pattern" and url:
                    if re.search(pattern, url, re.IGNORECASE):
                        return f"Custom rule #{rule['id']}: {rule.get('reason', pattern)}"
                elif rtype == "severity":
                    if severity == pattern:
                        return f"Custom rule #{rule['id']}: severity={pattern} filtered"
            except re.error:
                pass

        return None

    def _make_dedup_hash(self, *parts) -> str:
        """Create a dedup hash from finding components."""
        key = ":".join(str(p) for p in parts if p)
        return hashlib.sha256(key.encode()).hexdigest()

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        return "info"
