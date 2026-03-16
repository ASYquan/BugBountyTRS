#!/usr/bin/env bash
#
# subfinder_httpx.sh — Discover subdomains and probe with httpx (jhaddix one-liner)
#
# Usage:
#   ./subfinder_httpx.sh -d <domain> [-o <outdir>] [-p <ports>]
#   echo "example.com" | ./subfinder_httpx.sh
#   cat apex_domains.txt | ./subfinder_httpx.sh
#   ./subfinder_httpx.sh -f fisAPEXES
#
# Requirements: subfinder, httpx

set -euo pipefail

DEFAULT_PORTS="80,8080,443,8443,4443,8888"

usage() {
    cat <<EOF
Usage: $(basename "$0") -d <domain> [options]
       $(basename "$0") -f <apex_file> [options]
       cat domains.txt | $(basename "$0") [options]

Required (one of):
  -d <domain>       Single target domain
  -f <file>         File with apex domains (one per line)
  stdin              Pipe domains, one per line

Options:
  -o <outdir>       Output directory (default: current dir)
  -p <ports>        Comma-separated ports (default: $DEFAULT_PORTS)
  -t <threads>      httpx threads (default: 5)
  -r <rate>         httpx rate limit req/sec (default: 20, per Visma RoE)
  -a                Enable subfinder -all sources (default: on)
  -h                Show this help
EOF
    exit 1
}

DOMAIN=""
APEX_FILE=""
OUTDIR="."
PORTS="$DEFAULT_PORTS"
THREADS=5
RATE=20   # Visma RoE: max 20 req/sec
ALL_SOURCES=true

while getopts ":d:f:o:p:t:r:ah" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        f) APEX_FILE="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        p) PORTS="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        r) RATE="$OPTARG" ;;
        a) ALL_SOURCES=true ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

for cmd in subfinder httpx; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed" >&2
        exit 1
    fi
done

mkdir -p "$OUTDIR"

run_scan() {
    local target="$1"
    local outfile="${OUTDIR}/${target}"

    local subfinder_args=(-d "$target")
    if [[ "$ALL_SOURCES" == true ]]; then
        subfinder_args+=(-all)
    fi

    echo "[*] Scanning: $target" >&2

    subfinder "${subfinder_args[@]}" \
        | httpx \
            -status-code \
            -title \
            -content-length \
            -web-server \
            -asn \
            -location \
            -no-color \
            -follow-redirects \
            -t "$THREADS" \
            -rl "$RATE" \
            -ports "$PORTS" \
            -no-fallback \
            -probe-all-ips \
            -random-agent \
            -o "$outfile" \
            -oa || {
        echo "[!] Warning: scan failed for $target" >&2
        return 1
    }

    # Output results to stdout for piping
    if [[ -f "$outfile" ]]; then
        cat "$outfile"
    fi
}

if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        run_scan "$line"
    done
elif [[ -n "$APEX_FILE" ]]; then
    if [[ ! -f "$APEX_FILE" ]]; then
        echo "Error: File not found: $APEX_FILE" >&2
        exit 1
    fi
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        run_scan "$line"
    done < "$APEX_FILE"
elif [[ -n "$DOMAIN" ]]; then
    run_scan "$DOMAIN"
else
    echo "Error: Provide a domain (-d), file (-f), or pipe via stdin" >&2
    usage
fi
