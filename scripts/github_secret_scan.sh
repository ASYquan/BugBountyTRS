#!/usr/bin/env bash
#
# github_secret_scan.sh — Scan all repos in a GitHub org for secrets using Kingfisher
#
# Usage:
#   ./github_secret_scan.sh -o <org> -t <token> [-f <outfile>] [-p <per_page>] [-d <delay>]
#
# Requirements: curl, jq, kingfisher

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") -o <org> -t <token> [options]

Required:
  -o <org>        GitHub organization name
  -t <token>      GitHub personal access token (or set GITHUB_TOKEN env var)

Options:
  -f <outfile>    Output file (default: kingfisher_<org>_secretscan.txt)
  -p <per_page>   Repos per API page, max 100 (default: 100)
  -d <delay>      Delay in seconds between scans to avoid rate limits (default: 0)
  -h              Show this help message
EOF
    exit 1
}

# Defaults
ORG=""
TOKEN="${GITHUB_TOKEN:-}"
OUTFILE=""
PER_PAGE=100
DELAY=0

while getopts ":o:t:f:p:d:h" opt; do
    case "$opt" in
        o) ORG="$OPTARG" ;;
        t) TOKEN="$OPTARG" ;;
        f) OUTFILE="$OPTARG" ;;
        p) PER_PAGE="$OPTARG" ;;
        d) DELAY="$OPTARG" ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

if [[ -z "$ORG" ]]; then
    echo "Error: Organization name is required (-o)" >&2
    usage
fi

if [[ -z "$TOKEN" ]]; then
    echo "Error: GitHub token is required (-t or GITHUB_TOKEN env var)" >&2
    usage
fi

for cmd in curl jq kingfisher; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed or not in PATH" >&2
        exit 1
    fi
done

if [[ -z "$OUTFILE" ]]; then
    OUTFILE="kingfisher_${ORG}_secretscan.txt"
fi

echo "[*] Scanning repos for org: $ORG"
echo "[*] Output file: $OUTFILE"
echo ""

page=1
total_repos=0

while true; do
    repos=$(curl -sf \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: token $TOKEN" \
        "https://api.github.com/orgs/${ORG}/repos?per_page=${PER_PAGE}&page=${page}" 2>&1) || {
        echo "Error: GitHub API request failed on page $page" >&2
        echo "Response: $repos" >&2
        exit 1
    }

    count=$(echo "$repos" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        break
    fi

    echo "[*] Page $page: found $count repos"

    while IFS= read -r clone_url; do
        total_repos=$((total_repos + 1))
        echo "  [>] Scanning ($total_repos): $clone_url"
        kingfisher scan --git-url "$clone_url" >> "$OUTFILE" 2>&1 || {
            echo "  [!] Warning: kingfisher failed on $clone_url" >&2
        }

        if [[ "$DELAY" -gt 0 ]]; then
            sleep "$DELAY"
        fi
    done < <(echo "$repos" | jq -r '.[].clone_url')

    page=$((page + 1))
done

echo ""
echo "[*] Done. Scanned $total_repos repos. Results in: $OUTFILE"
