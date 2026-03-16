#!/usr/bin/env bash
#
# crtsh_subs.sh — Scrape crt.sh for subdomains (non-wildcard and wildcard modes)
#
# Usage:
#   ./crtsh_subs.sh -d <domain> [-w] [-o <outfile>]
#   echo "example.com" | ./crtsh_subs.sh
#   cat domains.txt | ./crtsh_subs.sh -w
#
# Requirements: curl, jq

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") -d <domain> [options]
       cat domains.txt | $(basename "$0") [options]

Required (one of):
  -d <domain>       Target domain
  stdin              Pipe domains, one per line

Options:
  -w                Extract wildcard subdomains only (strips *. prefix)
  -o <outfile>      Output file (default: stdout only)
  -h                Show this help
EOF
    exit 1
}

DOMAIN=""
WILDCARD=false
OUTFILE=""

while getopts ":d:o:wh" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        w) WILDCARD=true ;;
        o) OUTFILE="$OPTARG" ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed" >&2
        exit 1
    fi
done

scrape_crtsh() {
    local target="$1"
    local results

    results=$(curl -sf "https://crt.sh/json?identity=${target}&exclude=expired" 2>/dev/null) || {
        echo "[!] Warning: crt.sh request failed for $target" >&2
        return 1
    }

    if [[ "$WILDCARD" == true ]]; then
        echo "$results" \
            | jq -r '.[] | (.name_value // "" | split("\n")[]) , (.common_name // "")' \
            | sed 's/\\u002a\\./*./g; s/\r//g' \
            | grep -E '^\*\.' \
            | sed 's/^\*\.//; s/\.$//' \
            | sort -u
    else
        echo "$results" \
            | jq -r '.[].name_value
                     | split("\n")[]
                     | gsub("\r";"")
                     | select(startswith("*.")|not)
                     | select(. != "'"$target"'")
                    ' \
            | sort -u
    fi
}

run_scrape() {
    local target="$1"
    local subs

    subs=$(scrape_crtsh "$target") || return 1

    if [[ -n "$OUTFILE" ]]; then
        echo "$subs" >> "$OUTFILE"
    fi

    # Always output to stdout for piping
    echo "$subs"
}

if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        run_scrape "$line"
    done
elif [[ -n "$DOMAIN" ]]; then
    run_scrape "$DOMAIN"
else
    echo "Error: Provide a domain with -d or pipe domains via stdin" >&2
    usage
fi
