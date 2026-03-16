#!/usr/bin/env bash
#
# puredns_brute.sh — Brute-force subdomains with pureDNS
#
# Usage:
#   ./puredns_brute.sh -d <domain> [-w <wordlist>] [-r <resolvers>] [-R <rate>] [-T <trusted_rate>] [-o <outfile>]
#   echo "example.com" | ./puredns_brute.sh
#   cat domains.txt | ./puredns_brute.sh -R 500
#
# Requirements: puredns

set -euo pipefail

DEFAULT_WORDLIST="/usr/share/wordlists/SecLists-master/Discovery/DNS/dns-Jhaddix.txt"
DEFAULT_RESOLVERS="/usr/share/wordlists/resolvers.txt"

usage() {
    cat <<EOF
Usage: $(basename "$0") -d <domain> [options]
       cat domains.txt | $(basename "$0") [options]

Required (one of):
  -d <domain>       Target domain
  stdin              Pipe domains, one per line

Options:
  -w <wordlist>     DNS wordlist (default: dns-Jhaddix.txt)
  -r <resolvers>    Resolvers file (default: /usr/share/wordlists/resolvers.txt)
  -R <rate>         Rate limit for public resolvers (default: 1000)
  -T <rate>         Rate limit for trusted resolvers (default: 300)
  -o <outfile>      Output file (default: <domain>.puredns.txt)
  -h                Show this help
EOF
    exit 1
}

DOMAIN=""
WORDLIST="$DEFAULT_WORDLIST"
RESOLVERS="$DEFAULT_RESOLVERS"
RATE=1000
TRUSTED_RATE=300
OUTFILE=""

while getopts ":d:w:r:R:T:o:h" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        r) RESOLVERS="$OPTARG" ;;
        R) RATE="$OPTARG" ;;
        T) TRUSTED_RATE="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

for cmd in puredns; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed" >&2
        exit 1
    fi
done

run_puredns() {
    local target="$1"
    local outfile="${OUTFILE:-${target}.puredns.txt}"

    puredns bruteforce "$WORDLIST" "$target" \
        --resolvers "$RESOLVERS" \
        --rate-limit "$RATE" \
        --rate-limit-trusted "$TRUSTED_RATE" \
        --write "$outfile" || {
        echo "[!] Warning: puredns failed for $target" >&2
        return 1
    }

    # Output found subs to stdout for piping
    if [[ -f "$outfile" ]]; then
        cat "$outfile"
    fi
}

if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        run_puredns "$line"
    done
elif [[ -n "$DOMAIN" ]]; then
    run_puredns "$DOMAIN"
else
    echo "Error: Provide a domain with -d or pipe domains via stdin" >&2
    usage
fi
