#!/usr/bin/env bash
#
# vhost_fuzz.sh — Virtual host fuzzing with ffuf
#
# Usage:
#   ./vhost_fuzz.sh -u <url> [-w <wordlist>] [-o <outfile>] [-fc <codes>]
#   echo "https://example.com" | ./vhost_fuzz.sh
#
# Requirements: ffuf

set -euo pipefail

DEFAULT_WORDLIST="/usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"

usage() {
    cat <<EOF
Usage: $(basename "$0") -u <url> [options]
       cat targets.txt | $(basename "$0") [options]

Required (one of):
  -u <url>          Target URL (e.g. https://example.com)
  stdin              Pipe URLs, one per line

Options:
  -w <wordlist>     Wordlist for FUZZ (default: subdomains-top1million-5000.txt)
  -o <outfile>      Output file (default: <hostname>.vhosts.json)
  -fc <codes>       Filter HTTP status codes (e.g. 404,302)
  -fs <size>        Filter response size
  -t <threads>      Threads (default: 5)
  -r <rate>         Rate limit requests/sec (default: 20, per Visma RoE)
  -h                Show this help
EOF
    exit 1
}

URL=""
WORDLIST="$DEFAULT_WORDLIST"
OUTFILE=""
FILTER_CODE=""
FILTER_SIZE=""
THREADS=5
RATE=20   # Visma RoE: max 20 req/sec

while getopts ":u:w:o:t:r:h" opt; do
    case "$opt" in
        u) URL="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        r) RATE="$OPTARG" ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

# Handle long-style args that getopts can't parse
for arg in "$@"; do
    case "$arg" in
        -fc) shift; FILTER_CODE="$1"; shift ;;
        -fs) shift; FILTER_SIZE="$1"; shift ;;
    esac 2>/dev/null || true
done

if ! command -v ffuf &>/dev/null; then
    echo "Error: ffuf is not installed" >&2
    exit 1
fi

run_ffuf() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's|https?://||; s|/.*||; s|:.*||')
    local outfile="${OUTFILE:-${hostname}.vhosts.json}"

    local args=(
        -u "$target"
        -H "Host: FUZZ.${hostname}"
        -H "User-Agent: Intigriti-${INTIGRITI_USERNAME:-YOUR_USERNAME}-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
        -H "X-Bug-Bounty: Intigriti-${INTIGRITI_USERNAME:-YOUR_USERNAME}"
        -w "$WORDLIST"
        -o "$outfile"
        -of json
        -t "$THREADS"
    )

    if [[ "$RATE" -gt 0 ]]; then
        args+=(-rate "$RATE")
    fi

    if [[ -n "$FILTER_CODE" ]]; then
        args+=(-fc "$FILTER_CODE")
    fi

    if [[ -n "$FILTER_SIZE" ]]; then
        args+=(-fs "$FILTER_SIZE")
    fi

    echo "[*] VHost fuzzing: $target" >&2
    echo "[*] Output: $outfile" >&2

    ffuf "${args[@]}" || {
        echo "[!] Warning: ffuf failed for $target" >&2
        return 1
    }

    # Output found vhosts to stdout for piping
    if [[ -f "$outfile" ]]; then
        jq -r '.results[]?.host // empty' "$outfile" 2>/dev/null
    fi
}

if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        run_ffuf "$line"
    done
elif [[ -n "$URL" ]]; then
    run_ffuf "$URL"
else
    echo "Error: Provide a URL with -u or pipe URLs via stdin" >&2
    usage
fi
