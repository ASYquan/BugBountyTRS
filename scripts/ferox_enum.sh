#!/usr/bin/env bash
#
# ferox_enum.sh — Recursive directory enumeration with feroxbuster
#
# Usage:
#   ./ferox_enum.sh -u <url> [-w <wordlist>] [-t <threads>] [-r <rate>] [-s <scan_limit>] [-o <outfile>] [-A] [-g]
#   echo "https://example.com" | ./ferox_enum.sh
#   cat urls.txt | ./ferox_enum.sh -t 5 -r 10
#
# Supports both CLI args and piped input for automation.
#
# Requirements: feroxbuster

set -euo pipefail

DEFAULT_WORDLIST="/usr/share/wordlists/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt"

usage() {
    cat <<EOF
Usage: $(basename "$0") -u <url> [options]
       cat urls.txt | $(basename "$0") [options]

Required (one of):
  -u <url>          Target URL
  stdin              Pipe URLs, one per line (overrides -u)

Options:
  -w <wordlist>     Wordlist path (default: DirBuster small lowercase)
  -t <threads>      Number of threads (default: 1)
  -r <rate>         Requests per second rate limit (default: 1)
  -s <scan_limit>   Max concurrent scans (default: 5)
  -o <outfile>      Output file (default: <hostname>.ferox.txt)
  -A                Use random User-Agent (default: off, uses Intigriti RoE UA)
  -g                Collect links from response body (default: on)
  -n                Disable auto-recursion
  -e <extensions>   Comma-separated extensions (e.g. php,html,js)
  -x <status>       Status codes to filter out (e.g. 404,403)
  -h                Show this help message

Examples:
  ./ferox_enum.sh -u https://example.com
  ./ferox_enum.sh -u https://example.com -t 5 -r 10 -e php,html
  cat targets.txt | ./ferox_enum.sh -t 3 -r 5
EOF
    exit 1
}

# Defaults
URL=""
WORDLIST="$DEFAULT_WORDLIST"
THREADS=1
RATE=1
SCAN_LIMIT=5
OUTFILE=""
RANDOM_AGENT=false
COLLECT_LINKS=true
NO_RECURSION=false
EXTENSIONS=""
FILTER_STATUS=""

while getopts ":u:w:t:r:s:o:e:x:Agnh" opt; do
    case "$opt" in
        u) URL="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        r) RATE="$OPTARG" ;;
        s) SCAN_LIMIT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        A) RANDOM_AGENT=true ;;
        g) COLLECT_LINKS=true ;;
        n) NO_RECURSION=true ;;
        e) EXTENSIONS="$OPTARG" ;;
        x) FILTER_STATUS="$OPTARG" ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

if ! command -v feroxbuster &>/dev/null; then
    echo "Error: feroxbuster is not installed or not in PATH" >&2
    exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
    echo "Error: Wordlist not found: $WORDLIST" >&2
    exit 1
fi

run_ferox() {
    local target="$1"
    local outfile="$2"

    local args=(
        --url "$target"
        --wordlist "$WORDLIST"
        --threads "$THREADS"
        --rate-limit "$RATE"
        --scan-limit "$SCAN_LIMIT"
        -o "$outfile"
    )

    if [[ "$RANDOM_AGENT" == true ]]; then
        args+=(-A)
    else
        args+=(-a "Intigriti-${INTIGRITI_USERNAME:-YOUR_USERNAME}-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
        args+=(-H "X-Bug-Bounty: Intigriti-${INTIGRITI_USERNAME:-YOUR_USERNAME}")
    fi

    if [[ "$COLLECT_LINKS" == true ]]; then
        args+=(-g)
    fi

    if [[ "$NO_RECURSION" == true ]]; then
        args+=(-n)
    fi

    if [[ -n "$EXTENSIONS" ]]; then
        args+=(-x "$EXTENSIONS")
    fi

    if [[ -n "$FILTER_STATUS" ]]; then
        args+=(--filter-status "$FILTER_STATUS")
    fi

    echo "[*] Target: $target"
    echo "[*] Output: $outfile"
    echo "[*] Threads: $THREADS | Rate: $RATE/s | Scan limit: $SCAN_LIMIT"
    echo ""

    feroxbuster "${args[@]}" || {
        echo "[!] Warning: feroxbuster exited with error for $target" >&2
    }

    echo ""
}

get_outfile() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr ':' '_')
    echo "${hostname}.ferox.txt"
}

# Check if stdin has data (piped input)
if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)  # trim whitespace
        [[ -z "$line" || "$line" == \#* ]] && continue

        outfile="${OUTFILE:-$(get_outfile "$line")}"
        run_ferox "$line" "$outfile"
    done
elif [[ -n "$URL" ]]; then
    outfile="${OUTFILE:-$(get_outfile "$URL")}"
    run_ferox "$URL" "$outfile"
else
    echo "Error: Provide a URL with -u or pipe URLs via stdin" >&2
    usage
fi
