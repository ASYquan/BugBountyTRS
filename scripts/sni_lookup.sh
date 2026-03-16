#!/usr/bin/env bash
#
# sni_lookup.sh — Extract subdomains from Kaeferjaeger SNI/TLS data dumps
#
# Kaeferjaeger (kaeferjaeger.gay) publishes SNI scan data in text files with the format:
#   IP -- [hostname1, hostname2, ...]
#
# This script downloads the data (if not cached) and extracts subdomains
# matching a target domain.
#
# Usage:
#   ./sni_lookup.sh -d <domain> [-o <outfile>] [-D <data_dir>] [-f]
#   echo "example.com" | ./sni_lookup.sh [-o <outfile>]
#
# Examples:
#   ./sni_lookup.sh -d dell.com
#   ./sni_lookup.sh -d visma.com -o visma_sni_subs.txt
#   ./sni_lookup.sh -d example.com -f          # force re-download
#   cat targets.txt | ./sni_lookup.sh -o all_subs.txt
#
# Requirements: curl, awk, sed, grep
# Data source: https://kaeferjaeger.gay/?dir=sni-ip-ranges

set -euo pipefail

SNI_BASE_URL="https://kaeferjaeger.gay/sni-ip-ranges"
DEFAULT_DATA_DIR="${HOME}/.cache/bbtrs/sni-data"

usage() {
    cat <<EOF
Usage: $(basename "$0") -d <domain> [options]
       cat domains.txt | $(basename "$0") [options]

Required (one of):
  -d <domain>       Target domain to extract subdomains for
  stdin              Pipe domains, one per line

Options:
  -o <outfile>      Output file (default: stdout only)
  -D <data_dir>     Directory for cached SNI data (default: ${DEFAULT_DATA_DIR})
  -f                Force re-download of SNI data files
  -k <keyword>      Additional keyword filter (e.g. 'staging', 'dev', 'api')
  -x <exclude>      Exclude subdomains matching pattern
  -r                Raw mode — skip download, read from local *.txt in data_dir
  -h                Show this help

Examples:
  $(basename "$0") -d dell.com                     # basic subdomain extraction
  $(basename "$0") -d dell.com -k api              # only subs containing 'api'
  $(basename "$0") -d dell.com -x 'cdn\|static'    # exclude cdn/static subs
  $(basename "$0") -d example.com -r -D ./my_data  # use pre-downloaded data
EOF
    exit 1
}

DOMAIN=""
OUTFILE=""
DATA_DIR="$DEFAULT_DATA_DIR"
FORCE_DOWNLOAD=false
KEYWORD=""
EXCLUDE=""
RAW_MODE=false

while getopts ":d:o:D:k:x:frh" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        D) DATA_DIR="$OPTARG" ;;
        f) FORCE_DOWNLOAD=true ;;
        k) KEYWORD="$OPTARG" ;;
        x) EXCLUDE="$OPTARG" ;;
        r) RAW_MODE=true ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

for cmd in curl awk sed grep; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed" >&2
        exit 1
    fi
done

# Download SNI data files if not cached
download_sni_data() {
    mkdir -p "$DATA_DIR"

    echo "[*] Checking for SNI data updates..." >&2

    # Fetch the index page to find available data files
    local index
    index=$(curl -sf "${SNI_BASE_URL}/" 2>/dev/null) || {
        echo "[!] Failed to fetch SNI data index from ${SNI_BASE_URL}/" >&2
        echo "[*] Trying known file patterns..." >&2
        # Fall back to known file patterns
        for range in "0" "1" "2" "3" "4" "5" "6" "7" "8" "9"; do
            local fname="${range}.txt"
            local fpath="${DATA_DIR}/${fname}"
            if [[ "$FORCE_DOWNLOAD" == true ]] || [[ ! -f "$fpath" ]]; then
                echo "[*] Downloading ${fname}..." >&2
                curl -sfL "${SNI_BASE_URL}/${fname}" -o "$fpath" 2>/dev/null || true
            fi
        done
        return
    }

    # Parse index for .txt file links
    local files
    files=$(echo "$index" | grep -oE 'href="[^"]*\.txt"' | sed 's/href="//;s/"$//' | sort -u)

    if [[ -z "$files" ]]; then
        # Try .gz compressed files
        files=$(echo "$index" | grep -oE 'href="[^"]*\.(txt\.gz|gz)"' | sed 's/href="//;s/"$//' | sort -u)
    fi

    if [[ -z "$files" ]]; then
        echo "[!] No data files found in index. Using existing cached data." >&2
        return
    fi

    local count=0
    for fname in $files; do
        local fpath="${DATA_DIR}/${fname}"

        # Skip if already cached (unless force)
        if [[ "$FORCE_DOWNLOAD" != true ]] && [[ -f "$fpath" || -f "${fpath%.gz}" ]]; then
            continue
        fi

        echo "[*] Downloading ${fname}..." >&2
        if curl -sfL "${SNI_BASE_URL}/${fname}" -o "$fpath" 2>/dev/null; then
            count=$((count + 1))
            # Decompress if gzipped
            if [[ "$fname" == *.gz ]]; then
                gunzip -f "$fpath" 2>/dev/null || true
            fi
        else
            echo "[!] Failed to download ${fname}" >&2
            rm -f "$fpath"
        fi
    done

    echo "[*] Downloaded ${count} new data files" >&2
}

# Extract subdomains for a given domain from SNI data
# Data format: IP -- [hostname1, hostname2, ...]
extract_subs() {
    local target="$1"
    local data_files

    data_files=$(find "$DATA_DIR" -name '*.txt' -type f 2>/dev/null)

    if [[ -z "$data_files" ]]; then
        echo "[!] No SNI data files found in ${DATA_DIR}" >&2
        echo "[*] Run with -f to force download, or -D to specify data directory" >&2
        return 1
    fi

    local count
    count=$(echo "$data_files" | wc -l)
    echo "[*] Searching ${count} data files for ${target}..." >&2

    # Core extraction logic (generalized from Haddix's one-liner):
    #   cat *.txt | grep -F "domain" | awk -F'-- ' '{print $2}' |
    #   tr '[' '' | sed 's/ //' | sed 's/\]//' |
    #   grep -F ".domain" | sort -u
    #
    # Handles the SNI format: IP -- [host1, host2, host3]
    # Splits comma-separated hostnames and filters to target domain
    find "$DATA_DIR" -name '*.txt' -type f -exec cat {} + 2>/dev/null \
        | grep -F "$target" \
        | awk -F' -- ' '{print $2}' \
        | tr -d '[]' \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -F ".${target}" \
        | sort -u
}

# Process a single domain
process_domain() {
    local target="$1"
    local subs

    subs=$(extract_subs "$target") || return 1

    # Apply keyword filter
    if [[ -n "$KEYWORD" ]]; then
        subs=$(echo "$subs" | grep -iF "$KEYWORD" || true)
    fi

    # Apply exclusion filter
    if [[ -n "$EXCLUDE" ]]; then
        subs=$(echo "$subs" | grep -iv "$EXCLUDE" || true)
    fi

    if [[ -z "$subs" ]]; then
        echo "[*] No subdomains found for ${target}" >&2
        return 0
    fi

    local sub_count
    sub_count=$(echo "$subs" | wc -l)
    echo "[+] Found ${sub_count} subdomains for ${target}" >&2

    if [[ -n "$OUTFILE" ]]; then
        echo "$subs" >> "$OUTFILE"
    fi

    echo "$subs"
}

# Download data unless in raw mode
if [[ "$RAW_MODE" != true ]]; then
    download_sni_data
fi

# Process domains
if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" == \#* ]] && continue
        process_domain "$line"
    done
elif [[ -n "$DOMAIN" ]]; then
    process_domain "$DOMAIN"
else
    echo "Error: Provide a domain with -d or pipe domains via stdin" >&2
    usage
fi
