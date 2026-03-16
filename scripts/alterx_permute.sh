#!/usr/bin/env bash
#
# alterx_permute.sh — Generate subdomain permutations with alterx
#
# Usage:
#   ./alterx_permute.sh -i <subdomains.txt> [-o <outfile>]
#   cat subdomains.txt | ./alterx_permute.sh
#   ./scripts/crtsh_subs.sh -d example.com | ./scripts/alterx_permute.sh
#
# Requirements: alterx

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") -i <input_file> [options]
       cat subdomains.txt | $(basename "$0") [options]

Required (one of):
  -i <file>         Input file with subdomains
  stdin              Pipe subdomains, one per line

Options:
  -o <outfile>      Output file (default: stdout only)
  -e                Enrich mode (default: on)
  -h                Show this help
EOF
    exit 1
}

INPUT=""
OUTFILE=""
ENRICH=true

while getopts ":i:o:eh" opt; do
    case "$opt" in
        i) INPUT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        e) ENRICH=true ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

if ! command -v alterx &>/dev/null; then
    echo "Error: alterx is not installed" >&2
    exit 1
fi

build_args() {
    local args=()
    if [[ "$ENRICH" == true ]]; then
        args+=(-enrich)
    fi
    echo "${args[@]}"
}

ALTERX_ARGS=$(build_args)

if [[ ! -t 0 ]]; then
    # Piped input
    if [[ -n "$OUTFILE" ]]; then
        alterx $ALTERX_ARGS | tee "$OUTFILE"
    else
        alterx $ALTERX_ARGS
    fi
elif [[ -n "$INPUT" ]]; then
    if [[ ! -f "$INPUT" ]]; then
        echo "Error: Input file not found: $INPUT" >&2
        exit 1
    fi
    if [[ -n "$OUTFILE" ]]; then
        cat "$INPUT" | alterx $ALTERX_ARGS | tee "$OUTFILE"
    else
        cat "$INPUT" | alterx $ALTERX_ARGS
    fi
else
    echo "Error: Provide input with -i or pipe via stdin" >&2
    usage
fi
