#!/usr/bin/env bash
#
# scope_filter.sh — Remove out-of-scope domains from a list
#
# Usage:
#   ./scope_filter.sh -s <scope_pattern> -i <input_file> [-o <outfile>]
#   cat all_subs.txt | ./scope_filter.sh -s "example\.com"
#
# Requirements: grep

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") -s <pattern> [-i <input>] [-o <output>]
       cat domains.txt | $(basename "$0") -s <pattern>

Required:
  -s <pattern>      Regex pattern for in-scope domains (e.g. "example\\.com")

Optional:
  -i <file>         Input file (or pipe via stdin)
  -o <outfile>      Output file (default: stdout only)
  -v                Invert: remove matching (keep out-of-scope, drop in-scope)
  -h                Show this help
EOF
    exit 1
}

PATTERN=""
INPUT=""
OUTFILE=""
INVERT=false

while getopts ":s:i:o:vh" opt; do
    case "$opt" in
        s) PATTERN="$OPTARG" ;;
        i) INPUT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        v) INVERT=true ;;
        h) usage ;;
        *) echo "Error: Unknown option -$OPTARG" >&2; usage ;;
    esac
done

if [[ -z "$PATTERN" ]]; then
    echo "Error: Scope pattern is required (-s)" >&2
    usage
fi

GREP_ARGS=(-E "$PATTERN")
if [[ "$INVERT" == true ]]; then
    GREP_ARGS+=(-v)
fi

run_filter() {
    local result
    if [[ ! -t 0 ]]; then
        result=$(grep "${GREP_ARGS[@]}" || true)
    elif [[ -n "$INPUT" ]]; then
        if [[ ! -f "$INPUT" ]]; then
            echo "Error: Input file not found: $INPUT" >&2
            exit 1
        fi
        result=$(grep "${GREP_ARGS[@]}" "$INPUT" || true)
    else
        echo "Error: Provide input with -i or pipe via stdin" >&2
        usage
    fi

    if [[ -n "$OUTFILE" ]]; then
        echo "$result" > "$OUTFILE"
    fi

    echo "$result"
}

run_filter
