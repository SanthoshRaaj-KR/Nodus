#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [DIR] [--format table|json|sarif]"
  echo "  Scans a directory for known vulnerabilities using osv-scanner."
  exit 1
}

DIR="."
FORMAT="table"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      FORMAT="${2:?missing value for --format}"
      shift 2
      ;;
    -*)
      usage
      ;;
    *)
      DIR="$1"
      shift
      ;;
  esac
done

if ! command -v osv-scanner >/dev/null 2>&1; then
  echo "error: osv-scanner not found. Install it via:" >&2
  echo "  brew install osv-scanner" >&2
  exit 1
fi

osv-scanner scan --recursive "$DIR" --format "$FORMAT"
