#!/usr/bin/env bash
# Cut a GitHub release for the analyzer and attach the HTML file as a download.
#
# Usage:
#   ./release.sh <tag> [html-file]
#
# Examples:
#   ./release.sh v0.4                       # auto-picks the newest Taegis-NetFlow-Analyzer-*.html
#   ./release.sh v0.4 Taegis-NetFlow-Analyzer-v0.4.html
#
# Requires: gh (authenticated), run from the repo root.
set -euo pipefail

tag="${1:?usage: ./release.sh <tag> [html-file]}"
file="${2:-$(ls -1 Taegis-NetFlow-Analyzer-*.html 2>/dev/null | sort -V | tail -1)}"

[ -n "${file:-}" ] && [ -f "$file" ] || { echo "error: HTML file not found ('$file')" >&2; exit 1; }
command -v gh >/dev/null || { echo "error: gh CLI not found" >&2; exit 1; }

echo "Releasing $tag  (asset: $file)"

gh release create "$tag" "$file" \
  --title "Taegis NetFlow Analyzer $tag" \
  --notes "Single-file, 100% client-side HTML analyzer for Secureworks Taegis XDR exports (FortiGate netflow + M365/Entra auth).

Download the HTML asset below and open it in any browser — no install, no network. See the README for the full feature list."

echo "Done: $(gh release view "$tag" --json url --jq .url)"
