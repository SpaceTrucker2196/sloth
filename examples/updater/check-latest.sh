#!/usr/bin/env bash
# Reference fetcher for sloth's --check-manifest.
#
# Queries the GitHub releases API for the latest sloth release and
# writes a small manifest that the sloth binary reads with
# `--check-manifest FILE`. sloth itself never touches the network —
# this script is deliberately a separate process so operator-managed
# infrastructure (systemd timer, cron, whatever your policy allows)
# can be swapped in without recompiling.
#
# Usage:
#   check-latest.sh [OUTPUT_PATH]
#
#   OUTPUT_PATH defaults to /var/lib/sloth/version-manifest.json.
#
# Requirements:
#   - curl (for the HTTPS fetch)
#   - jq   (to extract fields from the GitHub response)
#
# Trust model:
#   - HTTPS to api.github.com is TLS-authenticated.
#   - If your policy demands stronger integrity, wrap this script in
#     something that verifies the release tarball's signature/hash
#     against a checked-in public key before writing the manifest.
#
# Suggested systemd timer:
#
#   /etc/systemd/system/sloth-version-check.service
#     [Service]
#     Type=oneshot
#     ExecStart=/usr/local/lib/sloth/check-latest.sh
#     User=nobody
#
#   /etc/systemd/system/sloth-version-check.timer
#     [Timer]
#     OnBootSec=1min
#     OnUnitActiveSec=6h
#     Persistent=true
#     [Install]
#     WantedBy=timers.target

set -euo pipefail

OUT="${1:-/var/lib/sloth/version-manifest.json}"
REPO="SpaceTrucker2196/sloth"
API="https://api.github.com/repos/${REPO}/releases/latest"

command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v jq   >/dev/null || { echo "jq is required" >&2; exit 2; }

# The atomic-write pattern below (write to a sibling temp file, then
# rename) guarantees the sloth process never observes a partially
# written manifest — the rename(2) is atomic on the same filesystem.
TMP="${OUT}.tmp.$$"
trap 'rm -f "$TMP"' EXIT

# GitHub returns 200 with the release JSON on success, or 404 if the
# repo has no releases yet. Anything else is a hard failure.
resp="$(curl --silent --show-error --fail --max-time 15 "$API")"

tag="$(printf '%s' "$resp" | jq -r '.tag_name')"
url="$(printf '%s' "$resp" | jq -r '.html_url')"

# Strip a leading "v" if present so the manifest carries a pure semver.
version="${tag#v}"
version="${version#V}"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$TMP" <<JSON
{
  "latest": "$version",
  "url":    "$url",
  "checked_at": "$now"
}
JSON

mkdir -p "$(dirname "$OUT")"
mv "$TMP" "$OUT"

echo "wrote $OUT (latest=$version)"
