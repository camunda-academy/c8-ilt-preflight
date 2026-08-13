#!/usr/bin/env bash
# Cross-compiles the Layer 1 preflight binary for all target platforms
# (windows/amd64, darwin/amd64, darwin/arm64, linux/amd64) and writes
# SHA-256 checksums into /preflight/releases.
# Stdlib only — no CGO, no external modules, so a customer security team
# can audit the source directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASES_DIR="$SCRIPT_DIR/../releases"
VERSION="${PREFLIGHT_VERSION:-0.2}"

mkdir -p "$RELEASES_DIR"
cd "$SCRIPT_DIR"

declare -a TARGETS=(
  "windows amd64 .exe"
  "darwin  amd64 "
  "darwin  arm64 "
  "linux   amd64 "
)

CHECKSUM_FILE="$RELEASES_DIR/SHA256SUMS.txt"
: > "$CHECKSUM_FILE"

for target in "${TARGETS[@]}"; do
  read -r goos goarch ext <<< "$target"
  out="preflight-${goos}-${goarch}${ext}"
  echo "Building $out ..."
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -ldflags "-s -w -X main.ToolVersion=${VERSION}" \
    -o "$RELEASES_DIR/$out" ./cmd/preflight
done

echo "Computing checksums ..."
cd "$RELEASES_DIR"
# Only the artifacts we just built — NOT a bare preflight-* glob, which on
# Windows also catches the "preflight-windows-amd64.exe~" backup the OS leaves
# when go build overwrites a locked/old exe (that stray entry then pollutes
# SHA256SUMS and the allowlist-by-hash guidance derived from it).
for target in "${TARGETS[@]}"; do
  read -r goos goarch ext <<< "$target"
  sha256sum "preflight-${goos}-${goarch}${ext}" >> "SHA256SUMS.txt"
done

echo
echo "Done. Artifacts + checksums in $RELEASES_DIR:"
cat "$CHECKSUM_FILE"
echo
echo "NOTE: artifacts are UNSIGNED. Use the checksums above for an allowlist-by-hash rule."
