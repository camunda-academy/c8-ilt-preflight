#!/usr/bin/env bash
# Cross-compiles the Layer 1 preflight binary for all target platforms
# (windows/amd64, darwin/amd64, darwin/arm64, linux/amd64) and writes
# SHA-256 checksums into /preflight/releases.
# Stdlib only — no CGO, no external modules, so a customer security team
# can audit the source directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASES_DIR="$SCRIPT_DIR/../releases"
VERSION="${PREFLIGHT_VERSION:-0.2.1}"

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

# Layer 2 entrypoint scripts get their own checksums too. Unlike the .java/
# .cs/.py sources, which only ever run under a signed dotnet/java/python
# interpreter, run.sh/run.cmd are executed directly by the OS -- exactly like
# the binary above -- so an endpoint allowlisting product can gate them the
# same way. A real customer's Application Control blocked layer2/csharp/run.cmd
# outright, and their security team had no published hash to allowlist it by.
# Paths are relative to this release folder's root, matching the shipped ZIP's
# internal layout, so they verify correctly once unzipped.
cd "$SCRIPT_DIR/.."
for stack in csharp java python typescript; do
  sha256sum "layer2/$stack/run.sh" "layer2/$stack/run.cmd" >> "$CHECKSUM_FILE"
done

echo
echo "Done. Artifacts + checksums in $RELEASES_DIR:"
cat "$CHECKSUM_FILE"
echo
echo "NOTE: artifacts are UNSIGNED. Use the checksums above for an allowlist-by-hash rule."
