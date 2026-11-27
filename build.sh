#!/usr/bin/env bash
#
# build.sh - Build age-tool's command-line tool and desktop app.
#
# Usage: ./build.sh [--cli-only]
#
#   --cli-only   skip the desktop app (which needs Docker running)
#
# CLI binaries are built static (CGO disabled), with local paths trimmed and
# debug symbols stripped, so release builds are smaller and reproducible.
#
# Builds the following targets into the ./builds directory:
#   - macOS Apple Silicon (darwin/arm64)
#   - macOS Intel (darwin/amd64)
#   - Windows x64 (windows/amd64)
#   - Linux x64 (linux/amd64)
#   - Linux ARM64 (linux/arm64)
#
# Then the desktop app, as AppImages for Linux x64 and ARM64, built in Docker
# by packaging/linux/build-gui.sh (it needs CGO, so it can't be built like
# the CLI):
#   - age-tool-linux-x64.AppImage
#   - age-tool-linux-arm64.AppImage
#
# Finally, SHA256SUMS lists the SHA256 hash of every file built, so users
# can check their downloads (sha256sum -c SHA256SUMS --ignore-missing).
#
# Exits with an error if anything failed to build.
#

set -e

# Parse the one option
CLI_ONLY=""
case "${1:-}" in
  "") ;;
  --cli-only) CLI_ONLY=1 ;;
  *) echo "usage: $0 [--cli-only]" >&2; exit 2 ;;
esac

# Output directory for compiled binaries
BUILD_DIR="./builds"

# Create the builds directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Track which builds succeeded, and how many were attempted
successful=()
attempted=0

# ─── Build targets ───────────────────────────────────────────────────────────
# Each entry: GOOS GOARCH output_filename

targets=(
  "darwin  arm64  age-tool-macos-arm64"
  "darwin  amd64  age-tool-macos-intel"
  "windows amd64  age-tool-windows-x64.exe"
  "linux   amd64  age-tool-linux-x64"
  "linux   arm64  age-tool-linux-arm64"
)

echo "Building the age-tool CLI for all targets..."
echo

for target in "${targets[@]}"; do
  attempted=$((attempted + 1))
  # Parse the target fields
  read -r goos goarch output <<< "$target"

  echo "Building: $output (${goos}/${goarch})"

  # Attempt the build, capturing any errors. Hardening flags:
  #   CGO_ENABLED=0  fully static binary with no C toolchain or libc dependency
  #   -trimpath      strip local filesystem paths (e.g. /Users/...) from the binary
  #   -s -w          omit symbol table and DWARF debug info (smaller binary)
  if CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
       go build -trimpath -ldflags="-s -w" -o "${BUILD_DIR}/${output}" .; then
    echo "  -> Success: ${BUILD_DIR}/${output}"
    successful+=("$output")
  else
    echo "  -> FAILED: ${output}"
  fi

  echo
done

# ─── Desktop app (AppImages) ─────────────────────────────────────────────────

if [ -z "$CLI_ONLY" ]; then
  echo "Building the age-tool desktop app (AppImages, in Docker)..."
  echo
  for arch in amd64 arm64; do
    attempted=$((attempted + 1))
    case "$arch" in
      amd64) output=age-tool-linux-x64.AppImage ;;
      arm64) output=age-tool-linux-arm64.AppImage ;;
    esac
    if bash ./packaging/linux/build-gui.sh "$BUILD_DIR" "$arch"; then
      successful+=("$output")
    else
      echo "  -> FAILED: ${output}"
    fi
    echo
  done
fi

# ─── Checksums ───────────────────────────────────────────────────────────────

# List the hash of every file built this run, in the standard format read
# by "sha256sum -c" and "shasum -a 256 -c"
if [ ${#successful[@]} -gt 0 ]; then
  (cd "$BUILD_DIR" && shasum -a 256 "${successful[@]}" > SHA256SUMS)
  echo "Checksums written to ${BUILD_DIR}/SHA256SUMS"
  echo
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo "========================================="
echo "Build summary: ${#successful[@]}/${attempted} targets built"
echo "========================================="

if [ ${#successful[@]} -gt 0 ]; then
  for bin in "${successful[@]}"; do
    echo "  ${BUILD_DIR}/${bin}"
  done
else
  echo "  No successful builds."
fi

echo

# Fail if anything didn't build, so release.sh (and anyone else) notices
[ ${#successful[@]} -eq "$attempted" ]
