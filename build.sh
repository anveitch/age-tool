#!/usr/bin/env bash
#
# build.sh - Cross-compile age-tool for multiple platforms.
#
# Builds the following targets into the ./builds directory:
#   - macOS Apple Silicon (darwin/arm64)
#   - macOS Intel (darwin/amd64)
#   - Windows x64 (windows/amd64)
#   - Linux x64 (linux/amd64)
#

set -e

# Output directory for compiled binaries
BUILD_DIR="./builds"

# Create the builds directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Track which builds succeeded
successful=()

# ─── Build targets ───────────────────────────────────────────────────────────
# Each entry: GOOS GOARCH output_filename

targets=(
  "darwin  arm64  age-tool-macos-arm64"
  "darwin  amd64  age-tool-macos-intel"
  "windows amd64  age-tool-windows-x64.exe"
  "linux   amd64  age-tool-linux-x64"
)

echo "Building age-tool for all targets..."
echo

for target in "${targets[@]}"; do
  # Parse the target fields
  read -r goos goarch output <<< "$target"

  echo "Building: $output (${goos}/${goarch})"

  # Attempt the build, capturing any errors
  if GOOS="$goos" GOARCH="$goarch" go build -o "${BUILD_DIR}/${output}" .; then
    echo "  -> Success: ${BUILD_DIR}/${output}"
    successful+=("$output")
  else
    echo "  -> FAILED: ${output}"
  fi

  echo
done

# ─── Summary ─────────────────────────────────────────────────────────────────

echo "========================================="
echo "Build summary: ${#successful[@]}/${#targets[@]} targets built"
echo "========================================="

if [ ${#successful[@]} -gt 0 ]; then
  for bin in "${successful[@]}"; do
    echo "  ${BUILD_DIR}/${bin}"
  done
else
  echo "  No successful builds."
fi

echo
