#!/usr/bin/env bash
#
# build-gui.sh - Build the Linux desktop app (age-tool-gui) as AppImages.
#
# Usage: packaging/linux/build-gui.sh [--test] <output dir> [amd64] [arm64]
#
#   --test   also run the full test suite inside each Linux container first
#
# With no architectures given, both are built. Writes, for each one:
#
#   <output dir>/age-tool-linux-x64.AppImage     (amd64: most PCs)
#   <output dir>/age-tool-linux-arm64.AppImage   (arm64: ARM machines)
#
# Fyne needs CGO and the Linux graphics libraries, so the build runs in the
# container described by Dockerfile (decision D3). Docker must be running.
# The amd64 build runs under emulation on an Apple Silicon Mac, so it takes
# a few minutes.
#
# An AppImage is the AppImage runtime (a small program that mounts the
# rest of the file and starts the app) followed by a SquashFS image of the
# app's files. Both parts are built from pinned, verified inputs: the
# runtime is checked against its hash in the Dockerfile, and the app's
# files come from this repository.
#

set -euo pipefail

# Folder holding this script and the Dockerfile, and the repository root
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

# ─── Arguments ───────────────────────────────────────────────────────────────

RUN_TESTS=""
if [ "${1:-}" = "--test" ]; then
  RUN_TESTS=1
  shift
fi
[ $# -ge 1 ] || { echo "usage: $0 [--test] <output dir> [amd64] [arm64]" >&2; exit 2; }
OUT=$1
shift
ARCHES=("$@")
[ ${#ARCHES[@]} -gt 0 ] || ARCHES=(amd64 arm64)

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

command -v docker >/dev/null 2>&1 || { echo "Docker is not installed." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop and try again." >&2; exit 1; }

# The container builds offline against the Mac's module cache (mounted
# read-only), so make sure every module is downloaded first
(cd "$REPO" && go mod download)
GOMODCACHE_DIR=$(cd "$REPO" && go env GOMODCACHE)

# ─── Build each architecture ─────────────────────────────────────────────────

for arch in "${ARCHES[@]}"; do
  case "$arch" in
    amd64) name=age-tool-linux-x64.AppImage ;;
    arm64) name=age-tool-linux-arm64.AppImage ;;
    *) echo "unknown architecture: $arch (use amd64 or arm64)" >&2; exit 2 ;;
  esac
  image="age-tool-linux-build:${arch}"

  echo "Building ${name} (linux/${arch})"

  # Build (or reuse, if nothing changed) the build image for this
  # architecture
  docker buildx build --quiet --platform "linux/${arch}" -t "$image" --load "$HERE" >/dev/null

  # Inside the container:
  #   1. optionally run the tests
  #   2. build age-tool-gui (stripped, without local paths)
  #   3. lay out the AppDir with the desktop entry and icons
  #   4. pack it as SquashFS (zstd), with fixed timestamps and root
  #      ownership so the same source gives the same image
  #   5. join the runtime and the image into the AppImage
  # The repository and module cache are read-only; a named volume keeps
  # Go's build cache between runs so rebuilds are quicker.
  docker run --rm --platform "linux/${arch}" \
    -v "$REPO":/src:ro \
    -v "$GOMODCACHE_DIR":/gomod:ro \
    -v "age-tool-gocache-${arch}":/root/.cache/go-build \
    -v "$OUT":/out \
    -e GOMODCACHE=/gomod -e GOFLAGS="-mod=readonly -buildvcs=false" -e GOPROXY=off \
    -e RUN_TESTS="$RUN_TESTS" -e NAME="$name" \
    "$image" bash -euo pipefail -c '
      if [ -n "$RUN_TESTS" ]; then go test ./...; fi
      work=$(mktemp -d)
      go build -trimpath -ldflags="-s -w" -o "$work/age-tool-gui" ./cmd/age-tool-gui
      go run ./packaging/linux/appdir "$work/AppDir" "$work/age-tool-gui"
      mksquashfs "$work/AppDir" "$work/app.squashfs" \
        -root-owned -noappend -comp zstd -Xcompression-level 19 \
        -mkfs-time 0 -all-time 0 -quiet -no-progress
      cat /opt/appimage/runtime "$work/app.squashfs" > "/out/$NAME.tmp"
      chmod 755 "/out/$NAME.tmp"
      mv "/out/$NAME.tmp" "/out/$NAME"
    '
  echo "  -> ${OUT}/${name}"
done
