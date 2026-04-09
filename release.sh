#!/usr/bin/env bash
#
# release.sh - Automate the age-tool release process.
#
# This script:
#   1. Prompts for a version number and release notes
#   2. Updates the appVersion constant in main.go and commits the change
#   3. Builds all platform binaries via build.sh
#   4. Calculates SHA256 hashes for macOS binaries
#   5. Creates a GitHub release with all binaries attached
#   6. Updates the Homebrew formula with new version, URLs, and hashes
#   7. Commits and pushes the updated formula
#   8. Prints a summary with upgrade instructions
#

set -e

# ─── Configuration ───────────────────────────────────────────────────────────

BUILD_DIR="./builds"
FORMULA_PATH="/Users/andy/export/Development/homebrew-age-tool/Formula/age-tool.rb"
GITHUB_REPO="anveitch/age-tool"

# Binary filenames (must match build.sh output)
ARM64_BIN="age-tool-macos-arm64"
INTEL_BIN="age-tool-macos-intel"
LINUX_BIN="age-tool-linux-x64"
WINDOWS_BIN="age-tool-windows-x64.exe"

# ─── Helper functions ────────────────────────────────────────────────────────

# Print an error message and exit
die() {
  echo "ERROR: $1" >&2
  exit 1
}

# Print a step header
step() {
  echo
  echo "──── $1 ────"
}

# ─── Step 1: Collect version number and release notes ────────────────────────

step "Release Details"

read -rp "Version number (e.g. 1.1.0): " VERSION
[ -z "$VERSION" ] && die "Version number cannot be empty."

# Validate version format (basic check for x.y.z)
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  die "Invalid version format. Expected x.y.z (e.g. 1.1.0)"
fi

TAG="v${VERSION}"

echo
echo "Enter release notes (press Ctrl+D when done):"
RELEASE_NOTES=$(cat)
[ -z "$RELEASE_NOTES" ] && die "Release notes cannot be empty."

echo
echo "Version: $VERSION (tag: $TAG)"
echo "Release notes:"
echo "$RELEASE_NOTES"
echo
read -rp "Proceed with release? [y/N]: " CONFIRM
[ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ] && die "Release cancelled."

# ─── Step 2: Update version in main.go ───────────────────────────────────────

step "Updating Version in main.go"

# Replace the hardcoded appVersion constant in main.go with the new version
if ! grep -q 'const appVersion = ' main.go; then
  die "Could not find appVersion constant in main.go"
fi

sed -i '' "s|const appVersion = \".*\"|const appVersion = \"${VERSION}\"|" main.go \
  || die "Failed to update version in main.go"

echo "Updated appVersion to \"${VERSION}\" in main.go"

# Commit the version bump to the age-tool repo
git add main.go || die "Failed to stage main.go"
git commit -m "Bump version to ${TAG}" || die "Failed to commit version bump"

echo "Version bump committed."

# ─── Step 3: Build all platform binaries ────────────────────────────────────

step "Building Binaries"

if [ ! -f "./build.sh" ]; then
  die "build.sh not found in current directory."
fi

bash ./build.sh || die "Build failed. Fix errors and try again."

# Verify all expected binaries exist
for bin in "$ARM64_BIN" "$INTEL_BIN" "$LINUX_BIN" "$WINDOWS_BIN"; do
  [ -f "${BUILD_DIR}/${bin}" ] || die "Expected binary not found: ${BUILD_DIR}/${bin}"
done

echo "All binaries built successfully."

# ─── Step 4: Calculate SHA256 hashes for macOS binaries ──────────────────────

step "Calculating SHA256 Hashes"

ARM64_SHA256=$(shasum -a 256 "${BUILD_DIR}/${ARM64_BIN}" | awk '{print $1}')
INTEL_SHA256=$(shasum -a 256 "${BUILD_DIR}/${INTEL_BIN}" | awk '{print $1}')

echo "  ${ARM64_BIN}: ${ARM64_SHA256}"
echo "  ${INTEL_BIN}: ${INTEL_SHA256}"

# ─── Step 5: Create GitHub release with binaries ─────────────────────────────

step "Creating GitHub Release"

# Check that gh CLI is available
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) is not installed. Install it from https://cli.github.com/"

# Check that we're authenticated
gh auth status >/dev/null 2>&1 || die "Not authenticated with GitHub CLI. Run 'gh auth login' first."

# Create the release and upload all four binaries
gh release create "$TAG" \
  "${BUILD_DIR}/${ARM64_BIN}" \
  "${BUILD_DIR}/${INTEL_BIN}" \
  "${BUILD_DIR}/${LINUX_BIN}" \
  "${BUILD_DIR}/${WINDOWS_BIN}" \
  --repo "$GITHUB_REPO" \
  --title "age-tool ${TAG}" \
  --notes "$RELEASE_NOTES" \
  || die "Failed to create GitHub release."

echo "GitHub release ${TAG} created successfully."

# ─── Step 6: Update the Homebrew formula ─────────────────────────────────────

step "Updating Homebrew Formula"

[ -f "$FORMULA_PATH" ] || die "Homebrew formula not found at: ${FORMULA_PATH}"

# Build the new download URLs
ARM64_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${ARM64_BIN}"
INTEL_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${INTEL_BIN}"

# Update version number
sed -i '' "s|version \".*\"|version \"${VERSION}\"|" "$FORMULA_PATH" \
  || die "Failed to update version in formula."

# Update arm64 URL and SHA256 (the arm64 block appears first in the formula)
sed -i '' "s|url \"https://github.com/${GITHUB_REPO}/releases/download/v[^\"]*/${ARM64_BIN}\"|url \"${ARM64_URL}\"|" "$FORMULA_PATH" \
  || die "Failed to update arm64 URL in formula."

# Update Intel URL and SHA256 (the Intel block appears second)
sed -i '' "s|url \"https://github.com/${GITHUB_REPO}/releases/download/v[^\"]*/${INTEL_BIN}\"|url \"${INTEL_URL}\"|" "$FORMULA_PATH" \
  || die "Failed to update Intel URL in formula."

# Update SHA256 hashes — arm64 hash comes first, Intel hash second.
# Use a counter to replace them in order.
FIRST_SHA_DONE=false
while IFS= read -r line; do
  if echo "$line" | grep -q 'sha256 "'; then
    if [ "$FIRST_SHA_DONE" = false ]; then
      # First sha256 line is for arm64
      echo "  sha256 \"${ARM64_SHA256}\""
      FIRST_SHA_DONE=true
    else
      # Second sha256 line is for Intel
      echo "  sha256 \"${INTEL_SHA256}\""
    fi
  else
    echo "$line"
  fi
done < "$FORMULA_PATH" > "${FORMULA_PATH}.tmp"

mv "${FORMULA_PATH}.tmp" "$FORMULA_PATH" \
  || die "Failed to write updated formula."

echo "Formula updated:"
echo "  Version: ${VERSION}"
echo "  arm64 SHA256: ${ARM64_SHA256}"
echo "  Intel SHA256: ${INTEL_SHA256}"

# ─── Step 7: Commit and push the updated formula ────────────────────────────

step "Committing and Pushing Formula"

FORMULA_DIR=$(dirname "$FORMULA_PATH")
FORMULA_REPO_DIR=$(cd "$FORMULA_DIR/.." && pwd)

cd "$FORMULA_REPO_DIR" || die "Could not change to formula repo directory."

git add Formula/age-tool.rb \
  || die "Failed to stage formula changes."

git commit -m "Update age-tool to ${TAG}" \
  || die "Failed to commit formula changes."

git push \
  || die "Failed to push formula changes."

echo "Formula committed and pushed successfully."

# Return to the original directory
cd - > /dev/null

# ─── Step 8: Print release summary ──────────────────────────────────────────

step "Release Summary"

echo
echo "========================================="
echo "  age-tool ${TAG} released successfully"
echo "========================================="
echo
echo "  Version:  ${VERSION}"
echo "  Tag:      ${TAG}"
echo
echo "  Binaries uploaded:"
echo "    - ${ARM64_BIN}  (sha256: ${ARM64_SHA256})"
echo "    - ${INTEL_BIN}  (sha256: ${INTEL_SHA256})"
echo "    - ${LINUX_BIN}"
echo "    - ${WINDOWS_BIN}"
echo
echo "  Homebrew formula updated:"
echo "    ${FORMULA_PATH}"
echo
echo "  Users can install or upgrade with:"
echo "    brew tap anveitch/age-tool"
echo "    brew install age-tool"
echo "    brew upgrade age-tool"
echo
echo "  Release page:"
echo "    https://github.com/${GITHUB_REPO}/releases/tag/${TAG}"
echo
