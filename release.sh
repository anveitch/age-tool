#!/usr/bin/env bash
#
# release.sh - Automate the age-tool release process.
#
# This script:
#   1. Prompts for a version number (x.y.z, or x.y.z-rc.N for a test
#      pre-release) and release notes
#   2. Runs pre-flight checks (tools, auth, Docker, branch, clean trees,
#      govulncheck known-vulnerability scans, tag unused) before anything
#      is modified
#   3. Updates the shared Version constant in internal/core/version.go
#      (used by both the CLI and the desktop app)
#   4. Builds the CLI binaries, the desktop app AppImages and SHA256SUMS via
#      build.sh (reverts version.go on failure)
#   5. Calculates SHA256 hashes for macOS binaries
#   6. Commits the version bump, pushes it, then creates and pushes an
#      annotated tag on that exact commit
#   7. Creates a GitHub release from the pushed tag with all binaries, the
#      AppImages and SHA256SUMS attached (marked as a pre-release for rc
#      versions)
#   8. Updates the Homebrew formula (CLI only) with new version, URLs, and
#      hashes; skipped for pre-releases, so Homebrew stays on the last
#      full release
#   9. Commits and pushes the updated formula (skipped for pre-releases)
#  10. Prints a summary with upgrade instructions
#
# Full releases are made from master. Pre-releases may be made from any
# branch (for 2.0, the v2 branch), so testers can try them before merging.
#

set -eo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

BUILD_DIR="./builds"
FORMULA_PATH="/Users/andy/export/Development/homebrew-age-tool/Formula/age-tool.rb"
GITHUB_REPO="anveitch/age-tool"
RELEASE_BRANCH="master"

# Binary filenames (must match build.sh output)
ARM64_BIN="age-tool-macos-arm64"
INTEL_BIN="age-tool-macos-intel"
LINUX_BIN="age-tool-linux-x64"
LINUX_ARM64_BIN="age-tool-linux-arm64"
WINDOWS_BIN="age-tool-windows-x64.exe"

# Desktop app AppImages and the checksum file (must match build.sh output)
APPIMAGE_X64="age-tool-linux-x64.AppImage"
APPIMAGE_ARM64="age-tool-linux-arm64.AppImage"
SUMS_FILE="SHA256SUMS"

# File holding the version constant shared by the CLI and the desktop app
VERSION_FILE="internal/core/version.go"

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

# Fail if a git repo has uncommitted changes to tracked files.
# Untracked files (e.g. .DS_Store) are ignored.
require_clean_tree() {
  local repo_dir="$1" label="$2"
  if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
    die "${label} has uncommitted changes. Commit or stash them first."
  fi
}

# Fail if a git repo's current branch is behind its upstream.
require_not_behind() {
  local repo_dir="$1" label="$2"
  git -C "$repo_dir" fetch --quiet origin || die "Failed to fetch ${label} from origin."
  local behind
  behind=$(git -C "$repo_dir" rev-list --count HEAD..@{u} 2>/dev/null) \
    || die "${label} has no upstream branch configured."
  [ "$behind" -eq 0 ] || die "${label} is ${behind} commit(s) behind origin. Pull first."
}

# ─── Step 1: Collect version number and release notes ────────────────────────

step "Release Details"

read -rp "Version number (e.g. 2.0.0, or 2.0.0-rc.1 for a test release): " VERSION
[ -z "$VERSION" ] && die "Version number cannot be empty."

# Validate version format: x.y.z, or x.y.z-rc.N for a pre-release
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
  die "Invalid version format. Expected x.y.z (e.g. 2.0.0) or x.y.z-rc.N (e.g. 2.0.0-rc.1)"
fi

# Release candidates are GitHub pre-releases and don't touch Homebrew
PRERELEASE=""
case "$VERSION" in
  *-rc.*) PRERELEASE=1 ;;
esac

TAG="v${VERSION}"

# ─── Step 2: Pre-flight checks (nothing is modified yet) ─────────────────────

step "Pre-flight Checks"

# Required tools
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) is not installed. Install it from https://cli.github.com/"
command -v go >/dev/null 2>&1 || die "Go is not installed."
command -v govulncheck >/dev/null 2>&1 \
  || die "govulncheck is not installed. Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest"
command -v docker >/dev/null 2>&1 || die "Docker is not installed (needed to build the desktop app)."
docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop first (needed to build the desktop app)."
gh auth status >/dev/null 2>&1 || die "Not authenticated with GitHub CLI. Run 'gh auth login' first."

# Required files
[ -f "./main.go" ]  || die "main.go not found. Run this script from the age-tool repo root."
[ -f "./build.sh" ] || die "build.sh not found in current directory."
grep -q '^const Version = ' "$VERSION_FILE" || die "Could not find the Version constant in ${VERSION_FILE}"

# age-tool repo must be clean and not behind origin. Full releases must
# come from the release branch; pre-releases can come from any branch.
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ -z "$PRERELEASE" ]; then
  [ "$CURRENT_BRANCH" = "$RELEASE_BRANCH" ] \
    || die "Must be on '${RELEASE_BRANCH}' to release (currently on '${CURRENT_BRANCH}')."
fi
require_clean_tree "." "age-tool repo"
require_not_behind "." "age-tool repo"

# Homebrew tap repo must be clean and not behind origin (full releases only)
if [ -z "$PRERELEASE" ]; then
  [ -f "$FORMULA_PATH" ] || die "Homebrew formula not found at: ${FORMULA_PATH}"
  FORMULA_REPO_DIR=$(cd "$(dirname "$FORMULA_PATH")/.." && pwd)
  require_clean_tree "$FORMULA_REPO_DIR" "Homebrew tap repo"
  require_not_behind "$FORMULA_REPO_DIR" "Homebrew tap repo"
fi

# Known-vulnerability scan. The release is blocked on ANY finding — including
# vulnerabilities in the Go standard library or dependencies that our code
# doesn't call — because that code is still compiled into the shipped
# binaries. govulncheck's exit code only reflects vulnerabilities our code
# calls, so findings are counted from its JSON output instead.
echo "Running govulncheck (this may take a moment)..."
if ! VULN_JSON=$(govulncheck -format json ./... 2>&1); then
  echo "$VULN_JSON" >&2
  die "govulncheck failed to run."
fi
VULN_COUNT=$(echo "$VULN_JSON" | grep -c '"finding"' || true)
if [ "$VULN_COUNT" -gt 0 ]; then
  echo
  govulncheck -show verbose ./... || true
  die "govulncheck reported ${VULN_COUNT} finding(s). Update Go and/or dependencies (go get -u ./... && go mod tidy) and re-run."
fi

# Second scan, by module. The scan above loads the code as it builds on
# this Mac, so it can't see the desktop app's Linux-only code (Fyne's
# Linux window and graphics driver needs CGO for Linux). Scanning every
# module the project requires covers those too, whatever platform uses them.
if ! VULN_JSON=$(govulncheck -scan module -format json 2>&1); then
  echo "$VULN_JSON" >&2
  die "govulncheck (module scan) failed to run."
fi
VULN_COUNT=$(echo "$VULN_JSON" | grep -c '"finding"' || true)
if [ "$VULN_COUNT" -gt 0 ]; then
  echo
  govulncheck -scan module -show verbose || true
  die "govulncheck module scan reported ${VULN_COUNT} finding(s). Update dependencies (go get -u ./... && go mod tidy) and re-run."
fi
echo "govulncheck: no known vulnerabilities."

# The tag must not already exist locally, on the remote, or as a release
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null \
  && die "Tag ${TAG} already exists locally."
[ -n "$(git ls-remote --tags origin "refs/tags/${TAG}")" ] \
  && die "Tag ${TAG} already exists on origin."
gh release view "$TAG" --repo "$GITHUB_REPO" >/dev/null 2>&1 \
  && die "GitHub release ${TAG} already exists."

echo "All pre-flight checks passed."

# Show any local commits that will be pushed along with this release
UNPUSHED=$(git log --oneline @{u}..HEAD)
if [ -n "$UNPUSHED" ]; then
  echo
  echo "NOTE: These unpushed local commits will be included in the release:"
  echo "$UNPUSHED" | sed 's/^/  /'
fi

# ─── Release notes and confirmation ──────────────────────────────────────────

echo
echo "Enter release notes (press Ctrl+D when done):"
RELEASE_NOTES=$(cat)
[ -z "$RELEASE_NOTES" ] && die "Release notes cannot be empty."

echo
echo "Version: $VERSION (tag: $TAG) from branch ${CURRENT_BRANCH}"
if [ -n "$PRERELEASE" ]; then
  echo "This is a PRE-RELEASE: marked as such on GitHub, Homebrew is not updated."
fi
echo "Release notes:"
echo "$RELEASE_NOTES"
echo
read -rp "Proceed with release? [y/N]: " CONFIRM
[ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ] && die "Release cancelled."

# ─── Step 3: Update the shared version ───────────────────────────────────────

step "Updating Version in ${VERSION_FILE}"

# Replace the Version constant shared by the CLI and the desktop app
sed -i '' "s|^const Version = \".*\"|const Version = \"${VERSION}\"|" "$VERSION_FILE" \
  || die "Failed to update version in ${VERSION_FILE}"
grep -qF "const Version = \"${VERSION}\"" "$VERSION_FILE" \
  || { git checkout -- "$VERSION_FILE"; die "Version not updated in ${VERSION_FILE}"; }

echo "Updated Version to \"${VERSION}\" in ${VERSION_FILE}"

# ─── Step 4: Build all platform binaries ────────────────────────────────────

step "Building Binaries"

# Clear stale binaries so an old build can never be uploaded by mistake
rm -rf "$BUILD_DIR"

# If the build fails, revert the version so the repo is left untouched
if ! bash ./build.sh; then
  git checkout -- "$VERSION_FILE"
  die "Build failed. ${VERSION_FILE} has been reverted. Fix errors and try again."
fi

# Verify every expected file exists
RELEASE_FILES=("$ARM64_BIN" "$INTEL_BIN" "$LINUX_BIN" "$LINUX_ARM64_BIN" "$WINDOWS_BIN" \
               "$APPIMAGE_X64" "$APPIMAGE_ARM64" "$SUMS_FILE")
for bin in "${RELEASE_FILES[@]}"; do
  if [ ! -f "${BUILD_DIR}/${bin}" ]; then
    git checkout -- "$VERSION_FILE"
    die "Expected file not found: ${BUILD_DIR}/${bin} (${VERSION_FILE} reverted)"
  fi
done

# Every release file must be listed in SHA256SUMS, and match it
(cd "$BUILD_DIR" && shasum -a 256 -c "$SUMS_FILE" >/dev/null) \
  || { git checkout -- "$VERSION_FILE"; die "SHA256SUMS does not match the built files (${VERSION_FILE} reverted)"; }
for bin in "${RELEASE_FILES[@]}"; do
  [ "$bin" = "$SUMS_FILE" ] && continue
  grep -qF "  ${bin}" "${BUILD_DIR}/${SUMS_FILE}" \
    || { git checkout -- "$VERSION_FILE"; die "${bin} is missing from SHA256SUMS (${VERSION_FILE} reverted)"; }
done

echo "All binaries built successfully."

# ─── Step 5: Calculate SHA256 hashes for macOS binaries ──────────────────────

step "Calculating SHA256 Hashes"

ARM64_SHA256=$(shasum -a 256 "${BUILD_DIR}/${ARM64_BIN}" | awk '{print $1}')
INTEL_SHA256=$(shasum -a 256 "${BUILD_DIR}/${INTEL_BIN}" | awk '{print $1}')

echo "  ${ARM64_BIN}: ${ARM64_SHA256}"
echo "  ${INTEL_BIN}: ${INTEL_SHA256}"

# ─── Step 6: Commit, push, and tag the version bump ─────────────────────────

step "Committing, Pushing and Tagging"

# Commit the version bump to the age-tool repo
git add "$VERSION_FILE" || die "Failed to stage ${VERSION_FILE}"
git commit -m "Bump version to ${TAG}" || die "Failed to commit version bump"

# Push the commit BEFORE creating the release so the tag points at the
# commit that actually contains the new version number
git push origin "$CURRENT_BRANCH" || die "Failed to push version bump to origin."

# Create an annotated tag on the version bump commit and push it
git tag -a "$TAG" -m "age-tool ${TAG}" || die "Failed to create tag ${TAG}."
git push origin "$TAG" || die "Failed to push tag ${TAG} to origin."

echo "Version bump committed and pushed; tagged $(git rev-parse --short HEAD) as ${TAG}."

# ─── Step 7: Create GitHub release with binaries ─────────────────────────────

step "Creating GitHub Release"

# --verify-tag makes gh use the tag we just pushed and fail rather than
# silently creating a new tag on whatever the remote branch head is
# Pre-releases are flagged so GitHub doesn't show them as the latest release
RELEASE_FLAGS=()
[ -n "$PRERELEASE" ] && RELEASE_FLAGS+=(--prerelease)

UPLOADS=()
for bin in "${RELEASE_FILES[@]}"; do
  UPLOADS+=("${BUILD_DIR}/${bin}")
done

gh release create "$TAG" \
  "${UPLOADS[@]}" \
  --repo "$GITHUB_REPO" \
  --verify-tag \
  "${RELEASE_FLAGS[@]}" \
  --title "age-tool ${TAG}" \
  --notes "$RELEASE_NOTES" \
  || die "Failed to create GitHub release. Tag ${TAG} is pushed; re-run 'gh release create' manually."

echo "GitHub release ${TAG} created successfully."

# ─── Step 8: Update the Homebrew formula ─────────────────────────────────────

# Homebrew users get full releases only, so a pre-release stops here
if [ -n "$PRERELEASE" ]; then
  step "Release Summary"
  echo
  echo "========================================="
  echo "  age-tool ${TAG} pre-release published"
  echo "========================================="
  echo
  echo "  Tag:      ${TAG} -> $(git rev-parse --short "${TAG}^{commit}") on ${CURRENT_BRANCH}"
  echo "  Files:"
  for bin in "${RELEASE_FILES[@]}"; do
    echo "    - ${bin}"
  done
  echo
  echo "  Homebrew was NOT updated (pre-release)."
  echo
  echo "  Release page (send this to testers):"
  echo "    https://github.com/${GITHUB_REPO}/releases/tag/${TAG}"
  echo
  exit 0
fi

step "Updating Homebrew Formula"

# Build the new download URLs
ARM64_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${ARM64_BIN}"
INTEL_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${INTEL_BIN}"

# Rewrite the formula in a single pass:
#   - version line gets the new version
#   - each url line gets the new URL for its binary, and remembers which
#     binary it was and its indentation
#   - each sha256 line gets the hash matching the url above it, using the
#     same indentation as that url line
awk \
  -v version="$VERSION" \
  -v arm_bin="$ARM64_BIN" -v arm_url="$ARM64_URL" -v arm_sha="$ARM64_SHA256" \
  -v intel_bin="$INTEL_BIN" -v intel_url="$INTEL_URL" -v intel_sha="$INTEL_SHA256" '
  # Leading whitespace of a line
  function indent_of(s) { match(s, /^[ \t]*/); return substr(s, 1, RLENGTH) }

  /^[ \t]*version "/ { print indent_of($0) "version \"" version "\""; next }

  /^[ \t]*url "/ {
    ind = indent_of($0)
    if (index($0, "/" arm_bin "\""))        { cur = "arm";   print ind "url \"" arm_url "\"";   next }
    else if (index($0, "/" intel_bin "\"")) { cur = "intel"; print ind "url \"" intel_url "\""; next }
    else                                    { cur = "" }
  }

  /^[ \t]*sha256 "/ && cur != "" {
    print ind "sha256 \"" (cur == "arm" ? arm_sha : intel_sha) "\""
    cur = ""
    next
  }

  { print }
' "$FORMULA_PATH" > "${FORMULA_PATH}.tmp" || die "Failed to rewrite formula."

mv "${FORMULA_PATH}.tmp" "$FORMULA_PATH" || die "Failed to write updated formula."

# Verify every expected value landed in the formula
for expected in "version \"${VERSION}\"" "$ARM64_URL" "$INTEL_URL" "$ARM64_SHA256" "$INTEL_SHA256"; do
  grep -qF "$expected" "$FORMULA_PATH" || die "Formula update incomplete: missing ${expected}"
done

echo "Formula updated:"
echo "  Version: ${VERSION}"
echo "  arm64 SHA256: ${ARM64_SHA256}"
echo "  Intel SHA256: ${INTEL_SHA256}"

# ─── Step 9: Commit and push the updated formula ────────────────────────────

step "Committing and Pushing Formula"

git -C "$FORMULA_REPO_DIR" add Formula/age-tool.rb \
  || die "Failed to stage formula changes."

git -C "$FORMULA_REPO_DIR" commit -m "Update age-tool to ${TAG}" \
  || die "Failed to commit formula changes."

git -C "$FORMULA_REPO_DIR" push \
  || die "Failed to push formula changes."

echo "Formula committed and pushed successfully."

# ─── Step 10: Print release summary ─────────────────────────────────────────

step "Release Summary"

echo
echo "========================================="
echo "  age-tool ${TAG} released successfully"
echo "========================================="
echo
echo "  Version:  ${VERSION}"
echo "  Tag:      ${TAG} -> $(git rev-parse --short "${TAG}^{commit}")"
echo
echo "  Binaries uploaded:"
echo "    - ${ARM64_BIN}  (sha256: ${ARM64_SHA256})"
echo "    - ${INTEL_BIN}  (sha256: ${INTEL_SHA256})"
echo "    - ${LINUX_BIN}"
echo "    - ${LINUX_ARM64_BIN}"
echo "    - ${WINDOWS_BIN}"
echo "    - ${APPIMAGE_X64}"
echo "    - ${APPIMAGE_ARM64}"
echo "    - ${SUMS_FILE}"
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
