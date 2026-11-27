# age-tool 2.0 Plan

age-tool 2.0 adds a desktop GUI aimed at **non-technical Linux users**, alongside the existing command-line tool. Because 2.0 changes where keys and logs are stored and splits the app into a shared core with two front ends, it is a major version.

Milestones are done **in order**. Each one ends with its own tests passing and a working build, so work can stop at any milestone without leaving the project broken.

## Goals

- A non-technical user can install age-tool on a common Linux desktop, generate a key, and encrypt or decrypt a file **without opening a terminal**.
- Right-click **Encrypt** / **Decrypt** in the file manager, and double-click a `.age` file to decrypt it.
- **Security parity:** the GUI enforces the same rules as the CLI, using the same code:
  - passphrase-protected private keys only, unlocked in memory
  - minimum passphrase length and 3 attempts
  - atomic output and overwrite confirmation
  - owner-only permissions and the audit log
- The CLI keeps working for technical users and stays a static, dependency-free binary.

## Non-goals for 2.0

These can come after 2.0:

- Flatpak / Flathub publishing (AppImage first)
- macOS `.app` bundle with notarization, and a Windows installer
- Multiple recipients per file, passphrase-only (scrypt) file encryption, or SSH keys as recipients

## Branching and versioning

- 2.0 work happens on a `v2` branch. `master` stays releasable for any **1.2.x security fixes** that are needed in the meantime.
- Pre-releases are tagged `2.0.0-rc.N`. `release.sh` currently only accepts `x.y.z`, so it needs updating to handle these (Milestone 5).
- The Homebrew formula continues to ship the **CLI only**.

---

## Milestone 1: Extract a shared core package

Move all encryption, key, nickname and audit-log logic out of `main.go` into a package with no terminal input or output. The CLI becomes a thin layer that calls it. **Users see no change.**

- [x] Create `internal/core`, split by area:
  - `validate.go`: limits, input and passphrase rules
  - `keys.go`: list, generate, protect, unlock and delete keys
  - `files.go`: atomic encrypt and decrypt, partial-file tracking, leftover detection
  - `nicknames.go`
  - `audit.go`
- [x] Core functions return errors and never print or exit. Audit-log problems come back as warnings. Prompts, retries and messages stay in the CLI.
- [x] Key, nickname and log locations are passed in as parameters, not assumed. The CLI passes the current folder, so Milestone 2 only has to change those values.
- [x] Root `main.go` kept as the CLI (menus and prompts only), so `build.sh` and `release.sh` are unchanged. The GUI will live in `cmd/age-tool-gui`.
- [x] Tests moved to `internal/core` (20 tests), plus CLI tests for the prompt helpers (3 tests).
- [x] Re-ran the end-to-end, Ctrl+C and closed-input tests against the new CLI.

**Done when:** all tests pass, the CLI behaves exactly as in 1.2.2, `gosec` and `govulncheck` are clean, and the CLI still builds static for all five targets.

**Result:** complete. A scripted session run through both v1.2.2 and the new CLI gave an identical 338-line transcript, identical resulting files and permissions, and an identical audit log and receipts. The session covered every startup warning and the main paths, including error and cancel cases. Small differences that don't show up in normal use:

- *Encrypt a Private Key* now also tightens an existing loose `.priv` file to `0600` when it protects it in place. Previously a `0644` open key stayed `0644` after being protected.
- A new public key file is created with "fail if it exists", so it can never overwrite an existing file.
- Rare I/O-failure messages are worded slightly differently, e.g. "Error: could not read key file" instead of "Error reading key file."

## Milestone 2: Key store and standard locations

Replace "everything in the current folder" with standard per-user locations. **This is the breaking change behind 2.0.**

| Data | Linux | macOS | Windows |
|---|---|---|---|
| Keys (`.pub`, `.priv`) and their nicknames (`keys.json`) | `~/.local/share/age-tool/keys/` | `~/Library/Application Support/age-tool/keys/` | `%AppData%\age-tool\keys\` |
| Settings | `~/.config/age-tool/` | `~/Library/Application Support/age-tool/` | `%AppData%\age-tool\` |
| Central audit log and receipts | `~/.local/state/age-tool/` | `~/Library/Logs/age-tool/` | `%LocalAppData%\age-tool\logs\` |

On Linux these follow the XDG variables (`$XDG_DATA_HOME`, `$XDG_CONFIG_HOME`, `$XDG_STATE_HOME`) when they are set.

`keys.json` stays beside the keys it names, so a key folder (e.g. on a USB stick used with `--keys`) carries its own nicknames.

**Audit logging (D4: both).** Every transaction is written to two places:

- **Central log**, in the location above, recording full file paths. This is what the GUI's activity view reads.
- **Local log**, `age-tool.log` and `logs/` in the folder of the file that was encrypted or decrypted (for key creation, the key folder), in the same format as 1.x.

**CLI key location (D2: key store).** The CLI uses the key store by default, from any folder. `--keys <folder>` uses a specific folder instead (`--keys .` gives the 1.x behaviour). The files being encrypted or decrypted still come from the folder age-tool is run in.

- [x] Key store directory created `0700` (and tightened at startup if it was loosened), and files inside it `0600`.
- [x] **Import public key:** from a `.pub` file, or by pasting an `age1…` string, so users can encrypt for other people (contacts). A pasted private key is refused without being echoed back.
- [x] **Export / share public key:** show the `age1…` string and save a copy as a file, never overwriting an existing one. (Clipboard comes with the GUI.)
- [x] **Migration:** detect keys and `keys.json` in the current folder (the 1.x layout) and offer to import them into the key store, with a "never ask for this folder" option. Copies are `0600`, existing key store files and nicknames are never overwritten, and the originals are never changed. Once everything is imported, the offer stops for that folder.
- [x] CLI uses the key store by default, with `--keys <folder>` to override. Added `--help`.
- [x] Startup checks: open private keys and loose permissions run against the key folder. Leftover temp files are checked in the current folder, where output is written.
- [x] Central and local audit logs. Receipts no longer overwrite each other when two transactions happen in the same second.
- [x] Tests for the path logic on each OS, the permissions, import, export, migration and both audit logs.

**Done when:** the CLI works from any folder using the key store, and a 1.x user's keys migrate without loss.

**Result:** complete. The tests rose from 23 to 36 (31 in core, 5 in the CLI). End-to-end checks used a throwaway home folder:

- **`--keys .` against v1.2.2:** the same scripted session as Milestone 1 produced identical files, local audit log and receipts. The transcript differed only by the new `Keys:` line and the two new Key Management items. "Back" moved from 6 to 8; options 1–5 are unchanged.
- **Key store workflow:**
  - migrated a 1.x folder (keys and nicknames)
  - imported a contact from a file and as pasted text
  - refused a pasted private key
  - exported a key, refusing to overwrite an existing file
  - from an unrelated folder, encrypted and decrypted using only the key store, with a matching round trip
  - "never ask" persisted per folder
  - everything created was `0600` / `0700`
- **Central log:** recorded full paths, while each local log kept the 1.x format.

**Not yet done:** the README still describes the 1.x layout. It gets rewritten in Milestone 6.

## Milestone 3: Desktop GUI (Fyne)

A separate `age-tool-gui` binary built with [Fyne](https://fyne.io), calling the core package.

- [x] **Home screen** with three clear actions: Encrypt a file, Decrypt a file, My keys.
- [x] **Encrypt:**
  1. Pick a file (file dialog or drag-and-drop).
  2. Pick who it's for (your keys and imported contacts, shown by nickname).
  3. The output is saved next to the original as `name.age`.
- [x] **Decrypt:**
  1. Pick a `.age` file.
  2. Choose a private key.
  3. Enter the passphrase (hidden; 3 attempts).
  4. The output is saved next to the `.age` file.
- [x] **My keys:** list, generate (with a passphrase strength warning), protect an open key, import, export or share a public key, nickname, delete (with confirmation).
- [x] **Overwrite confirmation** dialog, and clear plain-language error messages (no Go error text).
- [x] **View activity:** a read-only view of the audit log.
- [x] Passphrase fields are cleared after use, and nothing sensitive is kept in the GUI's state.
- [x] Command-line arguments (`age-tool-gui encrypt <file>`, `age-tool-gui decrypt <file>`) open straight into that flow. Milestone 4 needs these.
- [ ] Usability pass: test the screens with someone non-technical before moving on (script: [docs/usability-test.md](docs/usability-test.md)).

**Done when:** a non-technical tester can complete generate → encrypt → decrypt on Ubuntu without help.

**Progress: groundwork done (no Fyne needed).** Fyne needs a working C toolchain, and the Mac's was waiting on an Xcode update, so everything the screens call was built first in `internal/app`, with no toolkit code:

- **Workflows:**
  - `Encrypt`, plus `StartDecrypt` → `Try`, which checks the file, key and output before the passphrase is asked for and enforces the 3 attempts itself.
  - `GenerateKey`, `ProtectKey`, `ImportContact`, `ImportContactFile`, `PublicKeyText`, `ExportPublicKey`, `SetNickname`, `DeleteKey`.
  - `Keys` / `Recipients` / `Identities` for the pickers, and `Activity` for the activity view.

  They log to the central and local audit logs as the CLI does. Passphrases are passed in as byte slices and zeroed before each call returns.
- **Plain-language messages:** `Message(err)`. Core errors now carry kinds (`core.ErrInvalidName`, `ErrPassphraseTooShort`, `ErrKeyNotProtected`, …) that can be tested with `errors.Is`, while keeping their exact text, so CLI output is unchanged. Unknown errors get a general message, never Go error text.
- **Passphrase strength:** `core.RatePassphrase`, with labels for the meter.
- **Activity reader:** `core.ReadActivity` reads the central receipts newest first, skipping damaged ones.
- **Command line:** `ParseLaunch` handles `encrypt|decrypt <file>...`, plus bare files (decrypt `.age` files, encrypt others) for double-click.

Tests rose from 36 to 44 (33 core, 6 app, 5 CLI). gosec and govulncheck are clean, and the CLI still builds static for all five targets.

**Progress: screens built.** Once Xcode was updated, the Fyne screens were built in `cmd/age-tool-gui` on Fyne v2.8.2, as thin layers over `internal/app`:

- **Home:** Encrypt a file, Decrypt a file, My keys and View activity. Files dropped on the window open the matching workflow.
- **Encrypt and decrypt:** a file step and a key list (your own keys are marked "(you)"). Overwrite is confirmed per file, and several files from the command line are handled in turn. The passphrase is asked for each file and never kept. Wrong passphrases show the attempts left.
- **My keys:**
  - create (with a strength meter), add contact (paste or load a `.pub` file), share (copy or save a copy to a folder), rename, protect and delete (explaining what is lost)
  - unprotected keys are flagged in red and can't be chosen for decryption
  - a refused private key is never shown back on screen
- **Activity:** recent transactions, newest first, from the central log.
- **Background work:** encrypting and unlocking keys run off the UI thread behind a busy dialog. Closing the window mid-operation asks first and removes the partial output. Interrupt and termination signals do the same.
- **Startup:** private keys in the key store with loose permissions are tightened silently, since the GUI's users can't be expected to judge this. 1.x key migration stays in the CLI, which has a "current folder" to migrate from.
- **Tests:** a headless smoke test (Fyne's test driver) builds every screen and dialog with real keys and files, and runs the encrypt flow end to end. Setting `AGE_TOOL_SCREENSHOTS=<folder>` saves a PNG of each screen.
- **Dependencies:** `golang.org/x/image` is required at v0.48.0, above Fyne's v0.24.0, because the older version has known vulnerabilities and `release.sh` blocks on any finding.

The CLI still builds static with no Fyne code (`go list -deps .` contains none of it).

**Real window checked on macOS.** A screenshot tour (`cmd/age-tool-gui/screenshot_tour.go`, built only with `-tags screenshots`) walks every screen in the real window and saves each one. All 15 render cleanly. The text overlap seen in the headless renders was only a quirk of the test driver. The tour will also supply the user guide's screenshots in Milestone 6.

**Still to do:** the usability pass on Ubuntu, using the script and findings table in [docs/usability-test.md](docs/usability-test.md). This also serves as the Linux check of the real window.

## Milestone 4: Desktop and file manager integration (Linux)

- [x] `.desktop` launcher entry and an app icon (several sizes).
- [x] MIME type for `.age` files, so double-clicking one opens the decrypt flow.
- [x] Right-click menu entries for:
  - **Nautilus** (GNOME, Ubuntu)
  - **Dolphin** (KDE)
  - **Nemo** (Linux Mint / Cinnamon)
  - **Thunar** (XFCE)
- [x] A built-in **Install / Remove desktop integration** option, per user and needing no root.
- [ ] Test on Ubuntu LTS (checklist: [docs/desktop-integration-test.md](docs/desktop-integration-test.md)) (GNOME), Kubuntu or Fedora KDE, Linux Mint (Cinnamon), and Xubuntu (XFCE).

**Done when:** right-click Encrypt/Decrypt and double-click-to-decrypt work on all four desktops.

**Progress: built and checked against the Linux tools.** `internal/desktop` (plain Go, no toolkit code) installs everything per user under the XDG folders:

- **Launcher and icons:** `io.github.anveitch.age-tool.desktop`, plus SVG icons for the app and for `.age` files.
- **File type:** `application/x-age-encrypted`, recognised by `*.age` or by the `age-encryption.org/v1` header. age-tool is set as its default app in `mimeapps.list`.
- **Right-click entries:**
  - Nautilus Scripts entries
  - Dolphin service menus (Plasma 5 and 6 locations)
  - Nemo actions
  - Thunar custom actions, merged into the user's `uca.xml`, or a copy of the system defaults if they have none

Uninstalling removes only age-tool's files and its own entries in the shared files. A user's other Thunar actions, and another default app they chose, are left alone. Inside an AppImage the menus start the AppImage file itself (`$APPIMAGE`). If the program moves, the integration screen shows **Update**. The program path is quoted for each format (desktop Exec rules for launchers and Dolphin, shell quoting for Nautilus, Nemo and Thunar), and paths that can't be written safely are refused.

The app offers it from **Home → Desktop integration** (Linux only), and `age-tool-gui --install-desktop` / `--remove-desktop` do the same from the command line.

**Tests:** 8 new tests. One runs the generated Nautilus script with awkward file names. Another (`AGE_TOOL_LINUX_CHECK=1`) passed in an Ubuntu 24.04 container:

- `desktop-file-validate` accepts the launcher
- the XML files are well-formed
- `xdg-mime` recognises `.age` files by name and by content, and reports age-tool as their default app
- uninstalling removes the type

**Still to do:**
- Run the checklist on the four desktops. GNOME's Files has no plain right-click extension point without `python3-nautilus`, so its entries live under **Scripts**. The checklist will show whether that's good enough.
- Confirm the menu name (D6). The names are constants at the top of `internal/desktop/desktop.go`.

## Milestone 5: Build, packaging and release process

- [x] Fyne needs CGO, so the GUI is **not** a static build. Linux GUI builds run in Docker on the Mac, in our own build image (D3).
- [x] **AppImage** for Linux x86_64 and arm64: one file the user downloads and double-clicks, which also offers to install the desktop integration from Milestone 4.
- [x] `build.sh` builds the CLI (static, as now) and the GUI AppImages.
- [x] `release.sh`:
  - accept `x.y.z-rc.N` pre-release versions and mark them as GitHub pre-releases
  - upload the AppImages
  - keep the `govulncheck` gate covering the GUI's extra dependencies
  - leave the Homebrew formula on the CLI only
- [x] Publish SHA256 checksums for every release file. (The optional signature is D5, still open.)

**Done when:** a single `release.sh` run produces the CLI binaries, the AppImages and the checksums, and an AppImage downloaded from GitHub runs on a clean Ubuntu LTS install.

**Progress:** built. What remains is the first real `release.sh` run (`2.0.0-rc.1`) and running that download on a real Ubuntu PC.

**Risk accepted (2026-11-26):** the owner chose to release `2.0.0-rc.1` before the Milestone 3 usability test and the Milestone 4 four-desktop checklist have been run on real machines. Those tests now run against the rc download, and the release notes list this as a known limitation. Neither test may be skipped before `2.0.0`.

- **App icon fix (6af069a).** The window's X11 class is its title ("age-tool"), and the menu entry didn't name it, so GNOME would probably have shown a generic icon for the running app. The entry now has `StartupWMClass=age-tool`, and the window title comes from the same constant (verified under Xvfb: `WM_CLASS = "age-tool"`). Fyne didn't set `_NET_WM_ICON` under Xvfb, not even for a minimal program using Fyne's own logo, so the window icon used by XFCE and Cinnamon taskbars is a desktop checklist item (check 1).
- **XFCE tested in Docker (2026-11-26).** On a full XFCE 4.18 session (Ubuntu 24.04, Xvfb, xfwm4, panel, Thunar), the downloaded rc.1 arm64 AppImage passed all 12 desktop checks, driven with xdotool and checked by screenshot. With a window manager running, the padlock icon shows in the title bar, taskbar and workspace switcher, so the bare-Xvfb icon result came from the test setup. Details are in the Findings of [docs/desktop-integration-test.md](docs/desktop-integration-test.md). GNOME, KDE and Cinnamon still need real machines or VMs.
- **Real Ubuntu test (2026-11-26).** The owner ran the rc.1 x64 AppImage from GitHub on a vanilla Ubuntu Desktop install, on a real PC. It works as expected: nothing extra needed installing, it added itself to the app menu, and the icon is correct. This covers the Milestone 5 "done when" condition (an AppImage downloaded from GitHub runs on a clean Ubuntu LTS install).

- **One version number.** `internal/core/version.go` holds `Version`, used by both the CLI and the app. `release.sh` rewrites it; between releases it ends in `-dev`.
- **AppImage.** [packaging/linux/build-gui.sh](packaging/linux/build-gui.sh) builds, in the Docker image:
  - the program, then the AppDir, laid out by [packaging/linux/appdir](packaging/linux/appdir) from `internal/desktop`, so the AppImage's desktop entry and icon match `--install-desktop`
  - a zstd SquashFS image with fixed timestamps and root ownership
  - the official AppImage runtime (type2-runtime release 20251108) joined to the image

  The runtime's GPG signatures were checked against the AppImage project's key, and the Dockerfile pins and verifies their SHA256. No appimagetool is needed. Rebuilding gives a byte-identical AppImage. Sizes: about 12 MB (x64), 11 MB (arm64).
- **First-run offer.** Started from an AppImage with no integration installed (or with menus pointing at another copy), the app offers **Add to desktop** (or **Update**). "Not now" is remembered per copy. This is tested on Linux.
- **build.sh** builds the 5 CLI binaries, then both AppImages, then `SHA256SUMS` for everything built. `--cli-only` skips Docker. It now exits with an error if anything failed.
- **release.sh:**
  - accepts `x.y.z-rc.N`; pre-releases can be made from any branch (so `v2`), are flagged `--prerelease`, and stop before Homebrew
  - full releases must be on `master`
  - checks Docker is running
  - uploads the AppImages and `SHA256SUMS`, after checking every file is listed and matches
  - adds a second `govulncheck -scan module` pass, because the source scan on the Mac can't load the Linux-only CGO driver code
- **Verified:**
  - Both AppImages on a clean Ubuntu 24.04 container, with only the graphics libraries a desktop has: `--version` through FUSE and with `APPIMAGE_EXTRACT_AND_RUN`, `desktop-file-validate` on the embedded entry, and `--install-desktop` writing `Exec=<AppImage path> %F`.
  - The x64 AppImage only runs in Docker's x86 emulation on Apple Silicon once its `AI\x02` header marker is cleared. Every AppImage has that marker, and a real PC ignores it, so this is an emulator limit. The x64 build still needs a run on a real PC.

## Milestone 6: Documentation and 2.0.0 release

- [x] Restructure the README into a quick start, a GUI guide, a CLI guide and the security section.
- [x] A short **user guide for non-technical users** with screenshots: install, make a key, encrypt, decrypt, share your public key. ([docs/user-guide.md](docs/user-guide.md))
- [x] Upgrade notes for 1.x users covering the key store migration and the new log locations. ([docs/upgrading-to-2.0.md](docs/upgrading-to-2.0.md))
- [ ] Release `2.0.0-rc.1` to a few testers, fix what comes back, then release `2.0.0`.

**Done when:** 2.0.0 is published, and the docs let a new user get from download to first decrypted file on their own.

**Progress:** the docs are written. Release notes for testers: [docs/releases/2.0.0-rc.1.md](docs/releases/2.0.0-rc.1.md). The screenshots in `docs/images/` come from the real app window on Ubuntu 24.04 (the screenshot tour under Xvfb, with a `/home/sam` home folder). Next: `2.0.0-rc.1` from `v2`, then the testers' fixes, then merge `v2` into `master` and release `2.0.0` from there.

---

## Open decisions

Each one needs settling before the milestone it affects.

| # | Decision | Needed by | Recommendation |
|---|---|---|---|
| D1 | GUI toolkit | M3 | **Fyne**: pure Go, single binary, no runtime web engine. Wails was considered, but its WebKitGTK dependency varies across distributions. |
| D2 | CLI default: key store or current folder | M2 | **Decided:** key store by default, with `--keys <folder>` to override. |
| D3 | Where Linux GUI builds run | M5 | **Decided:** Docker on the Mac, using our own build image ([packaging/linux/Dockerfile](packaging/linux/Dockerfile): Ubuntu 22.04, Go with its checksum verified, X11 and Wayland headers) rather than fyne-cross. Binaries need glibc 2.34+ (Ubuntu 22.04, Debian 12, Mint 21, Fedora 35 and later). amd64 builds run under emulation, which takes a few minutes. |
| D4 | Central audit log vs per-folder log | M2 | **Decided:** both. Every transaction goes to the central log and to the local log beside the file. |
| D5 | Sign release files | M5 | **SHA256SUMS: done**, published with every release. **Signing: not for 2.0** (decided 2026-11-26). If wanted later, minisign is the simplest: one key pair and one extra file (`SHA256SUMS.minisig`). |
| D6 | App icon and name shown in menus | M4 | **Icon decided:** a padlock carrying a lowercase "a" on a dark slate tile (option C of four compared). `.age` files show a page with that icon as a badge. Both are text-free SVGs in `internal/desktop/icons/`. **Name:** "age-tool", with "File Encryption" as the generic name, for the rc (2026-11-26). It can still change before 2.0.0 if testers find it unclear. |

## Progress

| Milestone | Status |
|---|---|
| 1. Shared core package | ✅ Complete |
| 2. Key store and standard locations | ✅ Complete |
| 3. Desktop GUI (Fyne) | Built; usability test on Ubuntu pending |
| 4. Desktop and file manager integration | Built; testing on the four desktops pending |
| 5. Build, packaging and release process | Built; first `release.sh` run (2.0.0-rc.1) pending; Linux testing deferred to the rc (risk accepted) |
| 6. Documentation and 2.0.0 release | Docs written; rc.1, tester fixes and 2.0.0 pending |
