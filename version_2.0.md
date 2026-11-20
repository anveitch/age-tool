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

- [ ] Create `internal/core` with clear functions, for example:
  - `EncryptFile`, `DecryptFile`
  - `GenerateKeyPair`, `UnlockIdentity`, `ProtectPrivateKey`
  - `ListKeys`, `DeleteKeyPair`
  - nickname load and save
  - audit-log entries
- [ ] Core functions return errors and never print or exit. Prompts, retries and messages stay in the CLI.
- [ ] Move `cmd/age-tool` (or keep the root `main.go`) to a CLI that only handles prompts and menus.
- [ ] Move the existing unit tests to cover the core package. Add tests for anything that loses coverage in the move.
- [ ] Re-run the end-to-end session test (generate, encrypt, wrong then right passphrase, decrypt) and the Ctrl+C test against the new CLI.

**Done when:** all tests pass, the CLI behaves exactly as in 1.2.2, `gosec` and `govulncheck` are clean, and the CLI still builds static for all five targets.

## Milestone 2: Key store and standard locations

Replace "everything in the current folder" with standard per-user locations. **This is the breaking change behind 2.0.**

| Data | Linux | macOS | Windows |
|---|---|---|---|
| Keys (`.pub`, `.priv`) | `~/.local/share/age-tool/keys/` | `~/Library/Application Support/age-tool/keys/` | `%AppData%\age-tool\keys\` |
| Nicknames, settings | `~/.config/age-tool/` | `~/Library/Application Support/age-tool/` | `%AppData%\age-tool\` |
| Audit log and receipts | `~/.local/state/age-tool/` | `~/Library/Application Support/age-tool/logs/` | `%AppData%\age-tool\logs\` |

On Linux these follow the XDG variables (`$XDG_DATA_HOME`, `$XDG_CONFIG_HOME`, `$XDG_STATE_HOME`) when they are set.

- [ ] Key store directory created `0700`, and files inside it `0600`.
- [ ] **Import public key:** from a `.pub` file, or by pasting an `age1…` string, so users can encrypt for other people (contacts).
- [ ] **Export / share public key:** copy to the clipboard or save as a file.
- [ ] **Migration:** detect keys and `keys.json` in the current folder (the 1.x layout) and offer to import them into the key store. Never delete the originals automatically.
- [ ] CLI uses the key store by default, with an option to use a specific folder instead (see open decision D2).
- [ ] Startup checks (open private keys, loose permissions, leftover temp files) run against the key store.
- [ ] Tests for the path logic on each OS, the permissions, import, export and migration.

**Done when:** the CLI works from any folder using the key store, and a 1.x user's keys migrate without loss.

## Milestone 3: Desktop GUI (Fyne)

A separate `age-tool-gui` binary built with [Fyne](https://fyne.io), calling the core package.

- [ ] **Home screen** with three clear actions: Encrypt a file, Decrypt a file, My keys.
- [ ] **Encrypt:**
  1. Pick a file (file dialog or drag-and-drop).
  2. Pick who it's for (your keys and imported contacts, shown by nickname).
  3. The output is saved next to the original as `name.age`.
- [ ] **Decrypt:**
  1. Pick a `.age` file.
  2. Choose a private key.
  3. Enter the passphrase (hidden; 3 attempts).
  4. The output is saved next to the `.age` file.
- [ ] **My keys:** list, generate (with a passphrase strength warning), protect an open key, import, export or share a public key, nickname, delete (with confirmation).
- [ ] **Overwrite confirmation** dialog, and clear plain-language error messages (no Go error text).
- [ ] **View activity:** a read-only view of the audit log.
- [ ] Passphrase fields are cleared after use, and nothing sensitive is kept in the GUI's state.
- [ ] Command-line arguments (`age-tool-gui encrypt <file>`, `age-tool-gui decrypt <file>`) open straight into that flow. Milestone 4 needs these.
- [ ] Usability pass: test the screens with someone non-technical before moving on.

**Done when:** a non-technical tester can complete generate → encrypt → decrypt on Ubuntu without help.

## Milestone 4: Desktop and file manager integration (Linux)

- [ ] `.desktop` launcher entry and an app icon (several sizes).
- [ ] MIME type for `.age` files, so double-clicking one opens the decrypt flow.
- [ ] Right-click menu entries for:
  - **Nautilus** (GNOME, Ubuntu)
  - **Dolphin** (KDE)
  - **Nemo** (Linux Mint / Cinnamon)
  - **Thunar** (XFCE)
- [ ] A built-in **Install / Remove desktop integration** option, per user and needing no root.
- [ ] Test on Ubuntu LTS (GNOME), Kubuntu or Fedora KDE, Linux Mint (Cinnamon), and Xubuntu (XFCE).

**Done when:** right-click Encrypt/Decrypt and double-click-to-decrypt work on all four desktops.

## Milestone 5: Build, packaging and release process

- [ ] Fyne needs CGO, so the GUI is **not** a static build. Linux GUI builds need either Docker on the Mac (`fyne-cross`) or a Linux build machine (see open decision D3).
- [ ] **AppImage** for Linux x86_64 and arm64: one file the user downloads and double-clicks, which also offers to install the desktop integration from Milestone 4.
- [ ] `build.sh` builds the CLI (static, as now) and the GUI AppImages.
- [ ] `release.sh`:
  - accept `x.y.z-rc.N` pre-release versions and mark them as GitHub pre-releases
  - upload the AppImages
  - keep the `govulncheck` gate covering the GUI's extra dependencies
  - leave the Homebrew formula on the CLI only
- [ ] Publish SHA256 checksums for every release file, with an optional signature (see open decision D5).

**Done when:** a single `release.sh` run produces the CLI binaries, the AppImages and the checksums, and an AppImage downloaded from GitHub runs on a clean Ubuntu LTS install.

## Milestone 6: Documentation and 2.0.0 release

- [ ] Restructure the README into a quick start, a GUI guide, a CLI guide and the security section.
- [ ] A short **user guide for non-technical users** with screenshots: install, make a key, encrypt, decrypt, share your public key.
- [ ] Upgrade notes for 1.x users covering the key store migration and the new log locations.
- [ ] Release `2.0.0-rc.1` to a few testers, fix what comes back, then release `2.0.0`.

**Done when:** 2.0.0 is published, and the docs let a new user get from download to first decrypted file on their own.

---

## Open decisions

Each one needs settling before the milestone it affects.

| # | Decision | Needed by | Recommendation |
|---|---|---|---|
| D1 | GUI toolkit | M3 | **Fyne**: pure Go, single binary, no runtime web engine. Wails was considered, but its WebKitGTK dependency varies across distributions. |
| D2 | CLI default: key store or current folder | M2 | Key store by default, with an option to use a specific folder for scripting and power users. |
| D3 | Where Linux GUI builds run | M5 | Docker on the Mac with `fyne-cross`, which keeps everything local. GitHub Actions is the alternative if you'd rather avoid Docker. |
| D4 | Central audit log vs per-folder log | M2 | Central log in the standard state folder. A GUI user won't think to look in each folder. |
| D5 | Sign release files | M5 | At least publish a SHA256SUMS file. Optionally sign it (minisign or GPG) so users can verify downloads. |
| D6 | App icon and name shown in menus | M4 | Needs an icon. The menu name could be "age-tool" or something friendlier such as "Age File Encryption". |

## Progress

| Milestone | Status |
|---|---|
| 1. Shared core package | Not started |
| 2. Key store and standard locations | Not started |
| 3. Desktop GUI (Fyne) | Not started |
| 4. Desktop and file manager integration | Not started |
| 5. Build, packaging and release process | Not started |
| 6. Documentation and 2.0.0 release | Not started |
