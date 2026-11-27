# age-tool 2.1 Plan

age-tool 2.1 adds **encrypting a file with a password** instead of a key, a safe way to **keep a record of those passwords**, and a **Quit button**. The **Mac desktop app**, installed with Homebrew, follows as soon as the Apple Developer account is ready. It joins 2.1 if ready in time, otherwise 2.2.

Milestones are done **in order**. Each one ends with its own tests passing and a working build, as in 2.0.

## Goals

- **Password encryption in every version** (Linux app, Mac app, CLI on all platforms). Files are standard age passphrase (scrypt) files, interchangeable with `age -p` in both directions.
- Decrypting needs no choice from the user: age-tool tells from the file itself whether it was locked with a key or a password.
- Users can keep a record of each password, protected the same way as their private key, so a forgotten file password can be recovered.
- **Security parity**, as in 2.0: the app and the CLI share one implementation of every rule.

## Non-goals for 2.1

- A settings screen in the app (rules are set in the settings file; see D2)
- Storing passwords in the operating system's keychain (worth revisiting for the Mac app)
- Combining a password with keys in one file (age doesn't allow it)
- Multiple recipients per file, SSH keys as recipients, Flatpak, a Windows installer

## Branching and versioning

- 2.1 work happens on the `v2.1` branch, made from `master` after 2.0.0. `master` stays releasable for any **2.0.x fixes**.
- The version on `v2.1` is `2.1.0-dev`. Pre-releases are tagged `2.1.0-rc.N`, as in 2.0.
- The Mac app is a separate download (a Homebrew cask). The Homebrew **formula** stays the CLI only.

---

## Milestone 1: Quit button

- [x] **Quit** on the home screen, beside View activity and Desktop integration.
- [x] If an operation is running, it asks first and removes any half-written output. This is the same path as closing the window, so the code is shared, not duplicated.
- [x] Test, and a screenshot check.

**Done when:** the button quits from the home screen, and asks first while working.

## Milestone 2: Password encryption in the core

- [x] **Encrypt with a password**, using age's scrypt recipient and age's default work factor. One password per file; it can't be combined with keys (age forbids it).
- [x] **Detect how a file was locked** by reading its header (`-> scrypt` stanza versus key stanzas), without decrypting anything. Files that aren't age files are reported as before.
- [x] **Decrypt with a password**, with the same 3 attempts, atomic output and overwrite rules as key decryption.
- [x] **Password rule (D1, D2):**
  - at least 8 characters, including a number and a special character
  - rejects known-weak patterns, using the existing weak-passphrase checks
  - configurable in the settings file, but only stricter, never below the floor
- [x] **Suggested passwords (D3):** random words joined with `-`, plus a number and a special character, so they always meet the rule. Generated with `crypto/rand`.
- [x] **Audit logs:** record the method ("password") instead of a key. The password is never logged.
- [x] **Tests:**
  - round trips
  - header detection
  - the rule and its floor
  - the generator always meeting the rule
  - **interop with the real `age -p`**, in both directions

**Done when:** core tests pass, including files made and opened by `age -p`.

**Result:** complete. `internal/core/password.go` adds:
- `FileLockMethod`, which reads only the header
- `PasswordRules` with `Effective`, `Describe` and `CheckPassword`, plus `Settings.PasswordRules()`
- `SuggestPassword`
- `EncryptFileWithPassword` and `DecryptFileWithPassword`, which return `ErrWrongPassword` for a wrong password
- `RecordPasswordEncrypt` / `RecordPasswordDecrypt` audit records with `"method": "password"`; activity entries now carry `Method`

The weak-password check refuses:
- a common word with numbers or symbols added (`Summer26!`, `Qwerty123!`)
- the same with look-alike swaps undone inside the word (`P@ssword1`, `Summ3r2026#`)
- alphabet or keyboard runs
- passwords with no letters

9 new tests, including both directions with the real `age` v1.2.1. `age -p` made the fixture `testdata/made-by-age-p.txt.age` (`.gitignore` has an exception for it), and `age -d` opens age-tool's output, with expect typing the password; that test is skipped where age or expect isn't installed. gosec and govulncheck are clean.

## Milestone 3: Saved password records in the core

- [x] **Record contents:**
  - the encrypted file names and full paths (one record per encryption, covering every file encrypted with that password)
  - the date and time
  - the SHA256 of each encrypted file, so a record can't be matched to the wrong file
  - the password
- [x] **Protection (D4):** each record is age-encrypted to **all of the user's own public keys** (keys with a private half), so any of them can open it. It is never stored unprotected.
- [x] **Location:** `passwords/` in age-tool's data folder, beside `keys/`. Never next to the encrypted file. The folder is `0700` and the files `0600`, like keys.
- [x] **List and open:**
  - listing records shows file names and dates without a passphrase
  - opening a record asks for a key passphrase, with the same 3 attempts
  - deleting a record asks first
- [x] **No key yet:** saving isn't possible, and the caller is told so (the app offers to create a key first, or to skip).
- [x] **Tests:**
  - encrypt to several own keys, open with each
  - wrong passphrase
  - permissions
  - the password never appears in any log or listing

**Done when:** records round-trip with every own key, and nothing stores a password unprotected.

**Result:** complete. `internal/core/records.go` adds:
- `OwnKeys`, the key pairs with both halves; contacts are excluded
- `SavePasswordRecord`, which refuses with `ErrNoOwnKey` when there's no own key
- `ListPasswordRecords`, newest first, skipping damaged files
- `OpenPasswordRecord`, which returns `ErrRecordNotForKey` for a key the record wasn't saved for
- `DeletePasswordRecord`
- `RecordsForFile`, which matches by SHA256, so moved or renamed files are still found

`Locations.PasswordsDir` is `passwords/` beside `keys/` on each OS.

**Format:** one JSON file per record:
- a readable part: date, file paths and hashes, and the key names, which are already in the activity log
- `secret`: the password together with the same files and date, age-encrypted (armored) to every own key

Opening a record returns the encrypted copy, so editing the readable part can't change what a record says. Record IDs have a fixed shape (`20261127-153045-a1b2c3d4`), so an ID can't point outside the folder.

7 new tests:
- two keys and a contact
- each key opening the record
- a key added later refused
- 0700/0600 permissions
- the password not readable in the file
- tampering
- moved files
- unsafe IDs
- damaged records

## Milestone 4: CLI

- [x] **Encrypt:** "Encrypt for: 1) a key 2) a password". For a password:
  - offer a suggested password or "type your own"
  - type it twice, hidden
  - check it against the rule
- [x] **Keep a record?** (D5), with the same wording as the app:
  1. Save it, protected by my key (default)
  2. Don't save it. The password is shown once, to write down.
- [x] **Decrypt:** detect a password file, skip the key list, and ask for the password.
- [x] **Key Management → Saved passwords:** list, show (asks for the key passphrase), delete.
- [x] Tests, including a scripted session.

**Result:** complete. The new [passwords.go](passwords.go) holds the CLI's password flows:
- **Encrypt** asks "Encrypt for: 1) A key 2) A password". The password path shows the rule, then offers a suggestion (accept, or ask for another) or "type my own", hidden and typed twice, with 3 tries against the rule. It reminds the user to send the password separately, then asks the record question. Enter saves; without an own key, the password is shown once instead.
- **Decrypt** detects password files before listing keys, mentions a saved record for the file, confirms any overwrite, then allows 3 password tries.
- **Key Management:** "8) Saved Passwords" (list, show with a key passphrase, delete with confirmation); "Back" moved to 9. Items 1–7 are unchanged.
- **Shared code:** the key passphrase loop is now one helper, `unlockKeyWithAttempts`, used by Decrypt and Saved Passwords. Hidden input goes through `readSecret`, so tests can supply it.

**Tests:** 6 CLI tests drive the real menus: own password with a rule failure, suggested password plus record plus show, declining the record, three wrong passwords, deleting a record, and the unchanged key path. A real-terminal session driven by expect covered the same journey: `Summer26!` refused, the record saved, a wrong then a right password, the record shown. The CLI still builds static for all 5 platforms; gosec and govulncheck are clean.

## Milestone 5: Desktop app

- [x] **Encrypt screen:** "Who is it for?" gains **Protect with a password instead**. It shows:
  - password and confirm fields
  - the strength meter, with the rule shown
  - a **Suggest a password** button
  - the reminder to send the password separately from the file (for example, by phone)
- [x] **Keep a record?** dialog (D5):
  - **Save it, protected by my key** *(default)*, with the warning: "If you forget your key's passphrase, you lose this record too."
  - **Don't save it**, which shows the password once, with Copy
- [x] **Decrypt:** a password file skips "Which of your keys?" and asks for the password.
- [x] **Saved passwords** screen, from My keys: list, **Show password** (asks for the key passphrase, with Copy), delete.
- [x] Right-click and double-click need no changes. The app decides from the file.
- [x] Tests and the screenshot tour updated.

**Result:** complete.

- **App layer** ([internal/app/passwords.go](internal/app/passwords.go)):
  - rules, suggestions and `CheckNewPassword`
  - `EncryptWithPassword`
  - `LockMethod`
  - `PasswordDecryption`, with 3 attempts like `Decryption`
  - records: `CanSavePasswordRecords`, `SavePasswordRecord`, `PasswordRecords`, `RecordKeys`, `RecordOpening` (3 key-passphrase attempts), `DeletePasswordRecord`
  - plain-language messages for each new error

  `NewWithLocations` puts the passwords folder beside the keys if none is given.
- **Screens** ([cmd/age-tool-gui/passwords.go](cmd/age-tool-gui/passwords.go)):
  - **Encrypt:** "A password instead of a key" shows the password fields, a live rule check, and **Suggest a password** with the suggestion and Copy. With no keys at all, it's chosen automatically, so key-less users can still protect files.
  - **After a password encrypt:** "Keep a record?" (save by default, explaining only the selected choice), or the password shown once with Copy. Without an own key, it's shown once with the reason.
  - **Decrypt:** step 2 says no key is needed when every chosen file is a password file. Mixed selections are decrypted each the right way. The password prompt mentions a saved record.
  - **My keys:** a **Saved passwords** screen to list, show (key passphrase, 3 attempts, Copy) and delete.
  - **Activity:** says "with a password".
  - **Home:** the intro mentions passwords.
- **Shared prompt:** one passphrase/password dialog (`askSecret`) now serves key decryption, password decryption and opening records.
- **Window:** the default window is now 620×600 (was 520 tall), so the password panel fits without scrolling.
- **Tests:**
  - 3 GUI tests click through the whole journey: no-keys password encrypt with a weak password refused, the suggestion plus record, the decrypt screen, a wrong then a right password, showing and deleting the record, the activity wording, and a mixed password-and-key decrypt
  - 3 app tests
  - the screenshot tour gains 7 password screens (16–22), checked in the real window on Ubuntu 24.04

## Milestone 6: Docs and 2.1.0 release

- [x] **User guide:**
  - "Encrypt with a password"
  - "Saved passwords"
  - the advice to write the key passphrase down and keep it somewhere physically safe
  - new screenshots
- [x] **README:** the CLI guide, the security section (offline guessing and the record protection), and the settings file rule.
- [ ] A short usability check of the password flow, ideally with the 2.0 usability tester.
- [ ] `2.1.0-rc.1`, fixes, then `2.1.0` (merge `v2.1` into `master`, release from there).

**Progress (docs written):**
- **User guide:**
  - new sections "5. Encrypt with a password" (the rule, suggestions, why a password is weaker than a key, "Keep a record?") and "10. Saved passwords"
  - "Files locked with a password" under Decrypt
  - "Write your key's passphrase down" under Keep your key safe
  - two new troubleshooting entries
  - Quit on the home screen
  - all 18 screenshots re-taken in the real window on Ubuntu 24.04, 7 of them new
- **README:**
  - "Encrypting with a password" and "Saved password records" in the CLI guide
  - the Key Management menu with 8) Saved Passwords
  - the passwords folder in "Where files are kept"
  - "Password rules", with a `settings.json` example
  - a "File passwords" security section, plus logging and best-practice updates
- **Other docs:**
  - [docs/usability-test.md](docs/usability-test.md): 3 password tasks (8–10) and a 2.1 pass criterion
  - [docs/releases/2.1.0-rc.1.md](docs/releases/2.1.0-rc.1.md): release notes
  - the upgrade notes mention the 2.1 menu change
- **Screenshot tour:** shows the record and password-once dialogs over the home screen, so no other password appears behind them.

**Remaining:** the usability check of the password flow, `2.1.0-rc.1`, fixes, then `2.1.0`.

## Milestone 7: Mac desktop app (2.1 if ready, otherwise 2.2)

Depends on the Apple Developer account (organization enrolment, started 2026-11-27).

- [ ] **App bundle:** `age-tool.app` with:
  - the padlock icon
  - the `.age` file type, so double-click opens it
  - Info.plist metadata
- [ ] **Signing and notarization** with a Developer ID Application certificate, built into `release.sh` (codesign, notarytool, stapler). Credentials stay in the macOS keychain, never in the repo.
- [ ] **Homebrew cask** `age-tool-app` in the existing tap, installing the signed `.app` (`brew install --cask anveitch/age-tool/age-tool-app`). The formula stays the CLI.
- [ ] **Later:** Finder Quick Actions for right-click Encrypt / Decrypt.
- [ ] Note in the docs: the app draws its own interface (Fyne), so it looks the same as on Linux rather than like a native macOS app.

**Done when:** `brew install --cask` on a clean Mac gives an app that opens without any Gatekeeper warning.

---

## Decisions

| # | Decision | Status |
|---|---|---|
| D1 | Password rule | **Decided:** at least 8 characters with a number and a special character, rejecting known-weak patterns. The owner accepts the trade-off: 8 characters is weaker against offline guessing than the 12 used for key passphrases. |
| D2 | Configurable rule | **Decided:** in `settings.json` (`password_rules`: `min_length`, `require_number`, `require_special`). It can only be made stricter; D1 is the floor. Shared by the app and the CLI. No settings screen in 2.1. |
| D3 | Suggested passwords | **Decided:** offered in the app and the CLI. **Word list decided:** the EFF short word list (1,295 words used; CC BY 3.0 US, credited in the README). Suggestions are 4 words plus a two-digit number and a special character, about 51 bits. |
| D4 | Protecting saved records | **Decided:** age-encrypted to the user's own public keys, opened with a key passphrase. Never stored unprotected. Known limit, shown to users: forgetting the key passphrase loses the records too. |
| D5 | Saving at run time | **Decided:** the user chooses each time. "Save it, protected by my key" is the default; "Don't save it" shows the password once with Copy and stores nothing. |
| D6 | Mac app distribution | **Decided:** signed and notarized `.app`, installed by a Homebrew cask. Needs the Apple Developer account. |

## Progress

| Milestone | Status |
|---|---|
| 1. Quit button | ✅ Complete |
| 2. Password encryption in the core | ✅ Complete |
| 3. Saved password records | ✅ Complete |
| 4. CLI | ✅ Complete |
| 5. Desktop app | ✅ Complete |
| 6. Docs and 2.1.0 release | Docs written; usability check, rc.1 and 2.1.0 pending |
| 7. Mac desktop app | Waiting for the Apple Developer account |
