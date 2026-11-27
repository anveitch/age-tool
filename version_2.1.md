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

- [ ] **Quit** on the home screen, beside View activity and Desktop integration.
- [ ] If an operation is running, it asks first and removes any half-written output. This is the same path as closing the window, so the code is shared, not duplicated.
- [ ] Test, and a screenshot check.

**Done when:** the button quits from the home screen, and asks first while working.

## Milestone 2: Password encryption in the core

- [ ] **Encrypt with a password**, using age's scrypt recipient and age's default work factor. One password per file; it can't be combined with keys (age forbids it).
- [ ] **Detect how a file was locked** by reading its header (`-> scrypt` stanza versus key stanzas), without decrypting anything. Files that aren't age files are reported as before.
- [ ] **Decrypt with a password**, with the same 3 attempts, atomic output and overwrite rules as key decryption.
- [ ] **Password rule (D1, D2):**
  - at least 8 characters, including a number and a special character
  - rejects known-weak patterns, using the existing weak-passphrase checks
  - configurable in the settings file, but only stricter, never below the floor
- [ ] **Suggested passwords (D3):** random words joined with `-`, plus a number and a special character, so they always meet the rule. Generated with `crypto/rand`.
- [ ] **Audit logs:** record the method ("password") instead of a key. The password is never logged.
- [ ] **Tests:**
  - round trips
  - header detection
  - the rule and its floor
  - the generator always meeting the rule
  - **interop with the real `age -p`**, in both directions

**Done when:** core tests pass, including files made and opened by `age -p`.

## Milestone 3: Saved password records in the core

- [ ] **Record contents:**
  - the encrypted file names and full paths (one record per encryption, covering every file encrypted with that password)
  - the date and time
  - the SHA256 of each encrypted file, so a record can't be matched to the wrong file
  - the password
- [ ] **Protection (D4):** each record is age-encrypted to **all of the user's own public keys** (keys with a private half), so any of them can open it. It is never stored unprotected.
- [ ] **Location:** `passwords/` in age-tool's data folder, beside `keys/`. Never next to the encrypted file. The folder is `0700` and the files `0600`, like keys.
- [ ] **List and open:**
  - listing records shows file names and dates without a passphrase
  - opening a record asks for a key passphrase, with the same 3 attempts
  - deleting a record asks first
- [ ] **No key yet:** saving isn't possible, and the caller is told so (the app offers to create a key first, or to skip).
- [ ] **Tests:**
  - encrypt to several own keys, open with each
  - wrong passphrase
  - permissions
  - the password never appears in any log or listing

**Done when:** records round-trip with every own key, and nothing stores a password unprotected.

## Milestone 4: CLI

- [ ] **Encrypt:** "Encrypt for: 1) a key 2) a password". For a password:
  - offer a suggested password or "type your own"
  - type it twice, hidden
  - check it against the rule
- [ ] **Keep a record?** (D5), with the same wording as the app:
  1. Save it, protected by my key (default)
  2. Don't save it. The password is shown once, to write down.
- [ ] **Decrypt:** detect a password file, skip the key list, and ask for the password.
- [ ] **Key Management → Saved passwords:** list, show (asks for the key passphrase), delete.
- [ ] Tests, including a scripted session.

## Milestone 5: Desktop app

- [ ] **Encrypt screen:** "Who is it for?" gains **Protect with a password instead**. It shows:
  - password and confirm fields
  - the strength meter, with the rule shown
  - a **Suggest a password** button
  - the reminder to send the password separately from the file (for example, by phone)
- [ ] **Keep a record?** dialog (D5):
  - **Save it, protected by my key** *(default)*, with the warning: "If you forget your key's passphrase, you lose this record too."
  - **Don't save it**, which shows the password once, with Copy
- [ ] **Decrypt:** a password file skips "Which of your keys?" and asks for the password.
- [ ] **Saved passwords** screen, from My keys: list, **Show password** (asks for the key passphrase, with Copy), delete.
- [ ] Right-click and double-click need no changes. The app decides from the file.
- [ ] Tests and the screenshot tour updated.

## Milestone 6: Docs and 2.1.0 release

- [ ] **User guide:**
  - "Encrypt with a password"
  - "Saved passwords"
  - the advice to write the key passphrase down and keep it somewhere physically safe
  - new screenshots
- [ ] **README:** the CLI guide, the security section (offline guessing and the record protection), and the settings file rule.
- [ ] A short usability check of the password flow, ideally with the 2.0 usability tester.
- [ ] `2.1.0-rc.1`, fixes, then `2.1.0` (merge `v2.1` into `master`, release from there).

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
| D3 | Suggested passwords | **Decided:** offered in the app and the CLI. **Open:** the word list. The EFF short word list (1,296 words, CC BY 3.0, needs attribution) is the likely choice; 4 words plus a number and a symbol. |
| D4 | Protecting saved records | **Decided:** age-encrypted to the user's own public keys, opened with a key passphrase. Never stored unprotected. Known limit, shown to users: forgetting the key passphrase loses the records too. |
| D5 | Saving at run time | **Decided:** the user chooses each time. "Save it, protected by my key" is the default; "Don't save it" shows the password once with Copy and stores nothing. |
| D6 | Mac app distribution | **Decided:** signed and notarized `.app`, installed by a Homebrew cask. Needs the Apple Developer account. |

## Progress

| Milestone | Status |
|---|---|
| 1. Quit button | In progress |
| 2. Password encryption in the core | Not started |
| 3. Saved password records | Not started |
| 4. CLI | Not started |
| 5. Desktop app | Not started |
| 6. Docs and 2.1.0 release | Not started |
| 7. Mac desktop app | Waiting for the Apple Developer account |
