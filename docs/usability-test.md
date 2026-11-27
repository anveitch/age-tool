# age-tool usability test (2.0 Milestone 3, extended for 2.1)

This is a script for a 20–30 minute session with one **non-technical** person on Ubuntu. It checks the plan's "done when" test: they can generate a key, then encrypt and decrypt a file, **without help**.

## Before the session

1. Copy the AppImage to the Ubuntu machine and make it executable. Use `age-tool-linux-x64.AppImage` for ordinary PCs, or `age-tool-linux-arm64.AppImage` for ARM machines. It needs Ubuntu 22.04 or newer.

   ```
   chmod +x age-tool-linux-x64.AppImage
   ```

   Build it on the Mac with `./build.sh` (Docker must be running), or download it from a `2.0.0-rc` pre-release.

2. Use a fresh user account, or move `~/.local/share/age-tool`, `~/.local/state/age-tool` and `~/.config/age-tool` aside, so the tester starts with no keys.
3. Put a sample file such as `Holiday plans.txt` in the tester's `Documents` folder.
4. Start the app by double-clicking the AppImage. Choose **Not now** if it offers to add itself to the desktop (that's covered by the desktop integration test), and leave it on the home screen.

## Running it

- Read the tasks aloud one at a time, exactly as written. Don't name buttons or screens.
- Ask the tester to **think aloud**.
- **Don't help.** If they're stuck for 2 minutes, note where, then give the smallest hint you can.
- For each task, note: completed alone, completed with a hint, or not completed. Also note anything they said or misread.

## Tasks

| # | Read this aloud | Success looks like |
|---|---|---|
| 1 | "This app keeps files private. First, set yourself up so people can send you private files." | Creates a key with a passphrase of 12+ characters, typed twice. |
| 2 | "Encrypt the file Holiday plans in your Documents folder, so only you can open it." | `Holiday plans.txt.age` exists next to the original. |
| 3 | "Pretend the original is gone. Get your file back from the encrypted copy." | Decrypts, enters the passphrase, and finds the file. Watch what they do when asked about replacing the existing file. |
| 4 | "Try that again, but type your passphrase wrong on purpose the first time." | Reads the "attempts left" message, then succeeds. |
| 5 | "A friend wants to send you private files. Give them what they need." | Shares the **public** key (Copy or Save a copy). They must not try to send the private key or the passphrase. |
| 6 | "Here is your friend's key." (Paste an `age1…` key in a text file.) "Encrypt the same file for your friend." | Adds a contact, then encrypts for them. |
| 7 | "Find out what you've done with the app today." | Opens View activity. |
| 8 | *(2.1)* "Your neighbour doesn't use this app. Lock a copy of Holiday plans so they can open it with a password." | Chooses **A password instead of a key**, uses a suggested password or types one that meets the rule, and keeps a record. Watch whether the rule message is understood. |
| 9 | *(2.1)* "You've forgotten that password. Find it again." | Opens **My keys > Saved passwords**, chooses **Show password**, and enters the **key's** passphrase (not the file password). |
| 10 | *(2.1)* "Pretend you're the neighbour: open the file with the password." | Decrypts without being asked about keys, entering the file password. |

## Afterwards

Ask:

- What was confusing, or made you hesitate?
- What do you think a "public key" and a "private key" are? Check that they understand which one is safe to share.
- If you forgot your passphrase, what would happen to your encrypted files?
- *(2.1)* How would you give the neighbour the password? (Look for "not in the same email as the file".) What's the difference between your key's passphrase and the file's password?

**Pass:** tasks 1–3 completed alone, and no attempt to share the private key or passphrase. For 2.1, tasks 8 and 9 completed alone too, and the file password isn't sent in the same message as the file. Record the findings below, fix what came up, and repeat with a second tester if anything major changed.

## Findings

| Date | Tester | Task results (alone / hint / failed) | Problems seen | Fix |
|---|---|---|---|---|
| | | | | |
