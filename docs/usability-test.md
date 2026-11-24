# age-tool 2.0 usability test (Milestone 3)

This is a script for a 20–30 minute session with one **non-technical** person on Ubuntu. It checks the plan's "done when" test: they can generate a key, then encrypt and decrypt a file, **without help**.

## Before the session

1. Build the app on the Ubuntu machine (or copy over a Linux build):

   ```
   sudo apt install gcc libgl1-mesa-dev xorg-dev   # Fyne's build dependencies
   go build -o age-tool-gui ./cmd/age-tool-gui     # needs Go 1.26 from go.dev
   ```

2. Use a fresh user account, or move `~/.local/share/age-tool`, `~/.local/state/age-tool` and `~/.config/age-tool` aside, so the tester starts with no keys.
3. Put a sample file such as `Holiday plans.txt` in the tester's `Documents` folder.
4. Start the app (`./age-tool-gui`) and leave it on the home screen.

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

## Afterwards

Ask:

- What was confusing, or made you hesitate?
- What do you think a "public key" and a "private key" are? Check that they understand which one is safe to share.
- If you forgot your passphrase, what would happen to your encrypted files?

**Pass:** tasks 1–3 completed alone, and no attempt to share the private key or passphrase. Record the findings below, fix what came up, and repeat with a second tester if anything major changed.

## Findings

| Date | Tester | Task results (alone / hint / failed) | Problems seen | Fix |
|---|---|---|---|---|
| | | | | |
