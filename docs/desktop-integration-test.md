# age-tool 2.0 desktop integration test (Milestone 4)

Run this checklist on each desktop: **Ubuntu LTS (GNOME, Files)**, **Kubuntu or Fedora KDE (Dolphin)**, **Linux Mint Cinnamon (Nemo)** and **Xubuntu (Thunar)**. A virtual machine with each one's default install is enough.

## Setup

1. Copy a Linux build of `age-tool-gui` to `~/Applications/age-tool-gui`, and run `chmod +x ~/Applications/age-tool-gui`.
2. Create a key in the app, and put a test file such as `notes.txt` in `~/Documents`.
3. Install the integration, either from the app (Home → Desktop integration → Install) or with:

   ```
   ~/Applications/age-tool-gui --install-desktop
   ```

4. Close every file manager window (on KDE, also run `kbuildsycoca6`, or log out and back in if menus don't appear).

## Checks

Tick each one per desktop. Record the result as ✅, ❌ (with a note) or n/a.

| # | Check | GNOME | KDE | Cinnamon | XFCE |
|---|---|---|---|---|---|
| 1 | age-tool appears in the app menu with its icon, and opens the home screen. | | | | |
| 2 | Searching the menu for "encrypt" finds it. | | | | |
| 3 | Right-click `notes.txt` → **Encrypt with age-tool** opens the encrypt screen with the file chosen. (GNOME: under **Scripts**.) | | | | |
| 4 | Encrypting works, and `notes.txt.age` appears beside it with the padlock file icon. | | | | |
| 5 | Right-click `notes.txt.age` → **Decrypt with age-tool** opens the decrypt screen. | | | | |
| 6 | **Double-clicking** `notes.txt.age` opens the decrypt screen. | | | | |
| 7 | The Decrypt entry is **not** offered for `notes.txt`. (GNOME's Scripts menu shows both entries for every file, which is expected.) | | | | |
| 8 | Selecting 2 files → Encrypt opens one screen for both, and both are encrypted. | | | | |
| 9 | A file name with spaces and an apostrophe (`Bob's notes.txt`) works for encrypt and decrypt. | | | | |
| 10 | After moving `age-tool-gui` elsewhere and starting it, Desktop integration says **Update**. Updating makes the menus work again. | | | | |
| 11 | **Remove** takes away the menu entry, the right-click entries and the double-click association. Any existing Thunar custom actions (e.g. "Open Terminal Here") are still there. | | | | |

## Findings

| Date | Desktop / version | Problems seen | Fix |
|---|---|---|---|
| | | | |
