# Upgrading from age-tool 1.x to 2.0

age-tool 2.0 adds a desktop app for Linux, and changes where the command-line tool keeps keys and logs. Your encrypted files are unaffected: `.age` files made by 1.x open in 2.0, and the other way round.

## What changed

| | 1.x | 2.0 |
|---|---|---|
| Where keys are kept | The folder you run age-tool in | Your **key store**, one fixed folder (see below), used from any folder |
| Nicknames (`keys.json`) | Current folder | Beside the keys, in the key store |
| Files to encrypt or decrypt | Current folder | Current folder (unchanged) |
| Audit log | `age-tool.log` and `logs/` in the current folder | The same local log in the folder of the file, **plus** a central log (see below) |
| Key Management menu | 6 items, "Back" is 6 | 8 items: adds **Import a Public Key** (6) and **Export / Share a Public Key** (7); "Back" is now 8. Items 1–5 are unchanged. |
| Desktop app | None | `age-tool-linux-x64.AppImage` / `age-tool-linux-arm64.AppImage` for Linux. It uses the same key store. |

### Where things are kept

| Data | Linux | macOS | Windows |
|---|---|---|---|
| Key store (`.pub`, `.priv`, `keys.json`) | `~/.local/share/age-tool/keys/` | `~/Library/Application Support/age-tool/keys/` | `%AppData%\age-tool\keys\` |
| Settings | `~/.config/age-tool/` | `~/Library/Application Support/age-tool/` | `%AppData%\age-tool\` |
| Central audit log | `~/.local/state/age-tool/` | `~/Library/Logs/age-tool/` | `%LocalAppData%\age-tool\logs\` |

On Linux, `$XDG_DATA_HOME`, `$XDG_CONFIG_HOME` and `$XDG_STATE_HOME` are used when set. `age-tool --help` prints your key store and central log paths.

## Upgrading

1. Upgrade the command-line tool:
   - Homebrew: `brew upgrade age-tool`
   - Otherwise, download the new binary for your platform from the [releases page](https://github.com/anveitch/age-tool/releases) and replace the old one.
2. Run `age-tool` in the folder that holds your 1.x keys. It finds them and asks:

   ```
   Key files from age-tool 1.x were found in this folder:
      - work.priv
      - work.pub
   age-tool 2.0 keeps keys in your key store: /home/you/.local/share/age-tool/keys
   Import them? Copies are made; the files here are not changed.
   [Y]es / [n]o / ne[v]er ask for this folder:
   ```

   Answer **y**. age-tool copies the keys and their nicknames into the key store:
   - the files in your folder are **not changed or removed**
   - copies are owner-only (`0600`)
   - nothing already in the key store is overwritten; a different key with the same name is skipped and listed
3. Check the imported keys work, for example by decrypting a file. Then delete the originals in the old folder, remembering that any `.priv` files there are still private keys.

Repeat step 2 in each folder that has keys. Once everything in a folder is imported, age-tool stops asking about it.

**Using only the desktop app?** It doesn't import 1.x keys itself. Either run the command-line tool once in the old folder as above, or copy your `.pub`, `.priv` and `keys.json` files into the key store folder by hand. The app fixes their permissions when it starts.

## Keeping the 1.x way of working

To keep your keys in the current folder, as in 1.x, run:

```
age-tool --keys .
```

`--keys <folder>` works with any folder, such as a USB stick that carries its own keys and `keys.json`. Answering **v** ("never ask") at the import question remembers your choice for that folder.

## Going back to 1.x

Because the import only copies keys, your 1.x folders still work with 1.x. Keys created with 2.0 are in the key store; copy them into a folder to use them with 1.x.

## Linux desktop app

Linux users can now use age-tool without a terminal. See the [user guide](user-guide.md). The app uses the same key store, so keys imported with the command-line tool appear in it, and the other way round.
