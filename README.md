# age-tool

A command line AGE encryption management application for encrypting and decrypting files, generating and managing key pairs, and organising keys with nicknames. Built with the [filippo.io/age](https://filippo.io/age) Go library.

## Requirements

- Public keys must have a `.pub` extension
- Private keys must have a `.priv` extension and be passphrase-protected
- Key files and target files should be in the same directory as the application

## Building from Source

Building from source requires [Go](https://go.dev/) 1.21 or later.

To build for your current platform:

    go build -o age-tool .

To cross-compile for all supported platforms at once, use the included build script:

    ./build.sh

This creates a `builds/` directory containing binaries for every supported target.

### Platform Support

| Platform              | Binary name                 |
|-----------------------|-----------------------------|
| macOS Apple Silicon   | `age-tool-macos-arm64`      |
| Windows x64           | `age-tool-windows-x64.exe`  |
| Linux x64             | `age-tool-linux-x64`        |

The compiled binaries are self-contained and do not require Go to be installed on the target machine. However, if you plan to generate keys manually outside the application, the [age CLI](https://github.com/FiloSottile/age) must be installed on the target system. The built-in key generation feature has no external dependencies.

## Usage

Run the application from the directory containing your key files and target files:

    ./age-tool

You will be presented with the main menu:

    1) Encrypt
    2) Decrypt
    3) Key Management
    4) Quit

Type `q` or `Q` at any time to quit instead of selecting option 4.

On startup, the application performs a health check and warns you if any unencrypted private keys are found in the current directory.

## Encryption

1. The tool lists all files in the current directory (excluding `.age` files) for selection
2. The tool lists all `.pub` key files in the current directory for selection
   - Keys with nicknames are displayed as `Nickname (filename.pub)`
   - Keys without nicknames are displayed as `filename.pub`
3. The selected file is encrypted using the chosen public key
4. The output file is named with `.age` appended to the original filename
   - Example: `document.txt` becomes `document.txt.age`

## Decryption

1. The tool lists all `.age` files in the current directory for selection
2. The tool lists all `.priv` key files in the current directory for selection
   - Keys with nicknames are displayed as `Nickname (filename.priv)`
   - Keys without nicknames are displayed as `filename.priv`
3. The selected private key must be passphrase-protected. Unencrypted private keys are rejected with a warning
4. You will be prompted to enter the passphrase for the selected key (input is hidden)
5. The file is decrypted and the output has the `.age` extension stripped
   - Example: `document.txt.age` becomes `document.txt`

During decryption, the private key is temporarily decrypted to a hidden file (`.tmpkey-<random>`) with owner-only permissions. This file is automatically cleaned up:

- Immediately after the decryption operation completes (success or failure)
- On normal exit via the Quit menu option
- On forced exit via Ctrl+C, SIGTERM, or SIGHUP

A global registry and signal handler ensure temporary files are always removed.

## Key Management

Select option 3 from the main menu to access the key management submenu:

    1) List Keys
    2) Generate New Key Pair
    3) Encrypt a Private Key
    4) Delete a Key Pair
    5) Nickname a Key
    6) Back

### List Keys

Scans the current directory for `.pub` and `.priv` files and displays them grouped by base name. Each private key shows its protection status:

    key1
      Public:  Work Laptop (key1.pub)
      Private: Work Laptop (key1.priv) [ENCRYPTED]
    key2
      Public:  key2.pub
      Private: key2.priv [OPEN]

- `[ENCRYPTED]` -- the private key is passphrase-protected and ready to use
- `[OPEN]` -- the private key is unencrypted and will be rejected during decryption

### Generate New Key Pair

Creates a new AGE X25519 key pair with mandatory passphrase protection:

1. Prompts for a key pair name (e.g. `work` creates `work.pub` and `work.priv`)
2. Prompts for a passphrase and confirmation (input is hidden)
3. Generates the key pair in memory
4. Writes the public key to `name.pub`
5. Encrypts the private key with the passphrase and writes it to `name.priv`

The unencrypted private key material is never written to disk at any point.

### Encrypt a Private Key

For existing unencrypted `.priv` files that need to be secured:

1. Scans for `.priv` files that are not yet passphrase-protected
2. If none are found, displays a message and returns to the menu
3. Presents the unencrypted keys for selection
4. Prompts for a passphrase and confirmation
5. Encrypts the private key in place, overwriting the file

### Nickname a Key

Assigns a human-readable nickname to any `.pub` or `.priv` file:

1. Lists all key files with their current nickname (if set)
2. Prompts for the key to nickname and the new nickname
3. Saves the nickname to `keys.json`

Each key is nicknamed independently. A `.pub` and its matching `.priv` can have different nicknames, or one can have a nickname while the other does not. Nicknames are displayed throughout the application wherever keys are listed or selected.

Nicknames are stored in `keys.json` in the current directory:

```json
{
  "work.priv": "Work Laptop",
  "work.pub": "Work Public",
  "personal.priv": "Personal"
}
```

### Delete a Key Pair

Removes key files from the current directory:

1. Lists all key pairs grouped by base name
2. Prompts for selection and confirmation
3. Deletes both the `.pub` and `.priv` files (or whichever exists)
4. Removes any associated nicknames from `keys.json`

### Startup Health Check

On every launch, the application scans the current directory for `.priv` files and warns about any that are not passphrase-protected:

    !! WARNING: Unencrypted private key(s) detected !!
       - key2.priv
    These keys are NOT passphrase-protected and cannot be used for decryption.
    Use Key Management > Encrypt a Private Key to secure them.

## Manual Key Generation

If you prefer to generate keys outside the application:

1. Generate a new AGE key pair:

       age-keygen -o key1.txt

2. Extract the public key to a `.pub` file:

       age-keygen -y key1.txt > key1.pub

3. Encrypt the private key with a passphrase:

       age -p -o key1.priv key1.txt

   You will be prompted to enter and confirm a passphrase.

4. Remove the unencrypted private key:

       rm key1.txt

You should now have `key1.pub` (public key) and `key1.priv` (passphrase-protected private key).

## Security Notes

- **Never commit `.priv` files to version control.** Even passphrase-protected private keys should not be stored in repositories. Add `*.priv` to your `.gitignore`.
- **Always use passphrase-protected private keys.** The tool enforces this by rejecting unencrypted `.priv` files during decryption and warning about them on startup.
- **Use Generate New Key Pair for the safest workflow.** The built-in key generation never writes unencrypted key material to disk.
- **`.pub` files are safe to share.** Public keys can be freely distributed to anyone who needs to encrypt files for you.
- **`.age` files are safe to share.** Encrypted files can only be decrypted by the holder of the corresponding private key.
- **Temporary files are always cleaned up.** Decrypted key material is written to hidden temporary files with restricted permissions and removed immediately after use, including on Ctrl+C.
- **`keys.json` contains only nicknames, not key material.** It is safe to keep but is excluded from version control by default via `.gitignore`.
