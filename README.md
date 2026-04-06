# age-tool

A simple command line tool for encrypting and decrypting files using the AGE encryption library.

## Requirements

- AGE encryption library (filippo.io/age)
- Public keys must have a .pub extension
- Private keys must have a .priv extension and be passphrase-protected (see below)
- Key files and target files should be in the same directory as the running application

## Usage

Run the application from the directory containing your key files and target files:

    ./age-tool

You will be presented with the main menu:

    1. Encrypt
    2. Decrypt
    3. Quit (or type q/Q)

## Encryption

- The tool will scan the current directory for all files and present them for selection
- The tool will scan the current directory for .pub key files and present them for selection
- The encrypted output file will be named the same as the original with .age appended
  - Example: document.txt will become document.txt.age

## Decryption

- The tool will scan the current directory for .age files and present them for selection
- The tool will scan the current directory for .priv key files and present them for selection
- After selecting a .priv file, you will be prompted to enter the passphrase that protects it (your input will be hidden)
- The decrypted output file will have the .age extension removed
  - Example: document.txt.age will become document.txt

## Private Key Security

All .priv key files **must** be passphrase-protected using AGE's built-in scrypt encryption. When a .priv file is selected during decryption, the tool checks whether it is AGE-encrypted. If the key is not passphrase-protected, the tool will display a warning and return to the main menu without performing any decryption.

This requirement exists to prevent plaintext private keys from sitting on disk where they could be read by other processes or accidentally shared.

## Temporary File Handling

During decryption, the passphrase-protected private key is temporarily decrypted to a hidden file in the current directory (named `.tmpkey-<random>` with owner-only permissions). This temporary file is automatically removed:

- Immediately after the decryption operation completes (success or failure)
- On normal application exit via the Quit menu option
- On forced exit via Ctrl+C, SIGTERM, or SIGHUP

A global registry tracks all temporary files, and both a defer statement and a signal handler ensure cleanup occurs regardless of how the application exits.

## Key Generation

The full secure key pair creation workflow:

1. Generate a new AGE key pair:

       age-keygen -o key1.txt

2. Extract the public key to a .pub file:

       age-keygen -y key1.txt > key1.pub

3. Encrypt the private key with a passphrase:

       age -p -o key1.priv key1.txt

   You will be prompted to enter and confirm a passphrase.

4. Remove the unencrypted private key:

       rm key1.txt

You should now have `key1.pub` (public key, safe to share) and `key1.priv` (passphrase-protected private key).

## Security Notes

- **Never commit .priv files to version control.** Even though they are passphrase-protected, private keys should not be stored in repositories. Add `*.priv` to your .gitignore.
- **Always use passphrase-protected private keys.** The tool enforces this by rejecting unencrypted .priv files. This ensures your private key is never stored in plaintext on disk.
- **.pub files are safe to share.** Public keys can be freely distributed to anyone who needs to encrypt files for you.
- **.age files are safe to share.** Encrypted files can only be decrypted by the holder of the corresponding private key.
