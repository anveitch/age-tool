# age-tool

A simple command line tool for encrypting and decrypting files using the AGE encryption library.

## Requirements

- AGE encryption library (filippo.io/age)
- Public keys must have a .pub extension
- Private keys must have a .priv extension
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
- The decrypted output file will have the .age extension removed
  - Example: document.txt.age will become document.txt

## Key Generation

To generate a key pair for testing:

    age-keygen -o key1.priv
    age-keygen -y key1.priv > key1.pub

## Notes

- Never commit .priv key files to version control
- Public .pub key files can be shared freely
- Encrypted .age files can be safely shared
