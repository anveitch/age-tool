// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

// Encrypting and decrypting with a password, and saved password records,
// for the CLI. The rules and the cryptography live in internal/core,
// shared with the desktop app.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"age-tool/internal/core"

	"golang.org/x/term"
)

// readSecret reads one line of hidden input (a passphrase or password)
// from the terminal. Tests replace it to supply input without a terminal.
var readSecret = func() ([]byte, error) {
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return b, err
}

// maxPasswordTries is how many times a user may type a new password that
// breaks the rules (or doesn't match its confirmation) before giving up.
const maxPasswordTries = 3

// ─── Encrypt with a password ────────────────────────────────────────────────

// encryptWithPassword encrypts inputPath with a password the user chooses
// (or a suggested one), then asks whether to keep a record of it.
func encryptWithPassword(reader *bufio.Reader, inputPath string) {
	password, ok := choosePassword(reader)
	if !ok {
		return
	}

	outputPath := core.EncryptedOutputPath(inputPath)
	if !confirmOverwrite(reader, outputPath) {
		fmt.Println("Encryption cancelled.")
		return
	}
	if err := core.EncryptFileWithPassword(inputPath, outputPath, password); err != nil {
		fmt.Fprintln(os.Stderr, "Encryption failed.")
		return
	}

	fmt.Printf("\nEncrypted with a password: %s -> %s\n", inputPath, outputPath)
	printWarnings(auditFor(filepath.Dir(outputPath)).RecordPasswordEncrypt(time.Now(), inputPath, outputPath))
	fmt.Println("If you send this file to someone, tell them the password a different way (for example, by phone), not in the same message.")

	keepPasswordRecord(reader, []string{outputPath}, password)
}

// choosePassword offers a suggested password or lets the user type their
// own (hidden, twice), checked against the password rules. Returns false
// if the user gives up or input fails.
func choosePassword(reader *bufio.Reader) (string, bool) {
	rules := core.LoadSettings(locations.SettingsFile()).PasswordRules()
	fmt.Printf("\nPassword rule: %s\n", rules.Describe())
	fmt.Println("  1) Use a suggested password (easy to remember, hard to guess)")
	fmt.Println("  2) Type my own")
	choice, ok := promptSelectionOrBack(reader, "Choose", 2)
	if !ok {
		return "", false
	}

	if choice == 0 {
		// Offer suggestions until the user takes one
		for {
			suggestion, err := core.SuggestPassword(rules)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: could not make a suggestion.")
				return "", false
			}
			fmt.Printf("\nSuggested password:  %s\n", suggestion)
			fmt.Print("Use this password? [Y/n, n = suggest another]: ")
			if confirmDefaultYes(reader) {
				fmt.Println("Write it down or store it somewhere safe before you continue.")
				return suggestion, true
			}
		}
	}

	// Type their own: hidden, twice, checked against the rules
	for try := 1; try <= maxPasswordTries; try++ {
		fmt.Print("\nPassword: ")
		pass1, err := readSecret()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading password.")
			return "", false
		}
		fmt.Print("Type it again: ")
		pass2, err := readSecret()
		if err != nil {
			core.ClearBytes(pass1)
			fmt.Fprintln(os.Stderr, "Error reading password.")
			return "", false
		}
		password, same := string(pass1), string(pass1) == string(pass2)
		core.ClearBytes(pass1)
		core.ClearBytes(pass2)

		switch {
		case !same:
			fmt.Fprintln(os.Stderr, "The passwords don't match.")
		default:
			if err := rules.CheckPassword(password); err != nil {
				fmt.Fprintf(os.Stderr, "That password can't be used: %v.\n", err)
			} else {
				return password, true
			}
		}
		if try < maxPasswordTries {
			fmt.Println("Try again.")
		}
	}
	fmt.Fprintln(os.Stderr, "Too many tries. Nothing was encrypted.")
	return "", false
}

// keepPasswordRecord asks whether to save a record of password, used for
// the encrypted files, protected by the user's own keys. Without a key of
// their own, or if they decline, the password is shown once to write down.
func keepPasswordRecord(reader *bufio.Reader, files []string, password string) {
	showOnce := func() {
		fmt.Printf("\nThe password is:  %s\n", password)
		fmt.Println("Write it down or store it somewhere safe. Without it, the file can't be opened.")
	}

	keys, err := core.OwnKeys(keyDir)
	if err != nil || len(keys) == 0 {
		fmt.Println("\nA record of this password can't be saved: you need a key of your own to protect it")
		fmt.Println("(Key Management > Generate New Key Pair).")
		showOnce()
		return
	}

	fmt.Println("\nKeep a record of this password?")
	fmt.Println("  1) Save it, protected by my key (recommended)")
	fmt.Println("     You can look it up later in Key Management > Saved Passwords, with your key's passphrase.")
	fmt.Println("     If you forget your key's passphrase, you lose this record too.")
	fmt.Println("  2) Don't save it (the password is shown once, to write down)")
	fmt.Print("Choose [1-2, Enter = 1]: ")
	if answer := strings.TrimSpace(readLine(reader)); answer == "2" {
		showOnce()
		return
	}

	if _, err := core.SavePasswordRecord(locations.PasswordsDir, keys, files, password, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "The record couldn't be saved: %v.\n", err)
		showOnce()
		return
	}
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.PubFile
	}
	fmt.Printf("Record saved, protected by: %s\n", strings.Join(names, ", "))
}

// ─── Decrypt with a password ────────────────────────────────────────────────

// decryptWithPassword decrypts a password-locked file, allowing
// core.MaxPassAttempts tries at the password.
func decryptWithPassword(reader *bufio.Reader, inputPath string) {
	fmt.Println("\nThis file was encrypted with a password.")
	if recs, err := core.RecordsForFile(locations.PasswordsDir, inputPath); err == nil && len(recs) > 0 {
		fmt.Println("You have a saved record of its password: see Key Management > Saved Passwords.")
	}

	outputPath := core.DecryptedOutputPath(inputPath)
	if !confirmOverwrite(reader, outputPath) {
		fmt.Println("Decryption cancelled.")
		return
	}

	for attempt := 1; attempt <= core.MaxPassAttempts; attempt++ {
		fmt.Printf("\nEnter the file's password (attempt %d/%d): ", attempt, core.MaxPassAttempts)
		pass, err := readSecret()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading password.")
			return
		}
		err = core.DecryptFileWithPassword(inputPath, outputPath, string(pass))
		core.ClearBytes(pass)

		if err == nil {
			fmt.Printf("\nDecrypted: %s -> %s\n", inputPath, outputPath)
			printWarnings(auditFor(filepath.Dir(outputPath)).RecordPasswordDecrypt(time.Now(), inputPath, outputPath))
			return
		}
		if !errors.Is(err, core.ErrWrongPassword) {
			fmt.Fprintln(os.Stderr, "Decryption failed.")
			return
		}
		if attempt < core.MaxPassAttempts {
			fmt.Fprintln(os.Stderr, "Incorrect password, try again.")
		}
	}
	fmt.Fprintln(os.Stderr, "Maximum password attempts exceeded.")
}

// ─── Saved passwords ────────────────────────────────────────────────────────

// savedPasswords lists the saved password records and lets the user show
// or delete one.
func savedPasswords(reader *bufio.Reader) {
	records, skipped, err := core.ListPasswordRecords(locations.PasswordsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing saved passwords.")
		return
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d saved password file(s) couldn't be read.\n", skipped)
	}
	if len(records) == 0 {
		fmt.Println("\nNo saved passwords yet. They are offered when you encrypt a file with a password.")
		return
	}

	fmt.Println("\nSaved passwords (newest first):")
	for i, r := range records {
		fmt.Printf("  %d) %s  %s\n", i+1, r.Created.Local().Format("2006-01-02 15:04"), recordFilesLabel(r))
	}
	idx, ok := promptSelectionOrBack(reader, "Select a saved password", len(records))
	if !ok {
		return
	}
	rec := records[idx]

	fmt.Println("\n  1) Show the password")
	fmt.Println("  2) Delete this record")
	action, ok := promptSelectionOrBack(reader, "Choose", 2)
	if !ok {
		return
	}
	if action == 1 {
		fmt.Print("Delete this saved password? The encrypted files are not affected. [y/N]: ")
		if answer := strings.TrimSpace(strings.ToLower(readLine(reader))); answer != "y" && answer != "yes" {
			fmt.Println("Not deleted.")
			return
		}
		if err := core.DeletePasswordRecord(locations.PasswordsDir, rec.ID); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v.\n", err)
			return
		}
		fmt.Println("Saved password deleted.")
		return
	}
	showPasswordRecord(reader, rec)
}

// recordFilesLabel names a record's files: the first file's name, plus how
// many others.
func recordFilesLabel(r core.PasswordRecord) string {
	if len(r.Files) == 0 {
		return "(no files)"
	}
	label := filepath.Base(r.Files[0].Path)
	if n := len(r.Files) - 1; n > 0 {
		label += fmt.Sprintf(" and %d more", n)
	}
	return label
}

// showPasswordRecord unlocks one of the user's keys the record was saved
// for, then shows the password and the files it opens.
func showPasswordRecord(reader *bufio.Reader, rec core.PasswordRecord) {
	// The record's keys that are still here, with a private half
	own, err := core.OwnKeys(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	var usable []core.OwnKey
	for _, k := range own {
		for _, name := range rec.Keys {
			if k.PubFile == name {
				usable = append(usable, k)
			}
		}
	}
	if len(usable) == 0 {
		fmt.Fprintf(os.Stderr, "This record was saved for %s, which isn't in %s.\n", strings.Join(rec.Keys, ", "), keysWhere())
		return
	}

	key := usable[0]
	if len(usable) > 1 {
		nicks := core.LoadNicknames(nicknameFile)
		fmt.Println("\nWhich key do you want to unlock it with?")
		for i, k := range usable {
			fmt.Printf("  %d) %s\n", i+1, nicks.Label(k.PrivFile))
		}
		i, ok := promptSelectionOrBack(reader, "Select key", len(usable))
		if !ok {
			return
		}
		key = usable[i]
	}

	identity, ok := unlockKeyWithAttempts(filepath.Join(keyDir, key.PrivFile))
	if !ok {
		return
	}
	password, opened, err := core.OpenPasswordRecord(locations.PasswordsDir, rec.ID, identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v.\n", err)
		return
	}
	fmt.Printf("\nPassword:  %s\n", password)
	fmt.Println("It opens:")
	for _, f := range opened.Files {
		fmt.Printf("  %s\n", f.Path)
	}
}
