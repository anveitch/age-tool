// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Command age-tool is the interactive command-line front end for age-tool.
// It handles menus, prompts and messages only; all encryption, key, nickname
// and audit-log logic lives in the internal/core package.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"age-tool/internal/core"

	"filippo.io/age"
	"golang.org/x/term"
)

// Application version, printed with --version flag.
const appVersion = "1.2.2"

// Where the CLI keeps its files, set once at startup by setupLocations.
var (
	locations    core.Locations // Standard per-user locations (key store, settings, central log)
	keyDir       string         // Folder holding .pub / .priv files: the key store, or --keys <folder>
	nicknameFile string         // keys.json beside the keys
	usingStore   bool           // True when keyDir is the key store rather than a --keys folder
)

// options holds the parsed command-line options.
type options struct {
	keysDir     string // --keys <folder>: use this folder instead of the key store
	showVersion bool   // --version
	showHelp    bool   // --help / -h
}

// parseArgs parses command-line arguments (excluding the program name).
// Both -flag and --flag forms are accepted.
func parseArgs(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("age-tool", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors and help are printed by the caller
	fs.StringVar(&opts.keysDir, "keys", "", "")
	fs.BoolVar(&opts.showVersion, "version", false, "")
	fs.BoolVar(&opts.showHelp, "help", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.showHelp = true
			return opts, nil
		}
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return opts, nil
}

// printUsage prints the command-line help.
func printUsage() {
	fmt.Println("Usage: age-tool [--keys <folder>]")
	fmt.Println()
	fmt.Println("Interactive tool to encrypt and decrypt files with age keys.")
	fmt.Println("Files to encrypt or decrypt are taken from the current folder.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --keys <folder>  Use the key files in <folder> instead of your key store")
	fmt.Println("                   (--keys . gives the age-tool 1.x behaviour)")
	fmt.Println("  --version        Show the version")
	fmt.Println("  --help           Show this help")
	if loc, err := core.DefaultLocations(); err == nil {
		fmt.Println()
		fmt.Printf("Your key store: %s\n", loc.KeysDir)
		fmt.Printf("Central log:    %s\n", loc.CentralAudit().LogFile)
	}
}

// setupLocations decides where keys live (the key store, or the --keys
// folder) and makes sure the key store exists and is owner-only.
func setupLocations(opts options) error {
	loc, err := core.DefaultLocations()
	if err != nil {
		return err
	}
	locations = loc

	if opts.keysDir != "" {
		info, err := os.Stat(opts.keysDir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("key folder %s does not exist", opts.keysDir)
		}
		keyDir = opts.keysDir
		usingStore = false
	} else {
		if err := core.EnsurePrivateDir(loc.KeysDir); err != nil {
			return fmt.Errorf("cannot set up key store: %v", err)
		}
		keyDir = loc.KeysDir
		usingStore = true
	}
	nicknameFile = filepath.Join(keyDir, core.NicknameFileName)
	return nil
}

// keysWhere describes where the keys are, for messages: "current
// directory", "your key store (<path>)", or the --keys folder.
func keysWhere() string {
	switch {
	case core.SameDir(keyDir, "."):
		return "current directory"
	case usingStore:
		return fmt.Sprintf("your key store (%s)", keyDir)
	default:
		return keyDir
	}
}

// auditFor returns the audit logs for a transaction whose files are in
// dir: the central log plus the local log in dir.
func auditFor(dir string) core.AuditLogs {
	return core.NewAuditLogs(locations.CentralAudit(), core.LocalAudit(dir))
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage()
		os.Exit(2)
	}
	if opts.showHelp {
		printUsage()
		return
	}
	if opts.showVersion {
		fmt.Printf("age-tool v%s\n", appVersion)
		return
	}

	// Restore the terminal and clean up partial output if interrupted
	installInterruptHandler()

	// Verify the working directory is accessible and writable before starting
	if err := checkWorkingDirectory(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Decide where keys live and prepare the key store
	if err := setupLocations(opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("age-tool v%s: file encryption/decryption\n", appVersion)
	fmt.Printf("Keys: %s\n", keysWhere())

	// Startup check: offer to delete temp files left by a killed session
	cleanupLeftoverTempFiles(reader)

	// Offer to bring 1.x keys in this folder into the key store
	offerKeyMigration(reader)

	// Startup health check: warn about any unencrypted .priv files
	checkUnencryptedKeys()

	// Startup check: warn about key files with overly permissive permissions
	checkKeyFilePermissions(reader)

	// Main loop: present the menu after each operation until the user quits
	for {
		fmt.Println()
		fmt.Println("1) Encrypt")
		fmt.Println("2) Decrypt")
		fmt.Println("3) Key Management")
		fmt.Println("4) Quit")
		fmt.Print("\nChoose [1/2/3/4/q]: ")

		choice := strings.TrimSpace(readLine(reader))

		// Accept "4", "q", or "Q" as quit commands
		switch strings.ToLower(choice) {
		case "1":
			encrypt(reader)
		case "2":
			decrypt(reader)
		case "3":
			keyManagement(reader)
		case "4", "q":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

// installInterruptHandler saves the terminal's normal state and, on Ctrl+C,
// SIGTERM or SIGHUP, restores it before exiting. Without this, interrupting
// a hidden passphrase prompt leaves the terminal with echo switched off.
// It also removes any half-written output file before exiting.
func installInterruptHandler() {
	stdinFd := int(os.Stdin.Fd())
	var savedState *term.State
	if term.IsTerminal(stdinFd) {
		// Best effort: if the state can't be read, there is nothing to restore
		savedState, _ = term.GetState(stdinFd)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		// Restore echo and line editing if they were changed by a prompt
		if savedState != nil {
			_ = term.Restore(stdinFd, savedState)
		}
		// Remove any incomplete output so no partial plaintext is left behind
		core.RemoveInProgressOutput()
		fmt.Println("\nInterrupted. Exiting.")
		// 130 is the conventional exit status for termination by Ctrl+C
		os.Exit(130)
	}()
}

// checkWorkingDirectory verifies the current directory is accessible and
// writable by attempting to stat it and create a temporary probe file.
func checkWorkingDirectory() error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot determine working directory")
	}
	info, err := os.Stat(wd)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("working directory is not accessible")
	}
	// Write a tiny probe file to verify the directory is writable
	probe := filepath.Join(wd, ".age-tool-probe")
	if err := os.WriteFile(probe, []byte{}, 0600); err != nil {
		return fmt.Errorf("working directory is not writable")
	}
	// Best-effort removal: a leftover empty probe file is harmless
	_ = os.Remove(probe)
	return nil
}

// ─── Startup checks ─────────────────────────────────────────────────────────

// cleanupLeftoverTempFiles finds temporary files left by a session that was
// killed mid-operation and prompts the user to delete them.
func cleanupLeftoverTempFiles(reader *bufio.Reader) {
	leftovers, err := core.FindLeftoverTempFiles(keyDir)
	if err != nil || len(leftovers) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("!! WARNING: Leftover temporary file(s) found from a previous session !!")
	for _, f := range leftovers {
		fmt.Printf("   - %s\n", f)
	}
	fmt.Print("These may contain decrypted key material or partial plaintext. Delete them now? [Y/n]: ")
	if confirmDefaultYes(reader) {
		for _, f := range leftovers {
			if err := os.Remove(filepath.Join(keyDir, f)); err != nil {
				fmt.Fprintf(os.Stderr, "  Could not delete %s.\n", f)
			} else {
				fmt.Printf("  Deleted: %s\n", f)
			}
		}
	}
}

// offerKeyMigration looks for 1.x-style key files in the current folder
// and, when the key store is in use, offers to copy them into it. The
// originals are never changed. "never" stops the offer for this folder.
func offerKeyMigration(reader *bufio.Reader) {
	if !usingStore || core.SameDir(keyDir, ".") {
		return
	}
	settings := core.LoadSettings(locations.SettingsFile())
	if settings.IsMigrationDismissed(".") {
		return
	}
	files, err := core.ListKeyFiles(".")
	if err != nil || len(files) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("Key files from age-tool 1.x were found in this folder:")
	for _, f := range files {
		fmt.Printf("   - %s\n", f)
	}
	fmt.Printf("age-tool 2.0 keeps keys in your key store: %s\n", keyDir)
	fmt.Println("Import them? Copies are made; the files here are not changed.")
	fmt.Print("[Y]es / [n]o / ne[v]er ask for this folder: ")

	switch strings.TrimSpace(strings.ToLower(readLine(reader))) {
	case "", "y", "yes":
		// handled below
	case "v", "never":
		settings.DismissMigration(".")
		if err := settings.Save(locations.SettingsFile()); err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not save settings: %v\n", err)
		} else {
			fmt.Println("OK, you won't be asked again for this folder.")
			fmt.Println("To use the keys here directly, run: age-tool --keys .")
		}
		return
	default:
		fmt.Println("Not imported. To use the keys here directly, run: age-tool --keys .")
		return
	}

	result, err := core.ImportKeyFiles(".", keyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	report := func(label string, names []string) {
		if len(names) > 0 {
			fmt.Printf("  %s: %s\n", label, strings.Join(names, ", "))
		}
	}
	report("Imported", result.Imported)
	report("Already in key store", result.AlreadyPresent)
	report("Skipped, a different key with this name is already in the key store", result.Conflicts)
	report("Could not import", result.Failed)

	if len(result.Imported) > 0 || len(result.AlreadyPresent) > 0 {
		fmt.Println("Once you've checked your keys work, you can delete the originals here.")
		fmt.Println("Until then, remember any .priv files in this folder are still private keys.")
		// Don't offer again for this folder once everything is in the store
		if len(result.Conflicts) == 0 && len(result.Failed) == 0 {
			settings.DismissMigration(".")
			_ = settings.Save(locations.SettingsFile())
		}
	}
}

// checkUnencryptedKeys warns about any .priv files that are not
// passphrase-protected, so the user is immediately aware of insecure keys.
func checkUnencryptedKeys() {
	openKeys, err := core.OpenPrivateKeys(keyDir)
	if err != nil || len(openKeys) == 0 {
		return
	}

	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println()
	fmt.Println("!! WARNING: Unencrypted private key(s) detected !!")
	for _, k := range openKeys {
		fmt.Printf("   - %s\n", nicks.Label(k))
	}
	fmt.Println("These keys are NOT passphrase-protected and cannot be used for decryption.")
	fmt.Println("Use Key Management > Encrypt a Private Key to secure them.")
}

// checkKeyFilePermissions finds .priv files with overly permissive
// permissions and offers to fix each one.
func checkKeyFilePermissions(reader *bufio.Reader) {
	badPerms, err := core.PermissiveKeyFiles(keyDir)
	if err != nil || len(badPerms) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("!! WARNING: Key file(s) with overly permissive permissions !!")
	for _, f := range badPerms {
		path := filepath.Join(keyDir, f)
		warning := core.CheckKeyPermissions(path)
		if warning == "" {
			continue
		}
		fmt.Printf("  WARNING: %s — %s\n", f, warning)
		fmt.Printf("  Fix permissions to owner-only (0600)? [Y/n]: ")
		if confirmDefaultYes(reader) {
			if err := core.FixKeyPermissions(path); err != nil {
				fmt.Fprintf(os.Stderr, "  Could not fix permissions.\n")
			} else {
				fmt.Printf("  Permissions fixed: %s -> 0600\n", f)
			}
		}
	}
}

// ─── Encrypt ────────────────────────────────────────────────────────────────

// encrypt walks the user through selecting a file and public key, then
// encrypts the file. Errors are printed but do not terminate the program,
// allowing the user to return to the main menu.
func encrypt(reader *bufio.Reader) {
	// List all non-.age files in the current directory as encryption candidates
	files, err := core.ListFiles(".", func(name string) bool {
		return !strings.HasSuffix(name, core.AgeExt)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing files.")
		return
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No files found to encrypt.")
		return
	}

	fmt.Println("\nFiles available to encrypt:")
	for i, f := range files {
		fmt.Printf("  %d) %s\n", i+1, f)
	}
	file, ok := promptSelectionOrBack(reader, "Select file to encrypt", len(files))
	if !ok {
		return
	}
	inputPath := files[file]

	// Validate the selected file exists and is within size limits
	if _, err := core.CheckFileSize(inputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// List all .pub key files for the user to choose a recipient
	pubFiles, err := core.ListPublicKeys(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	if len(pubFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No .pub key files found in %s.\n", keysWhere())
		return
	}

	// Display public keys with their nicknames
	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println("\nPublic key files:")
	for i, f := range pubFiles {
		fmt.Printf("  %d) %s\n", i+1, nicks.Label(f))
	}
	keyIdx, ok := promptSelectionOrBack(reader, "Select public key", len(pubFiles))
	if !ok {
		return
	}
	keyFile := pubFiles[keyIdx]

	// Parse (and so validate) the selected public key
	recipient, err := core.ReadRecipient(filepath.Join(keyDir, keyFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Check if the output file already exists and confirm overwrite
	outputPath := core.EncryptedOutputPath(inputPath)
	if !confirmOverwrite(reader, outputPath) {
		fmt.Println("Encryption cancelled.")
		return
	}

	// Encrypt, writing output atomically with restrictive permissions
	if err := core.EncryptFile(inputPath, outputPath, recipient); err != nil {
		fmt.Fprintln(os.Stderr, "Encryption failed.")
		return
	}

	fmt.Printf("\nEncrypted: %s -> %s\n", inputPath, outputPath)
	printWarnings(auditFor(filepath.Dir(outputPath)).RecordEncrypt(time.Now(), inputPath, outputPath, keyFile, nicks[keyFile]))
}

// ─── Decrypt ────────────────────────────────────────────────────────────────

// decrypt walks the user through selecting an .age file and a
// passphrase-protected .priv key, unlocks the key in memory, then decrypts
// the file. Unprotected keys are rejected with a warning.
func decrypt(reader *bufio.Reader) {
	// List all .age files in the current directory as decryption candidates
	ageFiles, err := core.ListFiles(".", func(name string) bool {
		return strings.HasSuffix(name, core.AgeExt)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing files.")
		return
	}
	if len(ageFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No .age files found in current directory.")
		return
	}

	fmt.Println("\nEncrypted files:")
	for i, f := range ageFiles {
		fmt.Printf("  %d) %s\n", i+1, f)
	}
	fileIdx, ok := promptSelectionOrBack(reader, "Select file to decrypt", len(ageFiles))
	if !ok {
		return
	}
	inputPath := ageFiles[fileIdx]

	// Validate the selected file exists and is within size limits
	if _, err := core.CheckFileSize(inputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// List the .priv key files
	privFiles, err := core.ListPrivateKeys(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	if len(privFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No .priv key files found in %s.\n", keysWhere())
		return
	}

	// Display private keys with their nicknames
	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println("\nPrivate key files:")
	for i, f := range privFiles {
		fmt.Printf("  %d) %s\n", i+1, nicks.Label(f))
	}
	keyIdx, ok := promptSelectionOrBack(reader, "Select private key", len(privFiles))
	if !ok {
		return
	}
	keyFile := privFiles[keyIdx]
	keyPath := filepath.Join(keyDir, keyFile)

	// Only passphrase-protected private keys are accepted
	if err := core.ValidatePrivKeyFile(keyPath); err != nil {
		fmt.Fprintln(os.Stderr, "\nWARNING: The selected private key is NOT passphrase-protected.")
		fmt.Fprintln(os.Stderr, "For security, only passphrase-protected .priv files are accepted.")
		fmt.Fprintln(os.Stderr, "Use Key Management > Encrypt a Private Key to secure it.")
		return
	}

	// Prompt for the passphrase with limited attempts. The private key is
	// unlocked entirely in memory and never written to disk.
	var identity age.Identity
	for attempt := 1; attempt <= core.MaxPassAttempts; attempt++ {
		fmt.Printf("\nEnter passphrase for private key (attempt %d/%d): ", attempt, core.MaxPassAttempts)
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading passphrase.")
			return
		}

		// Attempt to unlock the key, then clear the passphrase from memory
		identity, err = core.UnlockIdentity(keyPath, string(passBytes))
		core.ClearBytes(passBytes)

		if err == nil {
			break
		}

		// Only a wrong passphrase is worth retrying; any other error means
		// the key file itself can't be used
		if !errors.Is(err, core.ErrWrongPassphrase) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		if attempt < core.MaxPassAttempts {
			fmt.Fprintln(os.Stderr, "Incorrect passphrase, try again.")
		} else {
			fmt.Fprintln(os.Stderr, "Maximum passphrase attempts exceeded.")
			return
		}
	}

	// Check if the output file already exists and confirm overwrite
	outputPath := core.DecryptedOutputPath(inputPath)
	if !confirmOverwrite(reader, outputPath) {
		fmt.Println("Decryption cancelled.")
		return
	}

	// Decrypt, writing output atomically with restrictive permissions
	if err := core.DecryptFile(inputPath, outputPath, identity); err != nil {
		fmt.Fprintln(os.Stderr, "Decryption failed.")
		return
	}

	fmt.Printf("\nDecrypted: %s -> %s\n", inputPath, outputPath)
	printWarnings(auditFor(filepath.Dir(outputPath)).RecordDecrypt(time.Now(), inputPath, outputPath, keyFile, nicks[keyFile]))
}

// ─── Key Management ─────────────────────────────────────────────────────────

// keyManagement presents a submenu for key-related operations and loops
// until the user chooses to return to the main menu.
func keyManagement(reader *bufio.Reader) {
	for {
		fmt.Println("\n--- Key Management ---")
		fmt.Println("1) List Keys")
		fmt.Println("2) Generate New Key Pair")
		fmt.Println("3) Encrypt a Private Key")
		fmt.Println("4) Delete a Key Pair")
		fmt.Println("5) Nickname a Key")
		fmt.Println("6) Import a Public Key (someone else's)")
		fmt.Println("7) Export / Share a Public Key")
		fmt.Println("8) Back")
		fmt.Print("\nChoose [1-8]: ")

		switch strings.TrimSpace(readLine(reader)) {
		case "1":
			listKeys()
		case "2":
			generateKeyPair(reader)
		case "3":
			encryptPrivateKey(reader)
		case "4":
			deleteKeyPair(reader)
		case "5":
			nicknameKey(reader)
		case "6":
			importPublicKey(reader)
		case "7":
			exportPublicKey(reader)
		case "8":
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

// listKeys displays the key pairs in the key directory. Each private key is
// labelled [ENCRYPTED] or [OPEN], plus [PERMS] if its permissions are too
// loose. Nicknames are shown alongside each file if set.
func listKeys() {
	pairs, _ := core.ListKeyPairs(keyDir)
	if len(pairs) == 0 {
		fmt.Printf("\nNo key files found in %s.\n", keysWhere())
		return
	}

	nicks := core.LoadNicknames(nicknameFile)
	fmt.Printf("\nKey pairs in %s:\n", keysWhere())
	fmt.Println()

	for _, p := range pairs {
		fmt.Printf("  %s\n", p.Base)

		if p.PubFile != "" {
			fmt.Printf("    Public:  %s\n", nicks.Label(p.PubFile))
		} else {
			fmt.Printf("    Public:  (not found)\n")
		}

		if p.PrivFile != "" {
			privPath := filepath.Join(keyDir, p.PrivFile)
			encrypted, err := core.IsAgeEncrypted(privPath)
			status := "[ENCRYPTED]"
			if err != nil {
				status = "[ERROR]"
			} else if !encrypted {
				status = "[OPEN]"
			}
			permWarn := ""
			if core.CheckKeyPermissions(privPath) != "" {
				permWarn = " [PERMS]"
			}
			fmt.Printf("    Private: %s %s%s\n", nicks.Label(p.PrivFile), status, permWarn)
		} else {
			fmt.Printf("    Private: (not found)\n")
		}
	}
}

// generateKeyPair prompts for a name and passphrase and creates a new key
// pair. The unencrypted private key is never written to disk.
func generateKeyPair(reader *bufio.Reader) {
	fmt.Print("\nKey pair name: ")
	name, err := core.SanitiseInput(readLine(reader))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Name cannot be empty.")
		return
	}
	if err := core.ValidateFilename(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Check the name is free before asking for a passphrase
	if core.KeyPairExists(keyDir, name) {
		fmt.Fprintf(os.Stderr, "Key files for '%s' already exist. Choose a different name.\n", name)
		return
	}

	passphrase, err := promptPassphraseConfirm("Enter passphrase for private key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	pubPath, privPath, err := core.GenerateKeyPair(keyDir, name, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	fmt.Printf("\nKey pair generated successfully:\n")
	fmt.Printf("  Public key:  %s\n", pubPath)
	fmt.Printf("  Private key: %s [ENCRYPTED]\n", privPath)

	printWarnings(auditFor(keyDir).RecordKeyCreation(time.Now(), name, pubPath, privPath))

	fmt.Println("\nYou can nickname each key individually via Key Management > Nickname a Key.")
}

// encryptPrivateKey lets the user select an unencrypted .priv file and
// protects it in place with a passphrase.
func encryptPrivateKey(reader *bufio.Reader) {
	openKeys, err := core.OpenPrivateKeys(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	if len(openKeys) == 0 {
		fmt.Println("\nNo unencrypted .priv files found. All private keys are already protected.")
		return
	}

	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println("\nUnencrypted private key files:")
	for i, f := range openKeys {
		fmt.Printf("  %d) %s [OPEN]\n", i+1, nicks.Label(f))
	}
	idx, ok := promptSelectionOrBack(reader, "Select key to encrypt", len(openKeys))
	if !ok {
		return
	}
	keyFile := openKeys[idx]
	keyPath := filepath.Join(keyDir, keyFile)

	// Read the key before asking for a passphrase, so a bad file is
	// reported straight away
	secretKey, err := core.ReadOpenSecretKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	passphrase, err := promptPassphraseConfirm("Enter passphrase")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Encrypt the private key and overwrite the file in place
	if err := core.WritePassphraseProtectedKey(keyPath, secretKey, passphrase); err != nil {
		fmt.Fprintln(os.Stderr, "Error encrypting private key.")
		return
	}

	fmt.Printf("\nPrivate key encrypted successfully: %s [ENCRYPTED]\n", nicks.Label(keyFile))
}

// deleteKeyPair lets the user choose a key pair, confirms, then deletes its
// .pub and .priv files and their nicknames.
func deleteKeyPair(reader *bufio.Reader) {
	pairs, _ := core.ListKeyPairs(keyDir)
	if len(pairs) == 0 {
		fmt.Printf("\nNo key files found in %s.\n", keysWhere())
		return
	}

	nicks := core.LoadNicknames(nicknameFile)

	// Display the key pairs with their existing files and nicknames
	fmt.Println("\nKey pairs:")
	for i, p := range pairs {
		parts := []string{}
		if p.PubFile != "" {
			parts = append(parts, core.PubExt)
		}
		if p.PrivFile != "" {
			parts = append(parts, core.PrivExt)
		}
		// Show a nickname if either the .pub or .priv has one
		label := p.Base
		if nick := nicks[p.Base+core.PubExt]; nick != "" {
			label = fmt.Sprintf("%s (%s)", nick, p.Base)
		} else if nick := nicks[p.Base+core.PrivExt]; nick != "" {
			label = fmt.Sprintf("%s (%s)", nick, p.Base)
		}
		fmt.Printf("  %d) %s (%s)\n", i+1, label, strings.Join(parts, ", "))
	}

	idx, ok := promptSelectionOrBack(reader, "Select key pair to delete", len(pairs))
	if !ok {
		return
	}
	base := pairs[idx].Base

	fmt.Printf("\nAre you sure you want to delete '%s'? This cannot be undone. [y/N]: ", base)
	confirm := strings.TrimSpace(strings.ToLower(readLine(reader)))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Deletion cancelled.")
		return
	}

	deleted, failed := core.DeleteKeyPair(keyDir, base, nicks)
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "Error deleting %s.\n", f)
	}
	if err := nicks.Save(nicknameFile); err != nil {
		fmt.Fprintln(os.Stderr, "Error updating nicknames.")
	}
	if len(deleted) > 0 {
		fmt.Printf("Deleted: %s\n", strings.Join(deleted, ", "))
	}
}

// nicknameKey lets the user give any .pub or .priv file a nickname. Each
// file is nicknamed independently.
func nicknameKey(reader *bufio.Reader) {
	keyFiles, err := core.ListKeyFiles(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	if len(keyFiles) == 0 {
		fmt.Printf("\nNo key files found in %s.\n", keysWhere())
		return
	}

	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println("\nKey files:")
	for i, f := range keyFiles {
		if nick := nicks[f]; nick != "" {
			fmt.Printf("  %d) %s (current nickname: %s)\n", i+1, f, nick)
		} else {
			fmt.Printf("  %d) %s (no nickname)\n", i+1, f)
		}
	}

	idx, ok := promptSelectionOrBack(reader, "Select key to nickname", len(keyFiles))
	if !ok {
		return
	}
	selected := keyFiles[idx]

	fmt.Print("Enter nickname: ")
	nick, err := core.SanitiseInput(readLine(reader))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if nick == "" {
		fmt.Fprintln(os.Stderr, "Nickname cannot be empty.")
		return
	}

	nicks[selected] = nick
	fmt.Printf("Nickname '%s' applied to %s.\n", nick, selected)
	if err := nicks.Save(nicknameFile); err != nil {
		fmt.Fprintln(os.Stderr, "Error saving nicknames.")
	}
}

// importPublicKey adds someone else's public key (a "contact") so files can
// be encrypted for them. The key can be pasted or read from a .pub file.
func importPublicKey(reader *bufio.Reader) {
	fmt.Println("\nPaste their public key (starts with age1...), or enter the path to their .pub file.")
	fmt.Print("Public key or file: ")
	entry := strings.TrimSpace(readLine(reader))
	if entry == "" {
		fmt.Println("Import cancelled.")
		return
	}

	// Treat the entry as a key if it looks like one (public or, by mistake,
	// private, which ParsePublicKey refuses without echoing it), otherwise
	// as a file path
	keyText := entry
	looksLikeKey := strings.HasPrefix(entry, "age1") || strings.Contains(strings.ToUpper(entry), "AGE-SECRET-KEY-")
	if !looksLikeKey {
		text, err := core.ReadPublicKeyString(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		keyText = text
	}
	key, err := core.ParsePublicKey(keyText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	fmt.Print("Name for this key (e.g. alice): ")
	name, err := core.SanitiseInput(readLine(reader))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Name cannot be empty.")
		return
	}

	path, err := core.ImportPublicKey(keyDir, name, key)
	if errors.Is(err, core.ErrKeyExists) {
		fmt.Fprintf(os.Stderr, "Key files for '%s' already exist. Choose a different name.\n", name)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Printf("Public key saved: %s\n", path)

	// Optional nickname, e.g. the person's full name
	fmt.Print("Nickname (optional, press Enter to skip): ")
	nick, err := core.SanitiseInput(readLine(reader))
	if err == nil && nick != "" {
		nicks := core.LoadNicknames(nicknameFile)
		nicks[filepath.Base(path)] = nick
		if err := nicks.Save(nicknameFile); err != nil {
			fmt.Fprintln(os.Stderr, "Error saving nicknames.")
		} else {
			fmt.Printf("Nickname '%s' applied to %s.\n", nick, filepath.Base(path))
		}
	}
	fmt.Println("You can now choose this key when encrypting files for them.")
}

// exportPublicKey shows a public key so it can be shared, and offers to
// save a copy in the current folder.
func exportPublicKey(reader *bufio.Reader) {
	pubFiles, err := core.ListPublicKeys(keyDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error listing key files.")
		return
	}
	if len(pubFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No .pub key files found in %s.\n", keysWhere())
		return
	}

	nicks := core.LoadNicknames(nicknameFile)
	fmt.Println("\nPublic key files:")
	for i, f := range pubFiles {
		fmt.Printf("  %d) %s\n", i+1, nicks.Label(f))
	}
	idx, ok := promptSelectionOrBack(reader, "Select public key to share", len(pubFiles))
	if !ok {
		return
	}
	pubFile := pubFiles[idx]

	key, err := core.ReadPublicKeyString(filepath.Join(keyDir, pubFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Printf("\nPublic key %s:\n\n  %s\n\n", nicks.Label(pubFile), key)
	fmt.Println("Share this with anyone who needs to encrypt files for you.")
	fmt.Println("It is safe to share. Never share a .priv file.")

	// The key folder already holds the file, so only offer a copy elsewhere
	if core.SameDir(keyDir, ".") {
		return
	}
	fmt.Printf("\nSave a copy as %s in the current folder? [y/N]: ", pubFile)
	answer := strings.TrimSpace(strings.ToLower(readLine(reader)))
	if answer != "y" && answer != "yes" {
		return
	}
	if err := core.ExportPublicKey(filepath.Join(keyDir, pubFile), pubFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Printf("Saved: %s\n", pubFile)
}

// ─── Prompt helpers ─────────────────────────────────────────────────────────

// printWarnings prints non-fatal warnings (e.g. audit-log problems).
func printWarnings(warnings []error) {
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "Warning: %v.\n", w)
	}
}

// readLine reads one line of user input. If input has ended (Ctrl+D, a
// closed pipe, or end of a redirected file) and nothing was read, it exits
// rather than letting the caller loop forever on empty input. A final line
// without a trailing newline is still returned; the next call then exits.
func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println("\nInput closed. Exiting.")
		os.Exit(0)
	}
	return line
}

// confirmDefaultYes reads a [Y/n] answer, treating an empty answer as yes.
func confirmDefaultYes(reader *bufio.Reader) bool {
	answer := strings.TrimSpace(strings.ToLower(readLine(reader)))
	return answer == "" || answer == "y" || answer == "yes"
}

// confirmOverwrite asks before overwriting an existing file. Returns true if
// the user confirms or the file does not exist.
func confirmOverwrite(reader *bufio.Reader, path string) bool {
	if !core.FileExists(path) {
		return true
	}
	fmt.Printf("\nFile '%s' already exists. Overwrite? [y/N]: ", filepath.Base(path))
	answer := strings.TrimSpace(strings.ToLower(readLine(reader)))
	return answer == "y" || answer == "yes"
}

// promptSelection repeatedly prompts the user until they enter a valid
// number between 1 and max. Returns a zero-based index.
func promptSelection(reader *bufio.Reader, prompt string, max int) int {
	for {
		fmt.Printf("%s [1-%d]: ", prompt, max)
		n, err := strconv.Atoi(strings.TrimSpace(readLine(reader)))
		if err == nil && n >= 1 && n <= max {
			return n - 1
		}
		fmt.Println("Invalid selection, try again.")
	}
}

// promptSelectionOrBack prints a clearly separated "<- Go Back" entry after
// a list of n items (numbered 1..n), then prompts for a choice. Returns the
// zero-based index of the chosen item and true, or false if the user chose
// Go Back.
func promptSelectionOrBack(reader *bufio.Reader, prompt string, n int) (int, bool) {
	fmt.Println()
	fmt.Printf("  %d) <- Go Back\n", n+1)
	idx := promptSelection(reader, prompt, n+1)
	return idx, idx != n
}

// promptPassphraseConfirm prompts for a passphrase twice (hidden input) and
// returns it only if both entries match and it meets the length rule. Weak
// passphrases are allowed with a warning.
func promptPassphraseConfirm(prompt string) (string, error) {
	fmt.Printf("\n%s (min %d chars): ", prompt, core.MinPassphraseLen)
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("could not read passphrase")
	}
	defer core.ClearBytes(pass1)

	fmt.Printf("Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("could not read passphrase")
	}
	defer core.ClearBytes(pass2)

	if string(pass1) != string(pass2) {
		return "", fmt.Errorf("passphrases do not match")
	}

	passphrase := string(pass1)
	if err := core.ValidateNewPassphrase(passphrase); err != nil {
		return "", err
	}

	// Warn about weak passphrases but allow the user to proceed
	if warning := core.PassphraseWarning(passphrase); warning != "" {
		fmt.Printf("WARNING: %s. Consider using a stronger passphrase.\n", warning)
	}

	return passphrase, nil
}
