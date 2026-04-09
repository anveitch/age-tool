// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"golang.org/x/term"
)

// Log file paths for the audit/receipt system.
const (
	logFile = "age-tool.log"
	logsDir = "logs"
)

// nicknameFile is the JSON config file that stores key nicknames.
// It maps filenames (e.g. "work.priv") to human-readable nicknames.
const nicknameFile = "keys.json"

// tempFileRegistry tracks temporary decrypted key files so they can be
// cleaned up on exit (normal return, defer, or signal). Access is
// synchronised because the signal handler runs in a separate goroutine.
var (
	tempFiles   []string
	tempFilesMu sync.Mutex
)

// registerTempFile adds a path to the global cleanup registry.
func registerTempFile(path string) {
	tempFilesMu.Lock()
	defer tempFilesMu.Unlock()
	tempFiles = append(tempFiles, path)
}

// unregisterTempFile removes a path from the registry (called after
// successful cleanup so we don't try to remove it twice).
func unregisterTempFile(path string) {
	tempFilesMu.Lock()
	defer tempFilesMu.Unlock()
	for i, p := range tempFiles {
		if p == path {
			tempFiles = append(tempFiles[:i], tempFiles[i+1:]...)
			return
		}
	}
}

// cleanupTempFiles removes every file still in the registry.
func cleanupTempFiles() {
	tempFilesMu.Lock()
	defer tempFilesMu.Unlock()
	for _, p := range tempFiles {
		os.Remove(p)
	}
	tempFiles = nil
}

// ─── Nickname helpers ───────────────────────────────────────────────────────

// loadNicknames reads the keys.json file and returns the filename-to-nickname
// mapping. Returns an empty map if the file does not exist or cannot be parsed.
func loadNicknames() map[string]string {
	data, err := os.ReadFile(nicknameFile)
	if err != nil {
		return make(map[string]string)
	}
	var nicks map[string]string
	if err := json.Unmarshal(data, &nicks); err != nil {
		return make(map[string]string)
	}
	return nicks
}

// saveNicknames writes the nickname map to keys.json with readable formatting.
func saveNicknames(nicks map[string]string) error {
	data, err := json.MarshalIndent(nicks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(nicknameFile, append(data, '\n'), 0644)
}

// formatKeyName returns "Nickname (filename)" if the file has a nickname,
// or just "filename" if it does not.
func formatKeyName(filename string, nicks map[string]string) string {
	if nick, ok := nicks[filename]; ok && nick != "" {
		return fmt.Sprintf("%s (%s)", nick, filename)
	}
	return filename
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	// Defer cleanup as a secondary safety net for normal exit paths
	defer cleanupTempFiles()

	// Set up a signal handler to catch Ctrl+C (SIGINT), SIGTERM, and SIGHUP
	// so that temporary key files are always removed before the process exits.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		cleanupTempFiles()
		os.Exit(1)
	}()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("age-tool: file encryption/decryption")

	// Startup health check: warn the user about any unencrypted .priv files
	// in the current directory before showing the main menu.
	checkUnencryptedKeys()

	// Main loop: present the menu after each operation until the user quits
	for {
		fmt.Println()
		fmt.Println("1) Encrypt")
		fmt.Println("2) Decrypt")
		fmt.Println("3) Key Management")
		fmt.Println("4) Quit")
		fmt.Print("\nChoose [1/2/3/4/q]: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		// Accept "4", "q", or "Q" as quit commands
		switch strings.ToLower(choice) {
		case "1":
			encrypt(reader)
		case "2":
			decrypt(reader)
		case "3":
			keyManagement(reader)
		case "4", "q":
			// Exit cleanly when the user chooses to quit
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

// checkUnencryptedKeys scans the current directory for .priv files and
// displays a warning for any that are not passphrase-protected. This runs
// once at startup so the user is immediately aware of insecure keys.
func checkUnencryptedKeys() {
	privFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".priv")
	})
	if err != nil || len(privFiles) == 0 {
		return
	}

	// Load nicknames so warnings can include the friendly name
	nicks := loadNicknames()

	// Collect the names of any unencrypted private key files
	var openKeys []string
	for _, f := range privFiles {
		encrypted, err := isAgeEncrypted(f)
		if err != nil {
			continue
		}
		if !encrypted {
			openKeys = append(openKeys, f)
		}
	}

	// Display a prominent warning if any unencrypted keys were found
	if len(openKeys) > 0 {
		fmt.Println()
		fmt.Println("!! WARNING: Unencrypted private key(s) detected !!")
		for _, k := range openKeys {
			fmt.Printf("   - %s\n", formatKeyName(k, nicks))
		}
		fmt.Println("These keys are NOT passphrase-protected and cannot be used for decryption.")
		fmt.Println("Use Key Management > Encrypt a Private Key to secure them.")
	}
}

// ─── Encrypt ────────────────────────────────────────────────────────────────

// encrypt walks the user through selecting a file and public key,
// then encrypts the file. Errors are printed but do not terminate the program,
// allowing the user to return to the main menu.
func encrypt(reader *bufio.Reader) {
	// List all non-.age files in the current directory as encryption candidates
	files, err := listFiles(".", func(name string) bool {
		return !strings.HasSuffix(name, ".age")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing files: %v\n", err)
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
	// Add a clearly separated "Go Back" option at the end of the list
	fmt.Println()
	fmt.Printf("  %d) <- Go Back\n", len(files)+1)

	file := promptSelection(reader, "Select file to encrypt", len(files)+1)
	// If the user selected the last option, return to the main menu
	if file == len(files) {
		return
	}
	inputPath := files[file]

	// List all .pub key files for the user to choose a recipient
	pubFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".pub")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing key files: %v\n", err)
		return
	}
	if len(pubFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No .pub key files found in current directory.")
		return
	}

	// Load nicknames and display public keys with their friendly names
	nicks := loadNicknames()
	fmt.Println("\nPublic key files:")
	for i, f := range pubFiles {
		fmt.Printf("  %d) %s\n", i+1, formatKeyName(f, nicks))
	}
	keyIdx := promptSelection(reader, "Select public key", len(pubFiles))

	// Parse the selected public key file into an age recipient
	pubKey, err := readRecipient(pubFiles[keyIdx])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key: %v\n", err)
		return
	}

	// Perform encryption, writing output as <original-filename>.age
	outputPath := inputPath + ".age"
	if err := encryptFile(inputPath, outputPath, pubKey); err != nil {
		fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
		return
	}

	fmt.Printf("\nEncrypted: %s -> %s\n", inputPath, outputPath)

	// Log the encryption transaction with file hashes
	srcMD5, srcSHA256, _ := hashFile(inputPath)
	outMD5, outSHA256, _ := hashFile(outputPath)
	keyNick := nicks[pubFiles[keyIdx]]
	logEncrypt(time.Now(), inputPath, srcMD5, srcSHA256, outputPath, outMD5, outSHA256, pubFiles[keyIdx], keyNick)
}

// ─── Decrypt ────────────────────────────────────────────────────────────────

// decrypt walks the user through selecting an .age file and a .priv key file,
// then decrypts the file. If the private key is passphrase-protected it will
// be temporarily decrypted for use and cleaned up immediately afterwards.
// Unprotected keys are rejected with a warning.
func decrypt(reader *bufio.Reader) {
	// List all .age files in the current directory as decryption candidates
	ageFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".age")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing files: %v\n", err)
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
	// Add a clearly separated "Go Back" option at the end of the list
	fmt.Println()
	fmt.Printf("  %d) <- Go Back\n", len(ageFiles)+1)

	fileIdx := promptSelection(reader, "Select file to decrypt", len(ageFiles)+1)
	// If the user selected the last option, return to the main menu
	if fileIdx == len(ageFiles) {
		return
	}
	inputPath := ageFiles[fileIdx]

	// Scan the current directory for .priv key files and present them as a list
	privFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".priv")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing key files: %v\n", err)
		return
	}
	if len(privFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No .priv key files found in current directory. Please add a private key file with a .priv extension.")
		return
	}

	// Load nicknames and display private keys with their friendly names
	nicks := loadNicknames()
	fmt.Println("\nPrivate key files:")
	for i, f := range privFiles {
		fmt.Printf("  %d) %s\n", i+1, formatKeyName(f, nicks))
	}
	keyIdx := promptSelection(reader, "Select private key", len(privFiles))
	keyPath := privFiles[keyIdx]

	// Check whether the selected .priv file is passphrase-protected (age-encrypted).
	// Unprotected private keys are rejected for security reasons.
	encrypted, err := isAgeEncrypted(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		return
	}
	if !encrypted {
		fmt.Fprintln(os.Stderr, "\nWARNING: The selected private key is NOT passphrase-protected.")
		fmt.Fprintln(os.Stderr, "For security, only passphrase-protected .priv files are accepted.")
		fmt.Fprintln(os.Stderr, "Use Key Management > Encrypt a Private Key to secure it.")
		return
	}

	// Prompt the user for the passphrase (input is hidden/masked)
	fmt.Print("\nEnter passphrase for private key: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // move to a new line after hidden input
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading passphrase: %v\n", err)
		return
	}
	passphrase := string(passBytes)

	// Decrypt the passphrase-protected key to a temporary hidden file
	tmpKeyPath, err := decryptKeyToTempFile(keyPath, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting private key: %v\n", err)
		return
	}
	// Ensure the temp file is cleaned up after this function returns
	defer removeTempFile(tmpKeyPath)

	// Parse the temporarily decrypted private key into an age identity
	identity, err := readIdentity(tmpKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing decrypted private key: %v\n", err)
		return
	}

	// Perform decryption, stripping the .age extension for the output filename
	outputPath := strings.TrimSuffix(inputPath, ".age")
	if err := decryptFile(inputPath, outputPath, identity); err != nil {
		fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
		return
	}

	fmt.Printf("\nDecrypted: %s -> %s\n", inputPath, outputPath)

	// Log the decryption transaction with file hashes
	srcMD5, srcSHA256, _ := hashFile(inputPath)
	outMD5, outSHA256, _ := hashFile(outputPath)
	keyNick := nicks[keyPath]
	logDecrypt(time.Now(), inputPath, srcMD5, srcSHA256, outputPath, outMD5, outSHA256, keyPath, keyNick)
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
		fmt.Println("6) Back")
		fmt.Print("\nChoose [1-6]: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
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
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

// listKeys scans the current directory for .pub and .priv files and displays
// them as paired entries where possible. Each .priv file is labelled with
// [ENCRYPTED] or [OPEN] to indicate its protection status. Nicknames are
// shown alongside each file if set.
func listKeys() {
	pubFiles, _ := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".pub")
	})
	privFiles, _ := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".priv")
	})

	if len(pubFiles) == 0 && len(privFiles) == 0 {
		fmt.Println("\nNo key files found in current directory.")
		return
	}

	// Load nicknames for display
	nicks := loadNicknames()

	// Build a set of unique key base names from both .pub and .priv files
	baseNames := make(map[string]bool)
	for _, f := range pubFiles {
		baseNames[strings.TrimSuffix(f, ".pub")] = true
	}
	for _, f := range privFiles {
		baseNames[strings.TrimSuffix(f, ".priv")] = true
	}

	// Sort the base names for consistent display order
	sorted := make([]string, 0, len(baseNames))
	for name := range baseNames {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	fmt.Println("\nKey pairs in current directory:")
	fmt.Println()

	for _, base := range sorted {
		fmt.Printf("  %s\n", base)

		// Check for the public key file and show its nickname
		pubPath := base + ".pub"
		if fileExists(pubPath) {
			fmt.Printf("    Public:  %s\n", formatKeyName(pubPath, nicks))
		} else {
			fmt.Printf("    Public:  (not found)\n")
		}

		// Check for the private key file, its encryption status, and nickname
		privPath := base + ".priv"
		if fileExists(privPath) {
			encrypted, err := isAgeEncrypted(privPath)
			status := "[ENCRYPTED]"
			if err != nil {
				status = fmt.Sprintf("[ERROR: %v]", err)
			} else if !encrypted {
				status = "[OPEN]"
			}
			fmt.Printf("    Private: %s %s\n", formatKeyName(privPath, nicks), status)
		} else {
			fmt.Printf("    Private: (not found)\n")
		}
	}
}

// generateKeyPair creates a new AGE key pair. The private key is encrypted
// with a user-provided passphrase and written directly to disk — the
// unencrypted key material is never written to a file at any point.
func generateKeyPair(reader *bufio.Reader) {
	// Prompt for the key pair name
	fmt.Print("\nKey pair name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Fprintln(os.Stderr, "Name cannot be empty.")
		return
	}

	// Check that neither the .pub nor .priv file already exists
	pubPath := name + ".pub"
	privPath := name + ".priv"
	if fileExists(pubPath) || fileExists(privPath) {
		fmt.Fprintf(os.Stderr, "Key files for '%s' already exist. Choose a different name.\n", name)
		return
	}

	// Prompt for a passphrase to protect the private key (hidden input)
	passphrase, err := promptPassphraseConfirm("Enter passphrase for private key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading passphrase: %v\n", err)
		return
	}

	// Generate a new X25519 key pair in memory
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		return
	}

	// Write the public key to the .pub file
	if err := os.WriteFile(pubPath, []byte(identity.Recipient().String()+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key: %v\n", err)
		return
	}

	// Encrypt the private key string with the passphrase and write it
	// directly to the .priv file — no plaintext key ever touches disk.
	if err := writeEncryptedPrivateKey(privPath, identity.String(), passphrase); err != nil {
		// Clean up the .pub file if the .priv file failed to write
		os.Remove(pubPath)
		fmt.Fprintf(os.Stderr, "Error writing encrypted private key: %v\n", err)
		return
	}

	fmt.Printf("\nKey pair generated successfully:\n")
	fmt.Printf("  Public key:  %s\n", pubPath)
	fmt.Printf("  Private key: %s [ENCRYPTED]\n", privPath)

	// Log the key creation transaction with file hashes
	pubMD5, pubSHA256, _ := hashFile(pubPath)
	privMD5, privSHA256, _ := hashFile(privPath)
	logKeyCreation(time.Now(), name, pubPath, pubMD5, pubSHA256, privPath, privMD5, privSHA256)

	// Offer to set nicknames for the new keys independently
	fmt.Println("\nYou can nickname each key individually via Key Management > Nickname a Key.")
}

// encryptPrivateKey scans for unencrypted .priv files, lets the user select
// one, and encrypts it in place with a passphrase.
func encryptPrivateKey(reader *bufio.Reader) {
	// Find all .priv files that are NOT already age-encrypted
	privFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".priv")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing key files: %v\n", err)
		return
	}

	// Load nicknames for display
	nicks := loadNicknames()

	var openKeys []string
	for _, f := range privFiles {
		encrypted, err := isAgeEncrypted(f)
		if err != nil {
			continue
		}
		if !encrypted {
			openKeys = append(openKeys, f)
		}
	}

	if len(openKeys) == 0 {
		fmt.Println("\nNo unencrypted .priv files found. All private keys are already protected.")
		return
	}

	fmt.Println("\nUnencrypted private key files:")
	for i, f := range openKeys {
		fmt.Printf("  %d) %s [OPEN]\n", i+1, formatKeyName(f, nicks))
	}
	idx := promptSelection(reader, "Select key to encrypt", len(openKeys))
	keyPath := openKeys[idx]

	// Read the plaintext private key from the file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		return
	}

	// Extract the AGE-SECRET-KEY line from the file (skip comment lines)
	secretKey := extractSecretKey(string(keyData))
	if secretKey == "" {
		fmt.Fprintln(os.Stderr, "Could not find AGE-SECRET-KEY in the file.")
		return
	}

	// Prompt for a passphrase with confirmation
	passphrase, err := promptPassphraseConfirm("Enter passphrase")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading passphrase: %v\n", err)
		return
	}

	// Encrypt the private key and overwrite the file in place
	if err := writeEncryptedPrivateKey(keyPath, secretKey, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting private key: %v\n", err)
		return
	}

	fmt.Printf("\nPrivate key encrypted successfully: %s [ENCRYPTED]\n", formatKeyName(keyPath, nicks))
}

// deleteKeyPair presents all key files to the user, confirms deletion,
// and removes both the .pub and .priv files for the selected key name.
// Also cleans up any associated nicknames from keys.json.
func deleteKeyPair(reader *bufio.Reader) {
	pubFiles, _ := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".pub")
	})
	privFiles, _ := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".priv")
	})

	if len(pubFiles) == 0 && len(privFiles) == 0 {
		fmt.Println("\nNo key files found in current directory.")
		return
	}

	// Load nicknames for display and later cleanup
	nicks := loadNicknames()

	// Build a sorted list of unique key base names
	baseNames := make(map[string]bool)
	for _, f := range pubFiles {
		baseNames[strings.TrimSuffix(f, ".pub")] = true
	}
	for _, f := range privFiles {
		baseNames[strings.TrimSuffix(f, ".priv")] = true
	}

	sorted := make([]string, 0, len(baseNames))
	for name := range baseNames {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	// Display the key pairs with their existing files and nicknames
	fmt.Println("\nKey pairs:")
	for i, base := range sorted {
		parts := []string{}
		if fileExists(base + ".pub") {
			parts = append(parts, ".pub")
		}
		if fileExists(base + ".priv") {
			parts = append(parts, ".priv")
		}
		// Show nickname if either the .pub or .priv has one
		label := base
		if nick, ok := nicks[base+".pub"]; ok && nick != "" {
			label = fmt.Sprintf("%s (%s)", nick, base)
		} else if nick, ok := nicks[base+".priv"]; ok && nick != "" {
			label = fmt.Sprintf("%s (%s)", nick, base)
		}
		fmt.Printf("  %d) %s (%s)\n", i+1, label, strings.Join(parts, ", "))
	}

	idx := promptSelection(reader, "Select key pair to delete", len(sorted))
	base := sorted[idx]

	// Ask for confirmation before deleting
	fmt.Printf("\nAre you sure you want to delete '%s'? This cannot be undone. [y/N]: ", base)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Deletion cancelled.")
		return
	}

	// Delete whichever files exist for this key name
	deleted := []string{}
	for _, ext := range []string{".pub", ".priv"} {
		path := base + ext
		if fileExists(path) {
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting %s: %v\n", path, err)
			} else {
				deleted = append(deleted, path)
			}
		}
		// Remove the nickname entry for this file regardless
		delete(nicks, path)
	}

	// Save the updated nicknames (with deleted keys removed)
	if err := saveNicknames(nicks); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating %s: %v\n", nicknameFile, err)
	}

	if len(deleted) > 0 {
		fmt.Printf("Deleted: %s\n", strings.Join(deleted, ", "))
	}
}

// nicknameKey lets the user select any .pub or .priv file and assign or
// update a nickname for it. Each key is nicknamed independently, so a
// .pub and its matching .priv can have different nicknames.
func nicknameKey(reader *bufio.Reader) {
	// Gather all .pub and .priv files in the current directory
	keyFiles, err := listFiles(".", func(name string) bool {
		return strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".priv")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing key files: %v\n", err)
		return
	}
	if len(keyFiles) == 0 {
		fmt.Println("\nNo key files found in current directory.")
		return
	}

	// Load existing nicknames for display
	nicks := loadNicknames()

	fmt.Println("\nKey files:")
	for i, f := range keyFiles {
		if nick, ok := nicks[f]; ok && nick != "" {
			fmt.Printf("  %d) %s (current nickname: %s)\n", i+1, f, nick)
		} else {
			fmt.Printf("  %d) %s (no nickname)\n", i+1, f)
		}
	}

	idx := promptSelection(reader, "Select key to nickname", len(keyFiles))
	selected := keyFiles[idx]

	// Prompt for the new nickname
	fmt.Print("Enter nickname: ")
	nick, _ := reader.ReadString('\n')
	nick = strings.TrimSpace(nick)
	if nick == "" {
		fmt.Fprintln(os.Stderr, "Nickname cannot be empty.")
		return
	}

	// Apply the nickname to the selected file only — each key (.pub / .priv)
	// is nicknamed independently so pairs can have different nicknames.
	nicks[selected] = nick
	fmt.Printf("Nickname '%s' applied to %s.\n", nick, selected)

	// Save the updated nicknames to keys.json
	if err := saveNicknames(nicks); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving nicknames: %v\n", err)
	}
}

// ─── Audit Logging ──────────────────────────────────────────────────────────

// hashFile computes both the MD5 and SHA256 hex-encoded hashes of a file.
func hashFile(path string) (md5Hex, sha256Hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	// Write file contents to both hashers simultaneously
	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), f); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(md5Hash.Sum(nil)), hex.EncodeToString(sha256Hash.Sum(nil)), nil
}

// writeReceiptJSON creates an individual JSON receipt file in the logs/
// directory. The filename is based on the transaction type and timestamp
// e.g. encrypt-2026-04-09-143022.json. The logs directory is created
// automatically if it doesn't exist.
func writeReceiptJSON(txType string, timestamp time.Time, receipt map[string]string) {
	// Ensure the logs directory exists
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create logs directory: %v\n", err)
		return
	}

	// Build the receipt filename from the transaction type and timestamp
	filename := fmt.Sprintf("%s-%s.json", txType, timestamp.Format("2006-01-02-150405"))
	path := filepath.Join(logsDir, filename)

	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not marshal receipt: %v\n", err)
		return
	}

	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write receipt %s: %v\n", path, err)
	}
}

// appendLogLine appends a single human-readable summary line to the running
// age-tool.log file. The file is created if it doesn't exist.
func appendLogLine(line string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open log file: %v\n", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, line)
}

// logEncrypt records an encryption transaction to both the running log file
// and an individual JSON receipt.
func logEncrypt(timestamp time.Time, srcFile, srcMD5, srcSHA256, outFile, outMD5, outSHA256, keyFile, keyNickname string) {
	// Build the JSON receipt
	receipt := map[string]string{
		"transaction":    "encrypt",
		"timestamp":      timestamp.Format(time.RFC3339),
		"source_file":    srcFile,
		"source_md5":     srcMD5,
		"source_sha256":  srcSHA256,
		"output_file":    outFile,
		"output_md5":     outMD5,
		"output_sha256":  outSHA256,
		"public_key":     keyFile,
		"key_nickname":   keyNickname,
	}
	writeReceiptJSON("encrypt", timestamp, receipt)

	// Append a human-readable summary to the running log
	keyLabel := keyFile
	if keyNickname != "" {
		keyLabel = fmt.Sprintf("%s (%s)", keyNickname, keyFile)
	}
	line := fmt.Sprintf("[%s] ENCRYPT: %s -> %s | key: %s | src-sha256: %s | out-sha256: %s",
		timestamp.Format("2006-01-02 15:04:05"), srcFile, outFile, keyLabel, srcSHA256[:16], outSHA256[:16])
	appendLogLine(line)
}

// logDecrypt records a decryption transaction to both the running log file
// and an individual JSON receipt.
func logDecrypt(timestamp time.Time, srcFile, srcMD5, srcSHA256, outFile, outMD5, outSHA256, keyFile, keyNickname string) {
	// Build the JSON receipt
	receipt := map[string]string{
		"transaction":    "decrypt",
		"timestamp":      timestamp.Format(time.RFC3339),
		"source_file":    srcFile,
		"source_md5":     srcMD5,
		"source_sha256":  srcSHA256,
		"output_file":    outFile,
		"output_md5":     outMD5,
		"output_sha256":  outSHA256,
		"private_key":    keyFile,
		"key_nickname":   keyNickname,
	}
	writeReceiptJSON("decrypt", timestamp, receipt)

	// Append a human-readable summary to the running log
	keyLabel := keyFile
	if keyNickname != "" {
		keyLabel = fmt.Sprintf("%s (%s)", keyNickname, keyFile)
	}
	line := fmt.Sprintf("[%s] DECRYPT: %s -> %s | key: %s | src-sha256: %s | out-sha256: %s",
		timestamp.Format("2006-01-02 15:04:05"), srcFile, outFile, keyLabel, srcSHA256[:16], outSHA256[:16])
	appendLogLine(line)
}

// logKeyCreation records a key creation transaction to both the running log
// file and an individual JSON receipt.
func logKeyCreation(timestamp time.Time, keyName, pubFile, pubMD5, pubSHA256, privFile, privMD5, privSHA256 string) {
	// Build the JSON receipt
	receipt := map[string]string{
		"transaction":         "key-creation",
		"timestamp":           timestamp.Format(time.RFC3339),
		"key_pair_name":       keyName,
		"public_key_file":     pubFile,
		"public_key_md5":      pubMD5,
		"public_key_sha256":   pubSHA256,
		"private_key_file":    privFile,
		"private_key_md5":     privMD5,
		"private_key_sha256":  privSHA256,
		"private_key_status":  "passphrase-encrypted",
	}
	writeReceiptJSON("key-creation", timestamp, receipt)

	// Append a human-readable summary to the running log
	line := fmt.Sprintf("[%s] KEY-CREATION: %s | pub: %s (sha256: %s) | priv: %s [ENCRYPTED] (sha256: %s)",
		timestamp.Format("2006-01-02 15:04:05"), keyName, pubFile, pubSHA256[:16], privFile, privSHA256[:16])
	appendLogLine(line)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// extractSecretKey finds the AGE-SECRET-KEY line in a key file string,
// skipping any comment lines that start with #.
func extractSecretKey(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	return ""
}

// writeEncryptedPrivateKey encrypts a secret key string with a passphrase
// using AGE's scrypt recipient and writes it to the given path. The file
// is created with owner-only read/write permissions (0600).
func writeEncryptedPrivateKey(path, secretKey, passphrase string) error {
	// Create the scrypt recipient from the passphrase
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("invalid passphrase: %w", err)
	}

	// Encrypt the secret key into a buffer (never write plaintext to disk)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return fmt.Errorf("encryption setup failed: %w", err)
	}
	if _, err := io.WriteString(w, secretKey+"\n"); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	// Write the encrypted data to disk with restrictive permissions
	return os.WriteFile(path, buf.Bytes(), 0600)
}

// promptPassphraseConfirm prompts the user to enter a passphrase twice
// (with hidden input) and returns it only if both entries match.
func promptPassphraseConfirm(prompt string) (string, error) {
	fmt.Printf("\n%s: ", prompt)
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}

	fmt.Printf("Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}

	if string(pass1) != string(pass2) {
		return "", fmt.Errorf("passphrases do not match")
	}

	if len(pass1) == 0 {
		return "", fmt.Errorf("passphrase cannot be empty")
	}

	return string(pass1), nil
}

// fileExists returns true if the given path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// isAgeEncrypted checks whether a file is age-encrypted by looking for the
// age header line "age-encryption.org/v1" at the start of the file.
// Returns true if the file is age-encrypted (passphrase-protected),
// false if it contains a plaintext key.
func isAgeEncrypted(path string) (bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Read the first line of the file to check for the age header
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		return strings.HasPrefix(line, "age-encryption.org/"), nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, fmt.Errorf("file is empty: %s", path)
}

// decryptKeyToTempFile decrypts a passphrase-protected age key file to a
// temporary hidden file in the current directory. The temp file has a
// randomised name prefixed with a dot to keep it hidden. The path is
// registered in the global cleanup registry so it can be removed on
// signal or abnormal exit.
func decryptKeyToTempFile(encryptedKeyPath, passphrase string) (string, error) {
	// Open the encrypted key file
	in, err := os.Open(filepath.Clean(encryptedKeyPath))
	if err != nil {
		return "", err
	}
	defer in.Close()

	// Create a scrypt identity from the passphrase to decrypt the key file
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid passphrase: %w", err)
	}

	// Decrypt the age-encrypted key file
	r, err := age.Decrypt(in, identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt key (wrong passphrase?): %w", err)
	}

	// Generate a random hex string for the temp filename
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("failed to generate random filename: %w", err)
	}
	tmpPath := filepath.Join(".", ".tmpkey-"+hex.EncodeToString(randBytes))

	// Register the temp file for cleanup before writing it
	registerTempFile(tmpPath)

	// Write the decrypted key to the temp file with restrictive permissions (owner-only read/write)
	out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, r); err != nil {
		return "", err
	}

	return tmpPath, nil
}

// removeTempFile deletes a temporary file and removes it from the global registry.
func removeTempFile(path string) {
	os.Remove(path)
	unregisterTempFile(path)
}

// listFiles returns the names of all non-directory entries in dir that
// pass the provided filter function.
func listFiles(dir string, filter func(string) bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filter(e.Name()) {
			result = append(result, e.Name())
		}
	}
	return result, nil
}

// promptSelection repeatedly prompts the user until they enter a valid
// number between 1 and max. Returns a zero-based index.
func promptSelection(reader *bufio.Reader, prompt string, max int) int {
	for {
		fmt.Printf("%s [1-%d]: ", prompt, max)
		input, _ := reader.ReadString('\n')
		n, err := strconv.Atoi(strings.TrimSpace(input))
		if err == nil && n >= 1 && n <= max {
			return n - 1
		}
		fmt.Println("Invalid selection, try again.")
	}
}

// readRecipient parses the first age recipient (public key) from a file.
func readRecipient(path string) (age.Recipient, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	recipients, err := age.ParseRecipients(f)
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients found in %s", path)
	}
	return recipients[0], nil
}

// readIdentity parses the first age identity (private key) from a file.
func readIdentity(path string) (age.Identity, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found in %s", path)
	}
	return identities[0], nil
}

// encryptFile encrypts the contents of inputPath to outputPath using
// the provided age recipient (public key).
func encryptFile(inputPath, outputPath string, recipient age.Recipient) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, in); err != nil {
		return err
	}

	return w.Close()
}

// decryptFile decrypts the contents of inputPath to outputPath using
// the provided age identity (private key).
func decryptFile(inputPath, outputPath string, identity age.Identity) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	r, err := age.Decrypt(in, identity)
	if err != nil {
		return err
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, r)
	return err
}
