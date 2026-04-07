package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
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

	"filippo.io/age"
	"golang.org/x/term"
)

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
			fmt.Printf("   - %s\n", k)
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
	file := promptSelection(reader, "Select file to encrypt", len(files))
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

	fmt.Println("\nPublic key files:")
	for i, f := range pubFiles {
		fmt.Printf("  %d) %s\n", i+1, f)
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
	fileIdx := promptSelection(reader, "Select file to decrypt", len(ageFiles))
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

	fmt.Println("\nPrivate key files:")
	for i, f := range privFiles {
		fmt.Printf("  %d) %s\n", i+1, f)
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
		fmt.Println("5) Back")
		fmt.Print("\nChoose [1-5]: ")

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
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

// listKeys scans the current directory for .pub and .priv files and displays
// them as paired entries where possible. Each .priv file is labelled with
// [ENCRYPTED] or [OPEN] to indicate its protection status.
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

		// Check for the public key file
		if fileExists(base + ".pub") {
			fmt.Printf("    Public:  %s.pub\n", base)
		} else {
			fmt.Printf("    Public:  (not found)\n")
		}

		// Check for the private key file and its encryption status
		privPath := base + ".priv"
		if fileExists(privPath) {
			encrypted, err := isAgeEncrypted(privPath)
			if err != nil {
				fmt.Printf("    Private: %s [ERROR: %v]\n", privPath, err)
			} else if encrypted {
				fmt.Printf("    Private: %s [ENCRYPTED]\n", privPath)
			} else {
				fmt.Printf("    Private: %s [OPEN]\n", privPath)
			}
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
		fmt.Printf("  %d) %s [OPEN]\n", i+1, f)
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

	fmt.Printf("\nPrivate key encrypted successfully: %s [ENCRYPTED]\n", keyPath)
}

// deleteKeyPair presents all key files to the user, confirms deletion,
// and removes both the .pub and .priv files for the selected key name.
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

	// Display the key pairs with their existing files
	fmt.Println("\nKey pairs:")
	for i, base := range sorted {
		parts := []string{}
		if fileExists(base + ".pub") {
			parts = append(parts, ".pub")
		}
		if fileExists(base + ".priv") {
			parts = append(parts, ".priv")
		}
		fmt.Printf("  %d) %s (%s)\n", i+1, base, strings.Join(parts, ", "))
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
	}

	if len(deleted) > 0 {
		fmt.Printf("Deleted: %s\n", strings.Join(deleted, ", "))
	}
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
