package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
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

	// Main loop: present the menu after each operation until the user quits
	for {
		fmt.Println()
		fmt.Println("1) Encrypt")
		fmt.Println("2) Decrypt")
		fmt.Println("3) Quit")
		fmt.Print("\nChoose [1/2/3/q]: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		// Accept "3", "q", or "Q" as quit commands
		switch strings.ToLower(choice) {
		case "1":
			encrypt(reader)
		case "2":
			decrypt(reader)
		case "3", "q":
			// Exit cleanly when the user chooses to quit
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
		}
	}
}

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
		fmt.Fprintln(os.Stderr, "Please encrypt your key with: age -p -o key.priv key.txt")
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
