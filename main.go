package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
)

func main() {
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
// then decrypts the file. Errors are printed but do not terminate the program,
// allowing the user to return to the main menu.
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

	// Parse the selected private key file into an age identity for decryption
	identity, err := readIdentity(privFiles[keyIdx])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading private key: %v\n", err)
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
