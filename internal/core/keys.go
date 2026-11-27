// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
)

// Key file extensions.
const (
	PubExt  = ".pub"
	PrivExt = ".priv"
)

// ErrWrongPassphrase is returned by UnlockIdentity when the passphrase does
// not unlock the key, so the caller can offer another attempt. Any other
// error means the key file itself is unusable and retrying won't help.
var ErrWrongPassphrase = errors.New("incorrect passphrase")

// ErrKeyExists is returned by GenerateKeyPair when a key pair with the
// requested name already exists.
var ErrKeyExists = errors.New("key files already exist")

// ─── Listing keys ───────────────────────────────────────────────────────────

// ListFiles returns the names (not paths) of all non-directory entries in
// dir that pass the provided filter function, in directory order.
func ListFiles(dir string, filter func(name string) bool) ([]string, error) {
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

// ListPublicKeys returns the names of all .pub files in dir.
func ListPublicKeys(dir string) ([]string, error) {
	return ListFiles(dir, func(name string) bool { return strings.HasSuffix(name, PubExt) })
}

// ListPrivateKeys returns the names of all .priv files in dir.
func ListPrivateKeys(dir string) ([]string, error) {
	return ListFiles(dir, func(name string) bool { return strings.HasSuffix(name, PrivExt) })
}

// ListKeyFiles returns the names of all .pub and .priv files in dir.
func ListKeyFiles(dir string) ([]string, error) {
	return ListFiles(dir, func(name string) bool {
		return strings.HasSuffix(name, PubExt) || strings.HasSuffix(name, PrivExt)
	})
}

// KeyPair describes the key files in a directory that share a base name.
// Either file may be missing; the corresponding field is then empty.
type KeyPair struct {
	Base     string // Shared base name, e.g. "work" for work.pub / work.priv
	PubFile  string // Public key filename, or "" if it doesn't exist
	PrivFile string // Private key filename, or "" if it doesn't exist
}

// ListKeyPairs groups the .pub and .priv files in dir by base name and
// returns them sorted by base name.
func ListKeyPairs(dir string) ([]KeyPair, error) {
	pubFiles, err := ListPublicKeys(dir)
	if err != nil {
		return nil, err
	}
	privFiles, err := ListPrivateKeys(dir)
	if err != nil {
		return nil, err
	}

	// Collect pairs by base name
	pairs := make(map[string]*KeyPair)
	get := func(base string) *KeyPair {
		if pairs[base] == nil {
			pairs[base] = &KeyPair{Base: base}
		}
		return pairs[base]
	}
	for _, f := range pubFiles {
		get(strings.TrimSuffix(f, PubExt)).PubFile = f
	}
	for _, f := range privFiles {
		get(strings.TrimSuffix(f, PrivExt)).PrivFile = f
	}

	// Sort by base name for a consistent display order
	result := make([]KeyPair, 0, len(pairs))
	for _, p := range pairs {
		result = append(result, *p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Base < result[j].Base })
	return result, nil
}

// OpenPrivateKeys returns the names of .priv files in dir that are NOT
// passphrase-protected. Files that can't be read are skipped.
func OpenPrivateKeys(dir string) ([]string, error) {
	privFiles, err := ListPrivateKeys(dir)
	if err != nil {
		return nil, err
	}
	var open []string
	for _, f := range privFiles {
		encrypted, err := IsAgeEncrypted(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		if !encrypted {
			open = append(open, f)
		}
	}
	return open, nil
}

// PermissiveKeyFiles returns the names of .priv files in dir whose
// permissions allow any group or world access.
func PermissiveKeyFiles(dir string) ([]string, error) {
	privFiles, err := ListPrivateKeys(dir)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, f := range privFiles {
		if CheckKeyPermissions(filepath.Join(dir, f)) != "" {
			bad = append(bad, f)
		}
	}
	return bad, nil
}

// ─── Key file checks ────────────────────────────────────────────────────────

// IsAgeEncrypted checks whether a file is age-encrypted by looking for the
// age header line "age-encryption.org/v1" at the start of the file.
func IsAgeEncrypted(path string) (bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return strings.HasPrefix(scanner.Text(), "age-encryption.org/"), nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, fmt.Errorf("file is empty")
}

// ValidatePubKeyFile checks that a .pub file contains a valid AGE public
// key by attempting to parse it as a recipient.
func ValidatePubKeyFile(path string) error {
	_, err := ReadRecipient(path)
	return err
}

// ValidatePrivKeyFile checks that a .priv file is a valid AGE-encrypted
// (passphrase-protected) private key by looking for the age header.
func ValidatePrivKeyFile(path string) error {
	encrypted, err := IsAgeEncrypted(path)
	if err != nil {
		return errorOfKind(ErrFileUnavailable, "cannot read private key file")
	}
	if !encrypted {
		return errorOfKind(ErrKeyNotProtected, "private key is not passphrase-encrypted")
	}
	return nil
}

// CheckKeyPermissions checks whether a key file has overly permissive
// permissions (any group or world access). Returns a warning message or an
// empty string. Only meaningful on Unix-like systems.
func CheckKeyPermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return fmt.Sprintf("file has overly permissive permissions (%04o)", mode)
	}
	return ""
}

// FixKeyPermissions restricts a key file to owner-only read/write (0600).
func FixKeyPermissions(path string) error {
	return os.Chmod(path, 0600)
}

// ─── Reading and unlocking keys ─────────────────────────────────────────────

// ReadRecipient parses the first age recipient (public key) from a file.
func ReadRecipient(path string) (age.Recipient, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, errorOfKind(ErrFileUnavailable, "cannot open public key file")
	}
	defer f.Close()

	recipients, err := age.ParseRecipients(f)
	if err != nil {
		return nil, errorOfKind(ErrNotPublicKey, "file does not contain a valid AGE public key")
	}
	if len(recipients) == 0 {
		return nil, errorOfKind(ErrNotPublicKey, "no AGE public key found in file")
	}
	return recipients[0], nil
}

// UnlockIdentity unlocks a passphrase-protected age private key file
// entirely in memory and returns the parsed identity. The plaintext key is
// never written to disk, and the in-memory copy of the key text is zeroed
// once parsed (best effort; the Go runtime may hold other copies).
// Returns ErrWrongPassphrase if the passphrase does not unlock the key.
func UnlockIdentity(encryptedKeyPath, passphrase string) (age.Identity, error) {
	in, err := os.Open(filepath.Clean(encryptedKeyPath))
	if err != nil {
		return nil, errorOfKind(ErrFileUnavailable, "cannot open key file")
	}
	defer in.Close()

	scryptIdentity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid passphrase")
	}

	// age.Decrypt reads the header and checks the passphrase up front, so a
	// failure here means the passphrase was wrong (or the header is corrupt)
	r, err := age.Decrypt(in, scryptIdentity)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	// Read the decrypted key text into memory, capped at a sane size
	keyData, err := io.ReadAll(io.LimitReader(r, maxKeyFileSize))
	// Zero the plaintext key bytes when this function returns
	defer ClearBytes(keyData)
	if err != nil {
		return nil, fmt.Errorf("could not read decrypted private key")
	}

	// Parse the AGE-SECRET-KEY line into an identity
	identities, err := age.ParseIdentities(bytes.NewReader(keyData))
	if err != nil || len(identities) == 0 {
		return nil, fmt.Errorf("decrypted file does not contain a valid AGE private key")
	}
	return identities[0], nil
}

// ExtractSecretKey finds the AGE-SECRET-KEY line in a key file's text,
// skipping comment lines. Returns "" if there is none.
func ExtractSecretKey(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	return ""
}

// ReadOpenSecretKey reads an unprotected (plaintext) private key file and
// returns its AGE-SECRET-KEY line, ready to be passphrase-protected with
// WritePassphraseProtectedKey.
func ReadOpenSecretKey(path string) (string, error) {
	keyData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("could not read key file")
	}
	defer ClearBytes(keyData)

	secretKey := ExtractSecretKey(string(keyData))
	if secretKey == "" {
		return "", fmt.Errorf("could not find AGE-SECRET-KEY in the file")
	}
	return secretKey, nil
}

// ─── Writing keys ───────────────────────────────────────────────────────────

// WritePassphraseProtectedKey encrypts a secret key string with a
// passphrase using AGE's scrypt recipient and writes it to path, replacing
// any existing file. The file is owner-only (0600).
func WritePassphraseProtectedKey(path, secretKey, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("encryption setup failed")
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return fmt.Errorf("encryption setup failed")
	}
	if _, err := io.WriteString(w, secretKey+"\n"); err != nil {
		return fmt.Errorf("encryption failed")
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("encryption failed")
	}

	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		return err
	}
	// os.WriteFile only sets permissions when creating the file, so tighten
	// an existing file being protected in place
	return os.Chmod(path, 0600)
}

// KeyPairExists reports whether name.pub or name.priv already exists in dir.
func KeyPairExists(dir, name string) bool {
	return FileExists(filepath.Join(dir, name+PubExt)) || FileExists(filepath.Join(dir, name+PrivExt))
}

// GenerateKeyPair creates a new X25519 key pair in dir as name.pub and
// name.priv. The private key is encrypted with the passphrase in memory
// and written directly to disk — unencrypted key material is never written
// to a file. Both files are owner-only (0600). If writing the private key
// fails, the public key is removed so a half-created pair isn't left behind.
// Returns the paths of the two files.
func GenerateKeyPair(dir, name, passphrase string) (pubPath, privPath string, err error) {
	if err := ValidateFilename(name); err != nil {
		return "", "", err
	}
	if err := ValidateNewPassphrase(passphrase); err != nil {
		return "", "", err
	}
	if KeyPairExists(dir, name) {
		return "", "", ErrKeyExists
	}
	pubPath = filepath.Join(dir, name+PubExt)
	privPath = filepath.Join(dir, name+PrivExt)

	// Generate the key pair in memory
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("could not generate key pair")
	}

	// Write the public key. Public keys are not secret, but it is written
	// owner-only (0600) like every other output file; copy it to share it.
	// O_EXCL ensures an existing file is never overwritten.
	if err := writeNewFile(pubPath, []byte(identity.Recipient().String()+"\n")); err != nil {
		return "", "", fmt.Errorf("could not write public key")
	}

	// Encrypt the private key with the passphrase and write it
	if err := WritePassphraseProtectedKey(privPath, identity.String(), passphrase); err != nil {
		if rmErr := os.Remove(pubPath); rmErr != nil {
			return "", "", fmt.Errorf("could not write encrypted private key, and the incomplete public key %s could not be removed; please delete it manually", pubPath)
		}
		return "", "", fmt.Errorf("could not write encrypted private key")
	}

	return pubPath, privPath, nil
}

// writeNewFile creates path with owner-only permissions and writes data,
// failing if the file already exists.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ─── Deleting keys ──────────────────────────────────────────────────────────

// DeleteKeyPair removes base.pub and base.priv from dir (whichever exist)
// and removes both files' entries from nicks. The caller saves nicks.
// A failure to delete one file doesn't stop the other being deleted.
// Returns the names of the files deleted and of any that couldn't be.
func DeleteKeyPair(dir, base string, nicks Nicknames) (deleted, failed []string) {
	for _, ext := range []string{PubExt, PrivExt} {
		name := base + ext
		path := filepath.Join(dir, name)
		if FileExists(path) {
			if err := os.Remove(path); err != nil {
				failed = append(failed, name)
			} else {
				deleted = append(deleted, name)
			}
		}
		// Remove the nickname entry for this file regardless
		delete(nicks, name)
	}
	return deleted, failed
}
