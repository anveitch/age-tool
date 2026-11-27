// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// maxPubKeyFileSize bounds how much is read when importing a public key
// file; real ones are a single short line.
const maxPubKeyFileSize = 16 * 1024

// ParsePublicKey checks that text contains exactly one age public key and
// returns it in canonical form. Blank lines and "#" comment lines (as
// written by age-keygen) are ignored. Private keys are refused outright so
// a secret can't be imported as a contact by mistake.
func ParsePublicKey(text string) (string, error) {
	if ContainsSecretKey(text) {
		return "", errorOfKind(ErrIsPrivateKey, "this is a private key, not a public key — never share or import it as a contact")
	}

	var keys []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	if len(keys) == 0 {
		return "", errorOfKind(ErrNotPublicKey, "no public key found")
	}
	if len(keys) > 1 {
		return "", errorOfKind(ErrNotPublicKey, fmt.Sprintf("expected one public key, found %d lines", len(keys)))
	}

	recipients, err := age.ParseRecipients(strings.NewReader(keys[0]))
	if err != nil || len(recipients) != 1 {
		return "", errorOfKind(ErrNotPublicKey, "not a valid age public key (it should start with \"age1\")")
	}
	return keys[0], nil
}

// ContainsSecretKey reports whether text contains an age private key, so a
// front end can avoid echoing it back (e.g. when an import is refused).
func ContainsSecretKey(text string) bool {
	return strings.Contains(strings.ToUpper(text), "AGE-SECRET-KEY-")
}

// ReadPublicKeyString reads a .pub file and returns its age public key,
// ready to show or share.
func ReadPublicKeyString(path string) (string, error) {
	data, err := readLimited(path, maxPubKeyFileSize)
	if err != nil {
		return "", errorOfKind(ErrFileUnavailable, fmt.Sprintf("could not read %s", filepath.Base(path)))
	}
	return ParsePublicKey(string(data))
}

// ImportPublicKey saves someone's public key (text from a file or pasted)
// into dir as name.pub, so files can be encrypted for them. The name must
// be a safe filename not already used by a key. Returns the new file's path.
func ImportPublicKey(dir, name, text string) (string, error) {
	if err := ValidateFilename(name); err != nil {
		return "", err
	}
	key, err := ParsePublicKey(text)
	if err != nil {
		return "", err
	}
	if KeyPairExists(dir, name) {
		return "", ErrKeyExists
	}
	path := filepath.Join(dir, name+PubExt)
	if err := writeNewFile(path, []byte(key+"\n")); err != nil {
		return "", fmt.Errorf("could not save public key")
	}
	return path, nil
}

// ExportPublicKey writes a copy of the public key in pubPath to destPath,
// for sharing. It refuses to overwrite an existing file. The copy is
// readable by others (0644) because public keys are meant to be shared.
func ExportPublicKey(pubPath, destPath string) error {
	key, err := ReadPublicKeyString(pubPath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(destPath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644) // #nosec G302 -- public keys are meant to be shared
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists", filepath.Base(destPath))
		}
		return fmt.Errorf("could not write %s", filepath.Base(destPath))
	}
	if _, err := fmt.Fprintln(f, key); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not write %s", filepath.Base(destPath))
	}
	return f.Close()
}

// readLimited reads at most limit bytes of a file, failing if it is larger.
func readLimited(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file too large")
	}
	return os.ReadFile(filepath.Clean(path))
}
