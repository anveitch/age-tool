// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Package core contains age-tool's encryption, key management, nickname and
// audit-log logic, shared by every front end (the CLI, and the GUI in 2.0).
//
// Nothing in this package reads from or writes to the terminal, and nothing
// exits the process. Problems are reported by returning an error or a
// warning string, and the front end decides how to present them.
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Security limits shared by all front ends.
const (
	MaxInputLength   = 255                    // Maximum length for user text inputs (names, nicknames)
	MaxFileSize      = 2 * 1024 * 1024 * 1024 // 2 GB maximum file size for processing
	MinPassphraseLen = 12                     // Minimum passphrase length for key encryption
	MaxPassAttempts  = 3                      // Maximum passphrase attempts before giving up

	// LegacyTmpKeyPrefix is the prefix of temporary decrypted key files
	// written by v1.2.0 and earlier. They are detected and offered for
	// deletion at startup.
	LegacyTmpKeyPrefix = ".tmpkey-"

	// PartialFilePrefix is the prefix of in-progress encrypt/decrypt output,
	// which is renamed into place only once the operation succeeds.
	PartialFilePrefix = ".age-tool-partial-"

	// maxKeyFileSize is the upper bound when reading a decrypted private key
	// into memory.
	maxKeyFileSize = 64 * 1024
)

// ─── Input validation ───────────────────────────────────────────────────────

// SanitiseInput trims whitespace and enforces the maximum input length.
// Returns the cleaned string and an error if it exceeds the limit.
func SanitiseInput(input string) (string, error) {
	s := strings.TrimSpace(input)
	if len(s) > MaxInputLength {
		return "", errorOfKind(ErrInvalidName, fmt.Sprintf("input exceeds maximum length of %d characters", MaxInputLength))
	}
	return s, nil
}

// ValidateFilename checks that a name is safe to use as a simple filename:
//   - not empty
//   - no path traversal sequences ("..")
//   - not an absolute path
//   - no path separators (it must name a file directly inside a directory)
func ValidateFilename(name string) error {
	if name == "" {
		return errorOfKind(ErrInvalidName, "filename cannot be empty")
	}
	if strings.Contains(name, "..") {
		return errorOfKind(ErrInvalidName, "path traversal not allowed")
	}
	if filepath.IsAbs(name) {
		return errorOfKind(ErrInvalidName, "absolute paths not allowed")
	}
	if strings.ContainsAny(name, "/\\") {
		return errorOfKind(ErrInvalidName, "path separators not allowed — files must be in the current directory")
	}
	return nil
}

// CheckFileSize verifies that the file exists and does not exceed the
// maximum allowed size. Returns the file size or an error.
func CheckFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, errorOfKind(ErrFileUnavailable, "cannot access file")
	}
	if info.Size() > MaxFileSize {
		return 0, errorOfKind(ErrFileTooLarge, "file exceeds maximum size of 2 GB")
	}
	return info.Size(), nil
}

// FileExists returns true if the given path exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ─── Passphrases ────────────────────────────────────────────────────────────

// ValidateNewPassphrase enforces the rules for a passphrase that will
// protect a private key. Currently that is the minimum length.
func ValidateNewPassphrase(pass string) error {
	if len(pass) < MinPassphraseLen {
		return errorOfKind(ErrPassphraseTooShort, fmt.Sprintf("passphrase must be at least %d characters", MinPassphraseLen))
	}
	return nil
}

// PassphraseWarning checks for simple weak patterns: all the same
// character, all digits, or a common sequence. Returns a warning message,
// or an empty string if none apply. Weak passphrases are allowed; the
// front end shows the warning and lets the user decide.
func PassphraseWarning(pass string) string {
	if len(pass) == 0 {
		return ""
	}

	// Check if all characters are the same. Compare whole runes (not bytes)
	// so multi-byte UTF-8 characters are handled correctly.
	runes := []rune(pass)
	allSame := true
	for _, c := range runes[1:] {
		if c != runes[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return "passphrase is all the same character"
	}

	// Check if all digits
	allDigits := true
	for _, c := range pass {
		if !unicode.IsDigit(c) {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "passphrase contains only digits"
	}

	// Check for simple ascending sequences and common words
	lower := strings.ToLower(pass)
	sequences := []string{"abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "password", "passphrase"}
	for _, seq := range sequences {
		if strings.Contains(seq, lower) || lower == seq {
			return "passphrase matches a common pattern"
		}
	}

	return ""
}

// PassphraseStrength rates a new passphrase for a strength meter.
type PassphraseStrength int

// Passphrase strength levels, weakest first.
const (
	StrengthTooShort PassphraseStrength = iota // Below MinPassphraseLen: not allowed
	StrengthWeak                               // Allowed, but matches a weak pattern (see PassphraseWarning)
	StrengthFair                               // Allowed, but short or made of few kinds of character
	StrengthStrong                             // Long, or mixes several kinds of character
)

// strongPassphraseLen is the length at which a passphrase counts as strong
// whatever characters it uses: four or five ordinary words reach it.
const strongPassphraseLen = 20

// RatePassphrase rates a passphrase that will protect a private key. Only
// StrengthTooShort is refused (by ValidateNewPassphrase); the other levels
// help the user choose. This is a simple guide, not an entropy estimate.
func RatePassphrase(pass string) PassphraseStrength {
	if len(pass) < MinPassphraseLen {
		return StrengthTooShort
	}
	if PassphraseWarning(pass) != "" {
		return StrengthWeak
	}
	if len([]rune(pass)) >= strongPassphraseLen {
		return StrengthStrong
	}

	// Count the kinds of character used: lower case, upper case, digits,
	// and anything else (spaces, punctuation, symbols)
	var lower, upper, digit, other bool
	for _, c := range pass {
		switch {
		case unicode.IsLower(c):
			lower = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsDigit(c):
			digit = true
		default:
			other = true
		}
	}
	kinds := 0
	for _, used := range []bool{lower, upper, digit, other} {
		if used {
			kinds++
		}
	}
	if kinds >= 3 {
		return StrengthStrong
	}
	return StrengthFair
}

// ClearBytes overwrites a byte slice with zeros to remove sensitive data
// from memory. This is a best-effort measure; the Go runtime may have
// already copied the data elsewhere.
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
