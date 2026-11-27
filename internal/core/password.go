// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"bufio"
	"crypto/rand"
	_ "embed" // for the suggested-password word list
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"filippo.io/age"
)

// ─── How a file was locked ──────────────────────────────────────────────────

// LockMethod says how an age file was encrypted, which decides what is
// needed to decrypt it.
type LockMethod int

// The ways an age file can be locked.
const (
	LockedWithKey      LockMethod = iota // For one or more public keys: needs a private key
	LockedWithPassword                   // With a password (age's scrypt recipient)
)

// ErrNotAgeFile is returned when a file doesn't start with the age header.
var ErrNotAgeFile = errors.New("not an age encrypted file")

// maxHeaderLines bounds how much of a file FileLockMethod reads. A real
// header has a few lines per recipient; this allows hundreds.
const maxHeaderLines = 2048

// FileLockMethod reads the header of the age file at path, without
// decrypting anything, and reports whether it was locked with a password
// or with keys. age writes a password-locked file with exactly one
// "-> scrypt" stanza, and never mixes it with key stanzas.
func FileLockMethod(path string) (LockMethod, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, errorOfKind(ErrFileUnavailable, "cannot open file")
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// The first line must be the age version line
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "age-encryption.org/") {
		return 0, ErrNotAgeFile
	}
	// Stanzas start "-> <type> ..."; the header ends with "--- <mac>"
	for range maxHeaderLines {
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "---") {
			return LockedWithKey, nil
		}
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "->" && fields[1] == "scrypt" {
			return LockedWithPassword, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, errorOfKind(ErrFileUnavailable, "cannot read file")
	}
	// No end of header: truncated, or not really an age file
	return 0, ErrNotAgeFile
}

// ─── Password rules ─────────────────────────────────────────────────────────

// MinPasswordLen is the shortest password allowed for encrypting a file.
// Settings can raise it but never lower it.
const MinPasswordLen = 8

// PasswordRules are the requirements for a password that encrypts files.
// They are set in the settings file ("password_rules") and can only be
// made stricter than DefaultPasswordRules: see Effective.
type PasswordRules struct {
	MinLength      int  `json:"min_length"`      // Minimum length in characters
	RequireNumber  bool `json:"require_number"`  // Must contain a digit
	RequireSpecial bool `json:"require_special"` // Must contain a special character (punctuation or symbol)
}

// DefaultPasswordRules is the floor: at least 8 characters, with a number
// and a special character.
var DefaultPasswordRules = PasswordRules{MinLength: MinPasswordLen, RequireNumber: true, RequireSpecial: true}

// Effective returns the rules actually enforced: these rules, but never
// weaker than DefaultPasswordRules. A typo or a hand-edited settings file
// can make the rules stricter, but can't switch them off.
func (r PasswordRules) Effective() PasswordRules {
	r.MinLength = max(r.MinLength, DefaultPasswordRules.MinLength)
	r.RequireNumber = r.RequireNumber || DefaultPasswordRules.RequireNumber
	r.RequireSpecial = r.RequireSpecial || DefaultPasswordRules.RequireSpecial
	return r
}

// Describe explains the rules in a sentence, for showing beside a
// password field, e.g. "At least 8 characters, including a number and a
// special character (such as ! or #)."
func (r PasswordRules) Describe() string {
	r = r.Effective()
	var needs []string
	if r.RequireNumber {
		needs = append(needs, "a number")
	}
	if r.RequireSpecial {
		needs = append(needs, "a special character (such as ! or #)")
	}
	text := fmt.Sprintf("At least %d characters", r.MinLength)
	if len(needs) > 0 {
		text += ", including " + strings.Join(needs, " and ")
	}
	return text + "."
}

// ErrPasswordTooWeak is the kind of error returned when a password breaks
// the rules. Its message says what is missing.
var ErrPasswordTooWeak = errors.New("password does not meet the rules")

// isSpecial reports whether c counts as a special character: punctuation
// or a symbol. Letters, digits and spaces don't count.
func isSpecial(c rune) bool {
	return unicode.IsPunct(c) || unicode.IsSymbol(c)
}

// commonPasswordWords are words that make a password easy to guess even
// with numbers and symbols added (e.g. "Summer26!"). A password whose
// letters are only one of these is refused. This is a short list of the
// most common choices, not a full cracking dictionary.
var commonPasswordWords = []string{
	"password", "passw", "passwd", "passphrase", "qwerty", "qwertyuiop", "asdf", "asdfgh", "zxcvbn",
	"letmein", "welcome", "admin", "administrator", "login", "iloveyou", "monkey", "dragon",
	"sunshine", "princess", "football", "baseball", "soccer", "master", "shadow", "secret",
	"summer", "winter", "spring", "autumn", "january", "february", "march", "april", "june",
	"july", "august", "september", "october", "november", "december", "abc", "abcd", "abcdef",
	"test", "guest", "user", "changeme", "default", "trustno", "hello", "freedom", "whatever",
	"qazwsx", "starwars", "superman", "batman", "computer", "internet", "michael", "jennifer",
}

// CheckPassword checks a new file password against the rules. It returns
// nil if the password is allowed, or an ErrPasswordTooWeak-kind error
// saying what to change.
func (r PasswordRules) CheckPassword(pass string) error {
	r = r.Effective()
	var problems []string
	if n := len([]rune(pass)); n < r.MinLength {
		problems = append(problems, fmt.Sprintf("use at least %d characters", r.MinLength))
	}
	hasDigit, hasSpecial := false, false
	for _, c := range pass {
		hasDigit = hasDigit || unicode.IsDigit(c)
		hasSpecial = hasSpecial || isSpecial(c)
	}
	if r.RequireNumber && !hasDigit {
		problems = append(problems, "add a number")
	}
	if r.RequireSpecial && !hasSpecial {
		problems = append(problems, "add a special character such as ! or #")
	}
	if len(problems) > 0 {
		return errorOfKind(ErrPasswordTooWeak, "password must "+joinProblems(problems))
	}
	if reason := weakPasswordReason(pass); reason != "" {
		return errorOfKind(ErrPasswordTooWeak, reason)
	}
	return nil
}

// joinProblems joins rule problems into one phrase: "a, b and c".
func joinProblems(p []string) string {
	if len(p) == 1 {
		return p[0]
	}
	return strings.Join(p[:len(p)-1], ", ") + " and " + p[len(p)-1]
}

// lookAlikes undoes the usual symbol-for-letter swaps ("p@ssw0rd"). It is
// applied only between the first and last letter, so numbers added at the
// end ("2026") stay numbers. "1" and "7" are left out because they are too
// ambiguous (l or i, t).
var lookAlikes = strings.NewReplacer("@", "a", "$", "s", "0", "o", "3", "e", "4", "a")

// onlyLetters returns the letters of s, lower case.
func onlyLetters(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if unicode.IsLetter(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// weakPasswordReason spots passwords that meet the rules but are still
// easy to guess. Returns a message, or "" if none apply.
func weakPasswordReason(pass string) string {
	// The general weak patterns shared with key passphrases
	if w := PassphraseWarning(pass); w != "" {
		return "password is too easy to guess: " + strings.TrimPrefix(w, "passphrase ")
	}
	// Two views of the word in the password, lower case and letters only:
	//   - the letters as typed: "Summer26!" -> "summer"
	//   - the part from the first letter to the last, with look-alike
	//     swaps undone: "P@ssw0rd1" -> "password", "Summ3r2026#" -> "summer"
	plain := onlyLetters(pass)
	if plain == "" {
		return "password is too easy to guess: add some letters"
	}
	inner := strings.TrimFunc(pass, func(c rune) bool { return !unicode.IsLetter(c) })
	swapped := onlyLetters(lookAlikes.Replace(inner))

	for _, word := range []string{plain, swapped} {
		if slices.Contains(commonPasswordWords, word) {
			return "password is too easy to guess: it is a common word with numbers or symbols added"
		}
		// Letters that are just a run along the alphabet or a keyboard row
		for _, run := range []string{"abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"} {
			if len(word) >= 3 && strings.Contains(run, word) {
				return "password is too easy to guess: its letters are a simple sequence"
			}
		}
	}
	return ""
}

// ─── Suggested passwords ────────────────────────────────────────────────────

//go:embed wordlist/eff_short.txt
var effShortWordList string

// suggestionWords returns the EFF short word list, skipping its comment
// header.
func suggestionWords() []string {
	var words []string
	for line := range strings.SplitSeq(effShortWordList, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words
}

// suggestionSpecials are the special characters used in suggested
// passwords: easy to type on any keyboard layout and to read aloud.
const suggestionSpecials = "!#%&*+=?@"

// SuggestPassword makes a random, memorable password that meets the rules,
// e.g. "kettle-orange-piano-march-47!": at least four words from the EFF
// short word list, a two-digit number and a special character. About 51
// bits of randomness with four words; more words are added if the rules
// need a longer password. Uses the operating system's secure random source.
func SuggestPassword(rules PasswordRules) (string, error) {
	rules = rules.Effective()
	words := suggestionWords()
	pick := func(n int) (int, error) {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return 0, err
		}
		return int(v.Int64()), nil
	}

	var parts []string
	for {
		i, err := pick(len(words))
		if err != nil {
			return "", err
		}
		parts = append(parts, words[i])
		if len(parts) < 4 {
			continue
		}
		// Words, then "-NN" and a special character: 4 more characters
		if len(strings.Join(parts, "-"))+4 >= rules.MinLength {
			break
		}
	}
	num, err := pick(90)
	if err != nil {
		return "", err
	}
	sym, err := pick(len(suggestionSpecials))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%d%c", strings.Join(parts, "-"), num+10, suggestionSpecials[sym]), nil
}

// ─── Encrypting and decrypting with a password ──────────────────────────────

// ErrWrongPassword is returned when a password doesn't open a file.
var ErrWrongPassword = errors.New("incorrect password")

// EncryptFileWithPassword encrypts inputPath to outputPath with a password,
// as "age -p" does (scrypt, age's default work factor). The password must
// already have passed CheckPassword. Output is atomic and owner-only, as
// for EncryptFile.
func EncryptFileWithPassword(inputPath, outputPath, password string) error {
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	return EncryptFile(inputPath, outputPath, recipient)
}

// DecryptFileWithPassword decrypts a password-locked file. Returns
// ErrWrongPassword if the password doesn't open it; nothing is written in
// that case. Output is atomic and owner-only, as for DecryptFile.
func DecryptFileWithPassword(inputPath, outputPath, password string) error {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return ErrWrongPassword
	}
	err = DecryptFile(inputPath, outputPath, identity)
	// age reports a password that doesn't match as NoIdentityMatchError
	if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
		return ErrWrongPassword
	}
	return err
}
