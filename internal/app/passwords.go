// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package app

// Encrypting and decrypting with a password, and saved password records,
// for front ends. The rules and the cryptography are in internal/core.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"age-tool/internal/core"
)

// Errors for password workflows (see also the core errors they wrap).
var (
	// ErrPasswordMismatch: the password and its confirmation differ.
	ErrPasswordMismatch = errors.New("passwords do not match")
	// ErrNotPasswordFile: a password was offered for a file locked with a key.
	ErrNotPasswordFile = errors.New("file was not encrypted with a password")
	// ErrTooManyPasswordAttempts: the last allowed password was wrong.
	ErrTooManyPasswordAttempts = errors.New("too many incorrect password attempts")
)

// ─── Rules and suggestions ──────────────────────────────────────────────────

// PasswordRules returns the rules for new file passwords: the settings
// file's rules, never weaker than the defaults.
func (s *Service) PasswordRules() core.PasswordRules {
	return core.LoadSettings(s.Locations.SettingsFile()).PasswordRules()
}

// SuggestPassword returns a random, memorable password that meets the
// rules.
func (s *Service) SuggestPassword() (string, error) {
	return core.SuggestPassword(s.PasswordRules())
}

// CheckNewPassword checks a new file password and its confirmation:
// ErrPasswordMismatch if they differ, or a core.ErrPasswordTooWeak-kind
// error (whose text says what to change) if it breaks the rules.
func (s *Service) CheckNewPassword(password, confirm string) error {
	if password != confirm {
		return ErrPasswordMismatch
	}
	return s.PasswordRules().CheckPassword(password)
}

// ─── Encrypt ────────────────────────────────────────────────────────────────

// EncryptWithPassword encrypts input with password (already checked with
// CheckNewPassword), saving input.age beside it. As for Encrypt, an
// existing output returns ErrOutputExists unless overwrite is true. The
// output is atomic and owner-only, and the transaction is logged without
// the password.
func (s *Service) EncryptWithPassword(input, password string, overwrite bool) (Result, error) {
	input, err := filepath.Abs(input)
	if err != nil {
		return Result{}, core.ErrFileUnavailable
	}
	if strings.HasSuffix(input, core.AgeExt) {
		return Result{}, ErrAlreadyEncrypted
	}
	if err := checkInputFile(input); err != nil {
		return Result{}, err
	}
	if err := s.PasswordRules().CheckPassword(password); err != nil {
		return Result{}, err
	}
	output := EncryptOutput(input)
	if err := checkOutput(output, overwrite); err != nil {
		return Result{}, err
	}
	if err := core.EncryptFileWithPassword(input, output, password); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}
	warnings := s.auditFor(filepath.Dir(output)).RecordPasswordEncrypt(s.Now(), input, output)
	return Result{Output: output, Warnings: warnings}, nil
}

// ─── Decrypt ────────────────────────────────────────────────────────────────

// LockMethod reports whether the .age file input was encrypted with a
// password or for keys, from its header, without decrypting it.
func (s *Service) LockMethod(input string) (core.LockMethod, error) {
	m, err := core.FileLockMethod(input)
	if errors.Is(err, core.ErrNotAgeFile) {
		return 0, ErrNotAgeFile
	}
	return m, err
}

// HasPasswordRecord reports whether a saved password record covers the
// encrypted file input (matched by content, so moved files count).
func (s *Service) HasPasswordRecord(input string) bool {
	recs, err := core.RecordsForFile(s.Locations.PasswordsDir, input)
	return err == nil && len(recs) > 0
}

// PasswordDecryption is one attempt to decrypt a password-locked file,
// allowing core.MaxPassAttempts passwords, like Decryption does for keys.
// It holds no secrets.
type PasswordDecryption struct {
	svc       *Service
	input     string // Absolute path of the .age file
	output    string // Where the decrypted file will be written
	overwrite bool   // The user confirmed replacing an existing output file
	attempts  int    // Passwords tried so far
	done      bool   // Finished, successfully or after too many attempts
}

// StartPasswordDecrypt prepares to decrypt input, a password-locked .age
// file. It fails straight away if the file isn't usable or isn't a
// password file (ErrNotPasswordFile), or if the output exists and
// overwrite is false (ErrOutputExists).
func (s *Service) StartPasswordDecrypt(input string, overwrite bool) (*PasswordDecryption, error) {
	input, err := filepath.Abs(input)
	if err != nil {
		return nil, core.ErrFileUnavailable
	}
	if !strings.HasSuffix(input, core.AgeExt) || filepath.Base(input) == core.AgeExt {
		return nil, ErrNotAgeFile
	}
	if err := checkInputFile(input); err != nil {
		return nil, err
	}
	method, err := s.LockMethod(input)
	if err != nil {
		return nil, err
	}
	if method != core.LockedWithPassword {
		return nil, ErrNotPasswordFile
	}
	output := DecryptOutput(input)
	if err := checkOutput(output, overwrite); err != nil {
		return nil, err
	}
	return &PasswordDecryption{svc: s, input: input, output: output, overwrite: overwrite}, nil
}

// Output returns where the decrypted file will be written.
func (d *PasswordDecryption) Output() string { return d.output }

// AttemptsLeft returns how many more passwords may be tried.
func (d *PasswordDecryption) AttemptsLeft() int {
	if d.done {
		return 0
	}
	return core.MaxPassAttempts - d.attempts
}

// Try decrypts the file with password (zeroed before Try returns). A wrong
// password returns core.ErrWrongPassword while attempts remain, and
// ErrTooManyPasswordAttempts on the last one. Any other outcome finishes
// the PasswordDecryption; calling Try again returns ErrFinished.
func (d *PasswordDecryption) Try(password []byte) (Result, error) {
	defer core.ClearBytes(password)
	if d.done {
		return Result{}, ErrFinished
	}
	d.attempts++

	// Re-check the output in case a file appeared while the user typed
	if err := checkOutput(d.output, d.overwrite); err != nil {
		d.done = true
		return Result{}, err
	}
	err := core.DecryptFileWithPassword(d.input, d.output, string(password))
	if errors.Is(err, core.ErrWrongPassword) {
		if d.attempts >= core.MaxPassAttempts {
			d.done = true
			return Result{}, ErrTooManyPasswordAttempts
		}
		return Result{}, err
	}
	d.done = true
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}
	s := d.svc
	warnings := s.auditFor(filepath.Dir(d.output)).RecordPasswordDecrypt(s.Now(), d.input, d.output)
	return Result{Output: d.output, Warnings: warnings}, nil
}

// ─── Saved password records ─────────────────────────────────────────────────

// CanSavePasswordRecords reports whether the user has a key of their own
// to protect saved password records with.
func (s *Service) CanSavePasswordRecords() bool {
	keys, err := core.OwnKeys(s.KeysDir)
	return err == nil && len(keys) > 0
}

// SavePasswordRecord saves a record of password, used to encrypt the files
// outputs, protected by all of the user's own keys. Returns the names of
// the keys that can open it, or core.ErrNoOwnKey if there are none.
func (s *Service) SavePasswordRecord(outputs []string, password string) ([]string, error) {
	keys, err := core.OwnKeys(s.KeysDir)
	if err != nil {
		return nil, err
	}
	rec, err := core.SavePasswordRecord(s.Locations.PasswordsDir, keys, outputs, password, s.Now())
	if err != nil {
		return nil, err
	}
	nicks := s.nicknames()
	names := make([]string, len(rec.Keys))
	for i, k := range rec.Keys {
		names[i] = choiceName(nicks, k, core.PubExt)
	}
	return names, nil
}

// PasswordRecords lists the saved password records, newest first, without
// their passwords. skipped counts record files that couldn't be read.
func (s *Service) PasswordRecords() (records []core.PasswordRecord, skipped int, err error) {
	return core.ListPasswordRecords(s.Locations.PasswordsDir)
}

// RecordKeys returns the user's keys that can open rec: its keys that are
// still in the key folder with a passphrase-protected private half. File
// is the private key file, for OpenPasswordRecord.
func (s *Service) RecordKeys(rec core.PasswordRecord) ([]Choice, error) {
	own, err := core.OwnKeys(s.KeysDir)
	if err != nil {
		return nil, err
	}
	nicks := s.nicknames()
	var choices []Choice
	for _, k := range own {
		for _, name := range rec.Keys {
			if k.PubFile != name {
				continue
			}
			path, err := s.keyPath(k.PrivFile)
			if err != nil {
				continue
			}
			choices = append(choices, Choice{
				File:      k.PrivFile,
				Name:      choiceName(nicks, k.PrivFile, core.PrivExt),
				Protected: core.ValidatePrivKeyFile(path) == nil,
			})
		}
	}
	return choices, nil
}

// RecordOpening is one attempt to open a saved password record with one
// of the user's private keys, allowing core.MaxPassAttempts passphrases.
type RecordOpening struct {
	svc      *Service
	id       string // The record's ID
	keyPath  string // Full path of the private key
	attempts int    // Passphrases tried so far
	done     bool   // Finished, successfully or after too many attempts
}

// StartOpenRecord prepares to open record rec with the private key
// privFile (from RecordKeys).
func (s *Service) StartOpenRecord(rec core.PasswordRecord, privFile string) (*RecordOpening, error) {
	keyPath, err := s.keyPath(privFile)
	if err != nil {
		return nil, err
	}
	if err := core.ValidatePrivKeyFile(keyPath); err != nil {
		return nil, err
	}
	return &RecordOpening{svc: s, id: rec.ID, keyPath: keyPath}, nil
}

// AttemptsLeft returns how many more passphrases may be tried.
func (o *RecordOpening) AttemptsLeft() int {
	if o.done {
		return 0
	}
	return core.MaxPassAttempts - o.attempts
}

// Try unlocks the key with passphrase (zeroed before Try returns) and
// returns the record's password and its files, as saved in the encrypted
// part of the record. A wrong passphrase returns core.ErrWrongPassphrase
// while attempts remain, then ErrTooManyAttempts.
func (o *RecordOpening) Try(passphrase []byte) (string, core.PasswordRecord, error) {
	defer core.ClearBytes(passphrase)
	if o.done {
		return "", core.PasswordRecord{}, ErrFinished
	}
	o.attempts++
	identity, err := core.UnlockIdentity(o.keyPath, string(passphrase))
	if errors.Is(err, core.ErrWrongPassphrase) {
		if o.attempts >= core.MaxPassAttempts {
			o.done = true
			return "", core.PasswordRecord{}, ErrTooManyAttempts
		}
		return "", core.PasswordRecord{}, err
	}
	o.done = true
	if err != nil {
		return "", core.PasswordRecord{}, err
	}
	return core.OpenPasswordRecord(o.svc.Locations.PasswordsDir, o.id, identity)
}

// DeletePasswordRecord removes the saved record with ID id. The encrypted
// files are not affected.
func (s *Service) DeletePasswordRecord(id string) error {
	return core.DeletePasswordRecord(s.Locations.PasswordsDir, id)
}
