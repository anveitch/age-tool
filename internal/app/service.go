// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Package app holds the GUI's workflows: encrypting, decrypting, managing
// keys and reading activity, each as one call that enforces the same rules
// as the CLI. It contains no toolkit code, so every workflow can be tested
// without a display, and the GUI's screens only gather choices, call these
// functions and show the results (using Message for errors).
//
// Nothing secret is kept here: passphrases are passed in as byte slices,
// used, and zeroed before the call returns.
package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"age-tool/internal/core"

	"filippo.io/age"
)

// Errors returned by the workflows, in addition to the core error kinds.
var (
	// ErrOutputExists: the output file already exists and overwriting it
	// wasn't confirmed. Ask the user, then try again with overwrite set.
	ErrOutputExists = errors.New("output file already exists")

	// ErrAlreadyEncrypted: the file chosen for encryption is already a .age file.
	ErrAlreadyEncrypted = errors.New("file is already encrypted")

	// ErrNotAgeFile: the file chosen for decryption isn't a .age file.
	ErrNotAgeFile = errors.New("not a .age file")

	// ErrIsFolder: a folder was chosen where a file was expected.
	ErrIsFolder = errors.New("is a folder")

	// ErrWrongKey: the encrypted file wasn't encrypted for the chosen key.
	ErrWrongKey = errors.New("file was not encrypted for this key")

	// ErrTooManyAttempts: the passphrase was wrong MaxPassAttempts times.
	ErrTooManyAttempts = errors.New("too many incorrect passphrase attempts")

	// ErrFinished: Try was called on a Decryption that already finished.
	ErrFinished = errors.New("decryption already finished")

	// ErrPassphraseMismatch: the two entries of a new passphrase differ.
	ErrPassphraseMismatch = errors.New("passphrases do not match")

	// ErrEncryptFailed and ErrDecryptFailed wrap any other failure while
	// writing the output (e.g. a damaged .age file or a full disk).
	ErrEncryptFailed = errors.New("encryption failed")
	ErrDecryptFailed = errors.New("decryption failed")
)

// Service runs the workflows against one key folder, logging every
// transaction to the central audit log and to a local log beside the files.
type Service struct {
	Locations core.Locations   // Standard per-user locations (central log, settings)
	KeysDir   string           // Folder holding the keys: normally Locations.KeysDir
	Now       func() time.Time // Clock for audit timestamps; time.Now unless testing
}

// New returns a Service using the standard per-user locations, creating
// the key store (owner-only) if needed.
func New() (*Service, error) {
	loc, err := core.DefaultLocations()
	if err != nil {
		return nil, err
	}
	return NewWithLocations(loc)
}

// NewWithLocations returns a Service using the given locations, creating
// the key store (owner-only) if needed. Used by tests and by New.
func NewWithLocations(loc core.Locations) (*Service, error) {
	if err := core.EnsurePrivateDir(loc.KeysDir); err != nil {
		return nil, err
	}
	return &Service{Locations: loc, KeysDir: loc.KeysDir, Now: time.Now}, nil
}

// nicknames loads the nicknames for the key folder.
func (s *Service) nicknames() core.Nicknames {
	return core.LoadNicknames(filepath.Join(s.KeysDir, core.NicknameFileName))
}

// saveNicknames writes the nicknames for the key folder.
func (s *Service) saveNicknames(n core.Nicknames) error {
	return n.Save(filepath.Join(s.KeysDir, core.NicknameFileName))
}

// auditFor returns the logs for a transaction whose output is in dir: the
// central log plus the local log in dir (the same pair the CLI uses).
func (s *Service) auditFor(dir string) core.AuditLogs {
	return core.NewAuditLogs(s.Locations.CentralAudit(), core.LocalAudit(dir))
}

// keyPath returns the path of a key file in the key folder, refusing
// anything that isn't a plain filename so a caller can't reach outside it.
func (s *Service) keyPath(file string) (string, error) {
	if err := core.ValidateFilename(file); err != nil {
		return "", err
	}
	return filepath.Join(s.KeysDir, file), nil
}

// ─── Listing keys ───────────────────────────────────────────────────────────

// Key describes a key pair in the key folder for the "My keys" screen.
// A key with only a public half is a contact: someone else's key, used to
// encrypt files for them.
type Key struct {
	Base         string // Shared base name, e.g. "work" for work.pub / work.priv
	Name         string // Name to show: a nickname if either file has one, else Base
	PubFile      string // Public key filename, or "" if missing
	PrivFile     string // Private key filename, or "" if missing
	PubNickname  string // Nickname of the public key file, if any
	PrivNickname string // Nickname of the private key file, if any
	Protected    bool   // The private key exists and is passphrase-protected
	Contact      bool   // Only a public key: someone else's key
}

// Keys lists the key pairs in the key folder, sorted by base name.
func (s *Service) Keys() ([]Key, error) {
	pairs, err := core.ListKeyPairs(s.KeysDir)
	if err != nil {
		return nil, err
	}
	nicks := s.nicknames()
	keys := make([]Key, 0, len(pairs))
	for _, p := range pairs {
		k := Key{
			Base:         p.Base,
			Name:         p.Base,
			PubFile:      p.PubFile,
			PrivFile:     p.PrivFile,
			PubNickname:  nicks[p.PubFile],
			PrivNickname: nicks[p.PrivFile],
			Contact:      p.PrivFile == "",
		}
		if p.PrivFile != "" {
			k.Protected = core.ValidatePrivKeyFile(filepath.Join(s.KeysDir, p.PrivFile)) == nil
		}
		// Prefer the public key's nickname, as the CLI does when deleting
		if k.PubNickname != "" {
			k.Name = k.PubNickname
		} else if k.PrivNickname != "" {
			k.Name = k.PrivNickname
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Choice is a key file offered in a picker, shown by name.
type Choice struct {
	File      string // Key filename, passed back to Encrypt or StartDecrypt
	Name      string // The file's nickname, or its base name
	Protected bool   // Private keys only: passphrase-protected (unprotected keys can't be used)
}

// choiceName returns a file's nickname, or its name without the extension.
func choiceName(nicks core.Nicknames, file, ext string) string {
	if nick := nicks[file]; nick != "" {
		return nick
	}
	return strings.TrimSuffix(file, ext)
}

// Recipients lists the public keys files can be encrypted for: the user's
// own keys and their contacts.
func (s *Service) Recipients() ([]Choice, error) {
	files, err := core.ListPublicKeys(s.KeysDir)
	if err != nil {
		return nil, err
	}
	nicks := s.nicknames()
	choices := make([]Choice, len(files))
	for i, f := range files {
		choices[i] = Choice{File: f, Name: choiceName(nicks, f, core.PubExt)}
	}
	return choices, nil
}

// Identities lists the private keys files can be decrypted with. Keys
// that aren't passphrase-protected are included, marked unprotected, so
// the GUI can explain why they can't be used.
func (s *Service) Identities() ([]Choice, error) {
	files, err := core.ListPrivateKeys(s.KeysDir)
	if err != nil {
		return nil, err
	}
	nicks := s.nicknames()
	choices := make([]Choice, len(files))
	for i, f := range files {
		choices[i] = Choice{
			File:      f,
			Name:      choiceName(nicks, f, core.PrivExt),
			Protected: core.ValidatePrivKeyFile(filepath.Join(s.KeysDir, f)) == nil,
		}
	}
	return choices, nil
}

// ─── Encrypt ────────────────────────────────────────────────────────────────

// Result reports a finished encryption or decryption.
type Result struct {
	Output   string  // Path of the file written
	Warnings []error // Non-fatal problems, e.g. an audit log couldn't be written
}

// checkInputFile checks that path is a file (not a folder) within the size
// limit.
func checkInputFile(path string) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return ErrIsFolder
	}
	_, err := core.CheckFileSize(path)
	return err
}

// checkOutput refuses to replace an existing output file unless the user
// confirmed it.
func checkOutput(path string, overwrite bool) error {
	if !overwrite && core.FileExists(path) {
		return ErrOutputExists
	}
	return nil
}

// EncryptOutput returns where encrypting input will write: beside it, with
// ".age" added. The GUI uses it to ask about overwriting before encrypting.
func EncryptOutput(input string) string {
	return core.EncryptedOutputPath(input)
}

// Encrypt encrypts input for the public key pubFile (from Recipients),
// saving the result beside it as input.age. If that file exists, Encrypt
// returns ErrOutputExists unless overwrite is true. The output is written
// atomically and owner-only, and the transaction is logged.
func (s *Service) Encrypt(input, pubFile string, overwrite bool) (Result, error) {
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
	keyPath, err := s.keyPath(pubFile)
	if err != nil {
		return Result{}, err
	}
	recipient, err := core.ReadRecipient(keyPath)
	if err != nil {
		return Result{}, err
	}
	output := EncryptOutput(input)
	if err := checkOutput(output, overwrite); err != nil {
		return Result{}, err
	}

	if err := core.EncryptFile(input, output, recipient); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}
	warnings := s.auditFor(filepath.Dir(output)).RecordEncrypt(s.Now(), input, output, pubFile, s.nicknames()[pubFile])
	return Result{Output: output, Warnings: warnings}, nil
}

// ─── Decrypt ────────────────────────────────────────────────────────────────

// DecryptOutput returns where decrypting input will write: beside it, with
// ".age" removed.
func DecryptOutput(input string) string {
	return core.DecryptedOutputPath(input)
}

// Decryption is one attempt to decrypt a file with a chosen private key.
// StartDecrypt checks everything that doesn't need the passphrase, so the
// user hears about problems before typing it; Try then unlocks the key,
// allowing at most core.MaxPassAttempts passphrases. A Decryption holds no
// secrets, only the file names and the number of attempts made.
type Decryption struct {
	svc       *Service
	input     string // Absolute path of the .age file
	output    string // Where the decrypted file will be written
	privFile  string // Private key filename in the key folder
	keyPath   string // Full path of the private key
	overwrite bool   // The user confirmed replacing an existing output file
	attempts  int    // Passphrases tried so far
	done      bool   // Finished, successfully or after too many attempts
}

// StartDecrypt prepares to decrypt input (a .age file) with the private
// key privFile (from Identities). It fails straight away if the file
// isn't usable, the key isn't passphrase-protected, or the output exists
// and overwrite is false (ErrOutputExists).
func (s *Service) StartDecrypt(input, privFile string, overwrite bool) (*Decryption, error) {
	input, err := filepath.Abs(input)
	if err != nil {
		return nil, core.ErrFileUnavailable
	}
	// Without the .age extension the output would be the input itself
	if !strings.HasSuffix(input, core.AgeExt) || filepath.Base(input) == core.AgeExt {
		return nil, ErrNotAgeFile
	}
	if err := checkInputFile(input); err != nil {
		return nil, err
	}
	keyPath, err := s.keyPath(privFile)
	if err != nil {
		return nil, err
	}
	if err := core.ValidatePrivKeyFile(keyPath); err != nil {
		return nil, err
	}
	output := DecryptOutput(input)
	if err := checkOutput(output, overwrite); err != nil {
		return nil, err
	}
	return &Decryption{svc: s, input: input, output: output, privFile: privFile, keyPath: keyPath, overwrite: overwrite}, nil
}

// Output returns where the decrypted file will be written.
func (d *Decryption) Output() string { return d.output }

// AttemptsLeft returns how many more passphrases may be tried.
func (d *Decryption) AttemptsLeft() int {
	if d.done {
		return 0
	}
	return core.MaxPassAttempts - d.attempts
}

// Try unlocks the private key with passphrase (zeroed before Try returns)
// and decrypts the file. A wrong passphrase returns core.ErrWrongPassphrase
// while attempts remain, and ErrTooManyAttempts on the last one. Any other
// outcome, success or failure, finishes the Decryption; calling Try again
// afterwards returns ErrFinished.
func (d *Decryption) Try(passphrase []byte) (Result, error) {
	defer core.ClearBytes(passphrase)
	if d.done {
		return Result{}, ErrFinished
	}
	d.attempts++

	// Unlock the key in memory; the plaintext key is never written to disk
	identity, err := core.UnlockIdentity(d.keyPath, string(passphrase))
	if errors.Is(err, core.ErrWrongPassphrase) {
		if d.attempts >= core.MaxPassAttempts {
			d.done = true
			return Result{}, ErrTooManyAttempts
		}
		return Result{}, err
	}
	// From here on the attempt is over, whatever happens
	d.done = true
	if err != nil {
		return Result{}, err
	}

	// Re-check the output in case a file appeared while the user typed
	if err := checkOutput(d.output, d.overwrite); err != nil {
		return Result{}, err
	}
	if err := core.DecryptFile(d.input, d.output, identity); err != nil {
		// age reports a file not encrypted for this key as NoIdentityMatchError
		if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
			return Result{}, ErrWrongKey
		}
		return Result{}, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	s := d.svc
	warnings := s.auditFor(filepath.Dir(d.output)).RecordDecrypt(s.Now(), d.input, d.output, d.privFile, s.nicknames()[d.privFile])
	return Result{Output: d.output, Warnings: warnings}, nil
}

// ─── Managing keys ──────────────────────────────────────────────────────────

// checkNewPassphrase checks a new passphrase and its confirmation. Both
// are left for the caller to clear.
func checkNewPassphrase(passphrase, confirm []byte) error {
	if string(passphrase) != string(confirm) {
		return ErrPassphraseMismatch
	}
	return core.ValidateNewPassphrase(string(passphrase))
}

// cleanName trims a user-entered name and checks it is a usable filename.
func cleanName(name string) (string, error) {
	name, err := core.SanitiseInput(name)
	if err != nil {
		return "", err
	}
	if err := core.ValidateFilename(name); err != nil {
		return "", err
	}
	return name, nil
}

// KeyCreated reports a newly generated key pair.
type KeyCreated struct {
	PubFile  string  // Path of the public key
	PrivFile string  // Path of the passphrase-protected private key
	Warnings []error // Non-fatal problems, e.g. an audit log couldn't be written
}

// GenerateKey creates a key pair called name in the key folder, protecting
// the private key with passphrase (which must match confirm). Both
// passphrase slices are zeroed before it returns. An optional nickname is
// given to both halves. The creation is logged.
func (s *Service) GenerateKey(name, nickname string, passphrase, confirm []byte) (KeyCreated, error) {
	defer core.ClearBytes(passphrase)
	defer core.ClearBytes(confirm)

	name, err := cleanName(name)
	if err != nil {
		return KeyCreated{}, err
	}
	if core.KeyPairExists(s.KeysDir, name) {
		return KeyCreated{}, core.ErrKeyExists
	}
	if err := checkNewPassphrase(passphrase, confirm); err != nil {
		return KeyCreated{}, err
	}
	nickname, err = core.SanitiseInput(nickname)
	if err != nil {
		return KeyCreated{}, err
	}

	pubPath, privPath, err := core.GenerateKeyPair(s.KeysDir, name, string(passphrase))
	if err != nil {
		return KeyCreated{}, err
	}
	created := KeyCreated{PubFile: pubPath, PrivFile: privPath}
	created.Warnings = s.auditFor(s.KeysDir).RecordKeyCreation(s.Now(), name, pubPath, privPath)

	if nickname != "" {
		if err := s.setNicknames(nickname, name+core.PubExt, name+core.PrivExt); err != nil {
			created.Warnings = append(created.Warnings, err)
		}
	}
	return created, nil
}

// ProtectKey passphrase-protects an open (unprotected) private key in
// place. The passphrase must match confirm; both are zeroed before it
// returns.
func (s *Service) ProtectKey(privFile string, passphrase, confirm []byte) error {
	defer core.ClearBytes(passphrase)
	defer core.ClearBytes(confirm)

	keyPath, err := s.keyPath(privFile)
	if err != nil {
		return err
	}
	// Read the key first, so a bad file is reported before the passphrase
	secretKey, err := core.ReadOpenSecretKey(keyPath)
	if err != nil {
		return err
	}
	if err := checkNewPassphrase(passphrase, confirm); err != nil {
		return err
	}
	return core.WritePassphraseProtectedKey(keyPath, secretKey, string(passphrase))
}

// ImportContact saves someone's public key (pasted text, or the contents
// of their .pub file) as name.pub, with an optional nickname, so files can
// be encrypted for them. A private key is refused (core.ErrIsPrivateKey).
func (s *Service) ImportContact(name, nickname, keyText string) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	nickname, err = core.SanitiseInput(nickname)
	if err != nil {
		return err
	}
	path, err := core.ImportPublicKey(s.KeysDir, name, keyText)
	if err != nil {
		return err
	}
	if nickname == "" {
		return nil
	}
	return s.setNicknames(nickname, filepath.Base(path))
}

// ImportContactFile imports a contact from a .pub file. See ImportContact.
func (s *Service) ImportContactFile(name, nickname, path string) error {
	key, err := core.ReadPublicKeyString(path)
	if err != nil {
		return err
	}
	return s.ImportContact(name, nickname, key)
}

// PublicKeyText returns the age1… text of a public key, to show or copy.
func (s *Service) PublicKeyText(pubFile string) (string, error) {
	keyPath, err := s.keyPath(pubFile)
	if err != nil {
		return "", err
	}
	return core.ReadPublicKeyString(keyPath)
}

// ExportPublicKey saves a copy of a public key at dest, never replacing an
// existing file.
func (s *Service) ExportPublicKey(pubFile, dest string) error {
	keyPath, err := s.keyPath(pubFile)
	if err != nil {
		return err
	}
	return core.ExportPublicKey(keyPath, dest)
}

// SetNickname gives a key file a nickname. An empty nickname removes it.
func (s *Service) SetNickname(file, nickname string) error {
	if _, err := s.keyPath(file); err != nil {
		return err
	}
	nickname, err := core.SanitiseInput(nickname)
	if err != nil {
		return err
	}
	return s.setNicknames(nickname, file)
}

// setNicknames sets (or with "" removes) the nickname of each file.
func (s *Service) setNicknames(nickname string, files ...string) error {
	nicks := s.nicknames()
	for _, f := range files {
		if nickname == "" {
			delete(nicks, f)
		} else {
			nicks[f] = nickname
		}
	}
	return s.saveNicknames(nicks)
}

// DeleteKey deletes both halves of the key pair base and their nicknames.
// The GUI must confirm with the user first. Returns an error naming any
// file that couldn't be deleted.
func (s *Service) DeleteKey(base string) error {
	if err := core.ValidateFilename(base); err != nil {
		return err
	}
	nicks := s.nicknames()
	_, failed := core.DeleteKeyPair(s.KeysDir, base, nicks)
	saveErr := s.saveNicknames(nicks)
	if len(failed) > 0 {
		return fmt.Errorf("could not delete %s", strings.Join(failed, ", "))
	}
	return saveErr
}

// ─── Activity ───────────────────────────────────────────────────────────────

// Activity returns up to limit of the most recent transactions from the
// central audit log, newest first, and how many receipts couldn't be read.
func (s *Service) Activity(limit int) ([]core.ActivityEntry, int, error) {
	return core.ReadActivity(s.Locations.CentralAudit().ReceiptsDir, limit)
}
