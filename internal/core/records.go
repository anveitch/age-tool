// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

// Saved password records: when a user encrypts files with a password,
// age-tool can keep a record of that password, so a forgotten password
// can be recovered. Each record is protected like a private key: the
// password is age-encrypted to the user's own public keys, so it can only
// be read with one of their private keys and its passphrase.
//
// A record is one JSON file in the passwords folder (Locations.PasswordsDir),
// owner-only:
//
//	{
//	  "version": 1,
//	  "created": "2026-11-27T15:30:45Z",
//	  "files":   [{"path": "/home/sam/Documents/notes.txt.age", "sha256": "…"}],
//	  "keys":    ["laptop.pub"],
//	  "secret":  "-----BEGIN AGE ENCRYPTED FILE-----…"
//	}
//
// The date, files and keys are readable without a passphrase, so records
// can be listed and matched to files. File names and paths are already in
// the activity log, so this reveals nothing new. "secret" holds the
// password, together with the same files and date, encrypted to the keys
// listed. When a record is opened, the encrypted copy is what's returned,
// so editing the readable part can't change what a record says.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// recordExt is the file extension of saved password records.
const recordExt = ".json"

// recordVersion is the record format version written by this code.
const recordVersion = 1

// maxRecordSize bounds how much of a record file is read.
const maxRecordSize = 1 << 20

// Errors from saved password records.
var (
	// ErrNoOwnKey: the user has no key of their own (a key with a private
	// half) to protect the record with, so it can't be saved.
	ErrNoOwnKey = errors.New("you need a key of your own to save a password record")
	// ErrRecordNotFound: no record with that ID.
	ErrRecordNotFound = errors.New("password record not found")
	// ErrRecordNotForKey: the record wasn't saved for the key used to open
	// it (for example, the key was created after the record).
	ErrRecordNotForKey = errors.New("this password record wasn't saved for that key")
	// ErrRecordDamaged: the record file can't be read or decrypted
	// properly.
	ErrRecordDamaged = errors.New("password record is damaged")
)

// RecordFile is one encrypted file covered by a record.
type RecordFile struct {
	Path   string `json:"path"`   // Full path of the encrypted file when it was made
	SHA256 string `json:"sha256"` // SHA256 of the encrypted file, to match it later
}

// PasswordRecord describes a saved password record without its password.
type PasswordRecord struct {
	ID      string       // Identifies the record (its file name without .json)
	Created time.Time    // When the files were encrypted
	Files   []RecordFile // The files encrypted with the password
	Keys    []string     // Public key files whose private keys can open it
}

// recordFile is the JSON layout of a record file.
type recordFile struct {
	Version int          `json:"version"`
	Created string       `json:"created"`
	Files   []RecordFile `json:"files"`
	Keys    []string     `json:"keys"`
	Secret  string       `json:"secret"`
}

// recordSecret is the JSON layout of the encrypted part of a record.
type recordSecret struct {
	Password string       `json:"password"`
	Created  string       `json:"created"`
	Files    []RecordFile `json:"files"`
}

// recordIDPattern is the shape of a record ID: date, time and a random
// suffix, e.g. 20261127-153045-a1b2c3d4. Only IDs of this shape are
// accepted, so an ID can never point outside the passwords folder.
var recordIDPattern = regexp.MustCompile(`^\d{8}-\d{6}-[0-9a-f]{8}$`)

// OwnKey is one of the user's own keys: a key pair with both halves.
type OwnKey struct {
	PubFile   string        // Public key file name, e.g. "laptop.pub"
	PrivFile  string        // Private key file name, e.g. "laptop.priv"
	Recipient age.Recipient // The public key
}

// OwnKeys returns the user's own keys in keysDir: key pairs that have both
// a public and a private half. Contacts (public keys only) aren't
// included. Pairs whose public key can't be read are skipped.
func OwnKeys(keysDir string) ([]OwnKey, error) {
	pairs, err := ListKeyPairs(keysDir)
	if err != nil {
		return nil, err
	}
	var keys []OwnKey
	for _, p := range pairs {
		if p.PubFile == "" || p.PrivFile == "" {
			continue
		}
		r, err := ReadRecipient(filepath.Join(keysDir, p.PubFile))
		if err != nil {
			continue
		}
		keys = append(keys, OwnKey{PubFile: p.PubFile, PrivFile: p.PrivFile, Recipient: r})
	}
	return keys, nil
}

// SavePasswordRecord saves a record of password, used to encrypt files
// (the encrypted .age files), in dir. The password is encrypted to every
// key in keys, so any of them can open the record. Returns ErrNoOwnKey if
// keys is empty: a record is never saved unprotected.
func SavePasswordRecord(dir string, keys []OwnKey, files []string, password string, now time.Time) (PasswordRecord, error) {
	if len(keys) == 0 {
		return PasswordRecord{}, ErrNoOwnKey
	}
	if password == "" || len(files) == 0 {
		return PasswordRecord{}, errors.New("nothing to record")
	}

	// Full paths and hashes of the encrypted files
	var recFiles []RecordFile
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			return PasswordRecord{}, err
		}
		_, sum, err := HashFile(abs)
		if err != nil {
			return PasswordRecord{}, errorOfKind(ErrFileUnavailable, "cannot read "+filepath.Base(abs))
		}
		recFiles = append(recFiles, RecordFile{Path: abs, SHA256: sum})
	}
	created := now.Format(time.RFC3339)

	// Encrypt the password (with the files and date) to the user's keys,
	// as ASCII armor so it fits in the JSON
	// #nosec G117 -- the JSON only exists in memory, is encrypted below and zeroed afterwards
	secretJSON, err := json.Marshal(recordSecret{Password: password, Created: created, Files: recFiles})
	if err != nil {
		return PasswordRecord{}, err
	}
	defer ClearBytes(secretJSON)
	var armored bytes.Buffer
	aw := armor.NewWriter(&armored)
	recipients := make([]age.Recipient, len(keys))
	keyNames := make([]string, len(keys))
	for i, k := range keys {
		recipients[i], keyNames[i] = k.Recipient, k.PubFile
	}
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return PasswordRecord{}, err
	}
	if _, err := w.Write(secretJSON); err != nil {
		return PasswordRecord{}, err
	}
	if err := w.Close(); err != nil {
		return PasswordRecord{}, err
	}
	if err := aw.Close(); err != nil {
		return PasswordRecord{}, err
	}

	id, err := newRecordID(now)
	if err != nil {
		return PasswordRecord{}, err
	}
	data, err := json.MarshalIndent(recordFile{
		Version: recordVersion, Created: created, Files: recFiles, Keys: keyNames, Secret: armored.String(),
	}, "", "  ")
	if err != nil {
		return PasswordRecord{}, err
	}
	if err := writeRecordFile(dir, id, append(data, '\n')); err != nil {
		return PasswordRecord{}, err
	}
	return PasswordRecord{ID: id, Created: now.Truncate(time.Second), Files: recFiles, Keys: keyNames}, nil
}

// newRecordID makes a record ID from the time and 4 random bytes.
func newRecordID(now time.Time) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return now.Format("20060102-150405") + "-" + hex.EncodeToString(b), nil
}

// writeRecordFile writes a record owner-only (0600) in dir (0700),
// through a temporary file, so a record is never half-written.
func writeRecordFile(dir, id string, data []byte) error {
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return fmt.Errorf("could not save the password record")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close() // already failing; the deferred Remove cleans up
		return fmt.Errorf("could not save the password record")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // already failing; the deferred Remove cleans up
		return fmt.Errorf("could not save the password record")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not save the password record")
	}
	if err := os.Rename(tmpName, filepath.Join(dir, id+recordExt)); err != nil {
		return fmt.Errorf("could not save the password record")
	}
	return nil
}

// recordPath returns the path of record id in dir, or ErrRecordNotFound
// if id isn't a valid record ID.
func recordPath(dir, id string) (string, error) {
	if !recordIDPattern.MatchString(id) {
		return "", ErrRecordNotFound
	}
	return filepath.Join(dir, id+recordExt), nil
}

// readRecordFile reads and parses record id in dir.
func readRecordFile(dir, id string) (recordFile, error) {
	path, err := recordPath(dir, id)
	if err != nil {
		return recordFile{}, err
	}
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return recordFile{}, ErrRecordNotFound
	}
	if err != nil {
		return recordFile{}, errorOfKind(ErrFileUnavailable, "cannot open the password record")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRecordSize))
	if err != nil {
		return recordFile{}, ErrRecordDamaged
	}
	var rf recordFile
	if err := json.Unmarshal(data, &rf); err != nil || rf.Version != recordVersion || rf.Secret == "" {
		return recordFile{}, ErrRecordDamaged
	}
	return rf, nil
}

// ListPasswordRecords lists the records in dir, newest first, without
// their passwords. A missing folder means no records. Files that can't be
// read are skipped and counted in skipped.
func ListPasswordRecords(dir string) (records []PasswordRecord, skipped int, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), recordExt)
		if !ok || e.IsDir() || !recordIDPattern.MatchString(id) {
			continue
		}
		rf, err := readRecordFile(dir, id)
		if err != nil {
			skipped++
			continue
		}
		created, err := time.Parse(time.RFC3339, rf.Created)
		if err != nil {
			skipped++
			continue
		}
		records = append(records, PasswordRecord{ID: id, Created: created, Files: rf.Files, Keys: rf.Keys})
	}
	// Newest first; IDs break ties (they start with the date and time)
	sort.Slice(records, func(i, j int) bool {
		if !records[i].Created.Equal(records[j].Created) {
			return records[i].Created.After(records[j].Created)
		}
		return records[i].ID > records[j].ID
	})
	return records, skipped, nil
}

// OpenPasswordRecord decrypts record id in dir with identity (an unlocked
// private key, from UnlockIdentity) and returns the password and the
// record as saved in its encrypted part. Returns ErrRecordNotForKey if the
// record wasn't saved for that key.
func OpenPasswordRecord(dir, id string, identity age.Identity) (string, PasswordRecord, error) {
	rf, err := readRecordFile(dir, id)
	if err != nil {
		return "", PasswordRecord{}, err
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(rf.Secret)), identity)
	if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
		return "", PasswordRecord{}, ErrRecordNotForKey
	}
	if err != nil {
		return "", PasswordRecord{}, ErrRecordDamaged
	}
	data, err := io.ReadAll(io.LimitReader(r, maxRecordSize))
	defer ClearBytes(data)
	if err != nil {
		return "", PasswordRecord{}, ErrRecordDamaged
	}
	var secret recordSecret
	if err := json.Unmarshal(data, &secret); err != nil || secret.Password == "" {
		return "", PasswordRecord{}, ErrRecordDamaged
	}
	created, err := time.Parse(time.RFC3339, secret.Created)
	if err != nil {
		return "", PasswordRecord{}, ErrRecordDamaged
	}
	return secret.Password, PasswordRecord{ID: id, Created: created, Files: secret.Files, Keys: rf.Keys}, nil
}

// DeletePasswordRecord removes record id from dir.
func DeletePasswordRecord(dir, id string) error {
	path, err := recordPath(dir, id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrRecordNotFound
		}
		return fmt.Errorf("could not delete the password record")
	}
	return nil
}

// RecordsForFile returns the records in dir that cover the encrypted file
// at path, matched by its SHA256, so a copy that was moved or renamed is
// still found. Newest first.
func RecordsForFile(dir, path string) ([]PasswordRecord, error) {
	_, sum, err := HashFile(path)
	if err != nil {
		return nil, errorOfKind(ErrFileUnavailable, "cannot read "+filepath.Base(path))
	}
	records, _, err := ListPasswordRecords(dir)
	if err != nil {
		return nil, err
	}
	var matches []PasswordRecord
	for _, r := range records {
		if slices.ContainsFunc(r.Files, func(f RecordFile) bool { return f.SHA256 == sum }) {
			matches = append(matches, r)
		}
	}
	return matches, nil
}
