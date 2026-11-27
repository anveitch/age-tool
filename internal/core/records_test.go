// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// recordsTestPass is the key passphrase used for test keys.
const recordsTestPass = "correct horse battery"

// recordsSetup makes a key folder with two keys of the user's own
// ("desktop" and "laptop") and one contact ("alice", public key only),
// plus two password-encrypted files. Returns the folders and file paths.
func recordsSetup(t *testing.T) (keysDir, recordsDir string, files []string) {
	t.Helper()
	root := t.TempDir()
	keysDir = filepath.Join(root, "keys")
	recordsDir = filepath.Join(root, "passwords")
	if err := EnsurePrivateDir(keysDir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"laptop", "desktop"} {
		if _, _, err := GenerateKeyPair(keysDir, name, recordsTestPass); err != nil {
			t.Fatal(err)
		}
	}
	contact, _ := age.GenerateX25519Identity()
	writeTestFile(t, filepath.Join(keysDir, "alice.pub"), contact.Recipient().String()+"\n")

	for _, name := range []string{"notes.txt", "plans.txt"} {
		plain := filepath.Join(root, name)
		writeTestFile(t, plain, "content of "+name)
		if err := EncryptFileWithPassword(plain, plain+AgeExt, testFilePassword); err != nil {
			t.Fatal(err)
		}
		files = append(files, plain+AgeExt)
	}
	return keysDir, recordsDir, files
}

// unlock opens one of the test keys with its passphrase.
func unlock(t *testing.T, keysDir, privFile string) age.Identity {
	t.Helper()
	id, err := UnlockIdentity(filepath.Join(keysDir, privFile), recordsTestPass)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestOwnKeys checks contacts aren't counted as the user's own keys.
func TestOwnKeys(t *testing.T) {
	keysDir, _, _ := recordsSetup(t)
	keys, err := OwnKeys(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, k := range keys {
		names = append(names, k.PubFile)
	}
	if strings.Join(names, ",") != "desktop.pub,laptop.pub" {
		t.Errorf("own keys = %v, want desktop.pub and laptop.pub only", names)
	}
}

// TestPasswordRecordRoundTrip saves a record for two files, protected by
// two keys, and opens it with each key.
func TestPasswordRecordRoundTrip(t *testing.T) {
	keysDir, recordsDir, files := recordsSetup(t)
	keys, _ := OwnKeys(keysDir)
	now := time.Date(2026, 11, 27, 15, 30, 45, 0, time.UTC)

	rec, err := SavePasswordRecord(recordsDir, keys, files, testFilePassword, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Files) != 2 || len(rec.Keys) != 2 || !strings.HasPrefix(rec.ID, "20261127-153045-") {
		t.Fatalf("saved record %+v", rec)
	}

	// Owner-only folder and file
	if info, _ := os.Stat(recordsDir); info.Mode().Perm() != 0700 {
		t.Errorf("records folder mode %v, want 0700", info.Mode().Perm())
	}
	path := filepath.Join(recordsDir, rec.ID+recordExt)
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Errorf("record file mode %v, want 0600", info.Mode().Perm())
	}

	// The password isn't readable in the file
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), testFilePassword) {
		t.Fatal("password stored in readable form")
	}

	// Either key opens it
	for _, priv := range []string{"laptop.priv", "desktop.priv"} {
		pw, opened, err := OpenPasswordRecord(recordsDir, rec.ID, unlock(t, keysDir, priv))
		if err != nil {
			t.Fatalf("%s: %v", priv, err)
		}
		if pw != testFilePassword {
			t.Errorf("%s: password %q", priv, pw)
		}
		if !opened.Created.Equal(now) || len(opened.Files) != 2 || opened.Files[0].Path != files[0] {
			t.Errorf("%s: opened record %+v", priv, opened)
		}
	}

	// And the password really opens the files
	out := filepath.Join(t.TempDir(), "out.txt")
	pw, _, _ := OpenPasswordRecord(recordsDir, rec.ID, unlock(t, keysDir, "laptop.priv"))
	if err := DecryptFileWithPassword(files[0], out, pw); err != nil {
		t.Errorf("recorded password doesn't open the file: %v", err)
	}
}

// TestPasswordRecordNeedsOwnKey checks a record is never saved without a
// key of the user's own to protect it.
func TestPasswordRecordNeedsOwnKey(t *testing.T) {
	_, recordsDir, files := recordsSetup(t)
	if _, err := SavePasswordRecord(recordsDir, nil, files, testFilePassword, time.Now()); !errors.Is(err, ErrNoOwnKey) {
		t.Fatalf("got %v, want ErrNoOwnKey", err)
	}
	if _, err := os.Stat(recordsDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("records folder created although nothing was saved")
	}
}

// TestPasswordRecordWrongKey checks a key created after the record, and a
// contact's key, can't open it.
func TestPasswordRecordWrongKey(t *testing.T) {
	keysDir, recordsDir, files := recordsSetup(t)
	keys, _ := OwnKeys(keysDir)
	rec, err := SavePasswordRecord(recordsDir, keys[:1], files, testFilePassword, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Saved for desktop only: laptop can't open it
	if _, _, err := OpenPasswordRecord(recordsDir, rec.ID, unlock(t, keysDir, "laptop.priv")); !errors.Is(err, ErrRecordNotForKey) {
		t.Errorf("other key: got %v, want ErrRecordNotForKey", err)
	}
	// A wrong passphrase fails earlier, when unlocking the key
	if _, err := UnlockIdentity(filepath.Join(keysDir, "desktop.priv"), "wrong passphrase!"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: got %v", err)
	}
}

// TestPasswordRecordListing checks records are listed newest first with
// their files and keys, damaged files are skipped, and the readable part
// can't change what an opened record says.
func TestPasswordRecordListing(t *testing.T) {
	keysDir, recordsDir, files := recordsSetup(t)
	keys, _ := OwnKeys(keysDir)

	// No folder yet: no records, no error
	if recs, skipped, err := ListPasswordRecords(recordsDir); err != nil || len(recs) != 0 || skipped != 0 {
		t.Fatalf("empty: %v, %d, %v", recs, skipped, err)
	}

	older, _ := SavePasswordRecord(recordsDir, keys, files[:1], testFilePassword, time.Now().Add(-time.Hour))
	newer, _ := SavePasswordRecord(recordsDir, keys, files[1:], "another-pass-word-9!", time.Now())
	writeTestFile(t, filepath.Join(recordsDir, "20260101-000000-deadbeef.json"), "not json")
	writeTestFile(t, filepath.Join(recordsDir, "notes.txt"), "not a record")

	recs, skipped, err := ListPasswordRecords(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].ID != newer.ID || recs[1].ID != older.ID {
		t.Fatalf("listing %+v", recs)
	}
	if skipped != 1 {
		t.Errorf("skipped %d, want 1 (the damaged record)", skipped)
	}

	// Edit the readable part of the older record: opening it still gives
	// the files that were encrypted with the password
	path := filepath.Join(recordsDir, older.ID+recordExt)
	var rf recordFile
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &rf)
	rf.Files[0].Path = "/somewhere/else.age"
	data, _ = json.Marshal(rf)
	writeTestFile(t, path, string(data))
	_, opened, err := OpenPasswordRecord(recordsDir, older.ID, unlock(t, keysDir, "laptop.priv"))
	if err != nil {
		t.Fatal(err)
	}
	if opened.Files[0].Path != files[0] {
		t.Errorf("opened record shows %q, want the original %q", opened.Files[0].Path, files[0])
	}
}

// TestRecordsForFile checks a record is found for its file, including
// after the file is moved, and not for other files.
func TestRecordsForFile(t *testing.T) {
	keysDir, recordsDir, files := recordsSetup(t)
	keys, _ := OwnKeys(keysDir)
	rec, _ := SavePasswordRecord(recordsDir, keys, files[:1], testFilePassword, time.Now())

	moved := filepath.Join(t.TempDir(), "renamed.age")
	if err := os.Rename(files[0], moved); err != nil {
		t.Fatal(err)
	}
	found, err := RecordsForFile(recordsDir, moved)
	if err != nil || len(found) != 1 || found[0].ID != rec.ID {
		t.Errorf("moved file: %+v, %v", found, err)
	}
	if found, _ := RecordsForFile(recordsDir, files[1]); len(found) != 0 {
		t.Errorf("other file matched %+v", found)
	}
}

// TestDeletePasswordRecord checks deleting, and that IDs can't point
// outside the records folder.
func TestDeletePasswordRecord(t *testing.T) {
	keysDir, recordsDir, files := recordsSetup(t)
	keys, _ := OwnKeys(keysDir)
	rec, _ := SavePasswordRecord(recordsDir, keys, files, testFilePassword, time.Now())

	// Files outside the folder that a bad ID might try to reach
	outside := filepath.Join(filepath.Dir(recordsDir), "keep.json")
	writeTestFile(t, outside, "{}")
	for _, bad := range []string{"../keep", "", "20261127-153045-a1b2c3d4/../../keep", "*"} {
		if err := DeletePasswordRecord(recordsDir, bad); !errors.Is(err, ErrRecordNotFound) {
			t.Errorf("Delete(%q) = %v, want ErrRecordNotFound", bad, err)
		}
		if _, _, err := OpenPasswordRecord(recordsDir, bad, nil); !errors.Is(err, ErrRecordNotFound) {
			t.Errorf("Open(%q) = %v, want ErrRecordNotFound", bad, err)
		}
	}
	if !FileExists(outside) {
		t.Fatal("a file outside the records folder was deleted")
	}

	if err := DeletePasswordRecord(recordsDir, rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := DeletePasswordRecord(recordsDir, rec.ID); !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if recs, _, _ := ListPasswordRecords(recordsDir); len(recs) != 0 {
		t.Errorf("records left: %+v", recs)
	}
}
