// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"age-tool/internal/core"
)

// cliKeyPass is the key passphrase used for test keys.
const cliKeyPass = "correct horse battery"

// cliTestPassword is a file password that meets the default rules.
const cliTestPassword = "Tr4vel#Bus-ride"

// setupCLI points the CLI at temporary folders (key store, passwords,
// settings, logs), makes a temporary working folder holding notes.txt the
// current directory, and returns the working folder. With ownKey, it also
// creates a key of the user's own named "laptop".
func setupCLI(t *testing.T, ownKey bool) string {
	t.Helper()
	root := t.TempDir()
	locations = core.Locations{
		KeysDir:      filepath.Join(root, "keys"),
		PasswordsDir: filepath.Join(root, "passwords"),
		ConfigDir:    filepath.Join(root, "config"),
		StateDir:     filepath.Join(root, "state"),
	}
	keyDir, nicknameFile, usingStore = locations.KeysDir, locations.NicknameFile(), true
	if err := core.EnsurePrivateDir(keyDir); err != nil {
		t.Fatal(err)
	}
	if ownKey {
		if _, _, err := core.GenerateKeyPair(keyDir, "laptop", cliKeyPass); err != nil {
			t.Fatal(err)
		}
	}
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "notes.txt"), []byte("meeting notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	return work
}

// secrets makes readSecret return the given hidden inputs in order, then
// fail. It restores the real readSecret when the test ends.
func secrets(t *testing.T, values ...string) {
	t.Helper()
	orig := readSecret
	t.Cleanup(func() { readSecret = orig })
	readSecret = func() ([]byte, error) {
		if len(values) == 0 {
			return nil, errors.New("no more test input")
		}
		v := values[0]
		values = values[1:]
		return []byte(v), nil
	}
}

// captureStdout runs fn and returns what it printed to standard output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	return <-done
}

// TestCLIEncryptWithOwnPassword encrypts with a typed password, after a
// first try that breaks the rules. With no key of the user's own, no
// record is offered; the password is shown once instead.
func TestCLIEncryptWithOwnPassword(t *testing.T) {
	work := setupCLI(t, false)
	secrets(t, "short", "short", cliTestPassword, cliTestPassword)

	// File 1, "a password", "type my own"
	out := captureStdout(t, func() { encrypt(input("1", "2", "2")) })

	enc := filepath.Join(work, "notes.txt.age")
	if m, err := core.FileLockMethod(enc); err != nil || m != core.LockedWithPassword {
		t.Fatalf("FileLockMethod = %v, %v\n%s", m, err, out)
	}
	if !strings.Contains(out, "The password is:  "+cliTestPassword) {
		t.Errorf("password not shown once without a key:\n%s", out)
	}
	if _, err := os.Stat(locations.PasswordsDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("a record was saved although there is no key to protect it")
	}
}

// TestCLIEncryptSuggestedAndSave takes a suggested password, saves a
// record, decrypts with the password, and reads it back from Saved
// Passwords.
func TestCLIEncryptSuggestedAndSave(t *testing.T) {
	work := setupCLI(t, true)

	// File 1, "a password", "suggested", accept it, keep a record (default)
	out := captureStdout(t, func() { encrypt(input("1", "2", "1", "", "")) })
	if !strings.Contains(out, "Record saved, protected by: laptop.pub") {
		t.Fatalf("record not saved:\n%s", out)
	}
	suggested := between(out, "Suggested password:  ", "\n")
	if err := core.DefaultPasswordRules.CheckPassword(suggested); err != nil {
		t.Fatalf("suggested %q: %v", suggested, err)
	}

	// Saved Passwords: record 1, "show", with the key's passphrase
	secrets(t, cliKeyPass)
	out = captureStdout(t, func() { savedPasswords(input("1", "1")) })
	if !strings.Contains(out, "Password:  "+suggested) {
		t.Fatalf("saved password not shown:\n%s", out)
	}
	if !strings.Contains(out, filepath.Join(work, "notes.txt.age")) {
		t.Errorf("files not listed:\n%s", out)
	}

	// Decrypt with that password, after one wrong try
	if err := os.Remove(filepath.Join(work, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	secrets(t, "Wrong#pass-1", suggested)
	out = captureStdout(t, func() { decrypt(input("1")) })
	if !strings.Contains(out, "You have a saved record of its password") {
		t.Errorf("saved record not mentioned:\n%s", out)
	}
	if got, err := os.ReadFile(filepath.Join(work, "notes.txt")); err != nil || string(got) != "meeting notes\n" {
		t.Fatalf("decrypted %q, %v\n%s", got, err, out)
	}

	// The password is in no log
	for _, dir := range []string{work, locations.StateDir} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && !strings.HasSuffix(path, ".age") {
				if data, _ := os.ReadFile(path); strings.Contains(string(data), suggested) {
					t.Errorf("password found in %s", path)
				}
			}
			return nil
		})
	}
}

// TestCLIDontSaveRecord declines the record: the password is shown once
// and nothing is saved.
func TestCLIDontSaveRecord(t *testing.T) {
	setupCLI(t, true)
	secrets(t, cliTestPassword, cliTestPassword)
	out := captureStdout(t, func() { encrypt(input("1", "2", "2", "2")) })
	if !strings.Contains(out, "The password is:  "+cliTestPassword) {
		t.Errorf("password not shown once:\n%s", out)
	}
	if recs, _, _ := core.ListPasswordRecords(locations.PasswordsDir); len(recs) != 0 {
		t.Errorf("records saved: %+v", recs)
	}
}

// TestCLIDecryptPasswordAttempts checks three wrong passwords stop the
// decryption without writing anything.
func TestCLIDecryptPasswordAttempts(t *testing.T) {
	work := setupCLI(t, false)
	if err := core.EncryptFileWithPassword("notes.txt", "notes.txt.age", cliTestPassword); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove("notes.txt"); err != nil {
		t.Fatal(err)
	}
	secrets(t, "Wrong#pass-1", "Wrong#pass-2", "Wrong#pass-3", cliTestPassword)
	decrypt(input("1"))
	if core.FileExists(filepath.Join(work, "notes.txt")) {
		t.Fatal("file decrypted after three wrong passwords")
	}
}

// TestCLIDeleteSavedPassword deletes a record after confirming.
func TestCLIDeleteSavedPassword(t *testing.T) {
	setupCLI(t, true)
	keys, _ := core.OwnKeys(keyDir)
	if err := core.EncryptFileWithPassword("notes.txt", "notes.txt.age", cliTestPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := core.SavePasswordRecord(locations.PasswordsDir, keys, []string{"notes.txt.age"}, cliTestPassword, nowForTest()); err != nil {
		t.Fatal(err)
	}

	// Answering "n" keeps it
	savedPasswords(input("1", "2", "n"))
	if recs, _, _ := core.ListPasswordRecords(locations.PasswordsDir); len(recs) != 1 {
		t.Fatal("record deleted without confirmation")
	}
	savedPasswords(input("1", "2", "y"))
	if recs, _, _ := core.ListPasswordRecords(locations.PasswordsDir); len(recs) != 0 {
		t.Errorf("record not deleted: %+v", recs)
	}
}

// TestCLIKeyEncryptionStillWorks checks the key path is unchanged: encrypt
// for a key, then decrypt with it.
func TestCLIKeyEncryptionStillWorks(t *testing.T) {
	work := setupCLI(t, true)
	// File 1, "a key", key 1
	encrypt(input("1", "1", "1"))
	if m, err := core.FileLockMethod("notes.txt.age"); err != nil || m != core.LockedWithKey {
		t.Fatalf("FileLockMethod = %v, %v", m, err)
	}
	if err := os.Remove("notes.txt"); err != nil {
		t.Fatal(err)
	}
	secrets(t, cliKeyPass)
	decrypt(input("1", "1"))
	if got, _ := os.ReadFile(filepath.Join(work, "notes.txt")); string(got) != "meeting notes\n" {
		t.Errorf("decrypted %q", got)
	}
}

// between returns the text in s after start, up to end.
func between(s, start, end string) string {
	_, after, ok := strings.Cut(s, start)
	if !ok {
		return ""
	}
	before, _, _ := strings.Cut(after, end)
	return before
}

// nowForTest is the time used for records made directly in tests.
func nowForTest() time.Time { return time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC) }
