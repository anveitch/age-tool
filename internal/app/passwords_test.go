// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"age-tool/internal/core"
)

// appFilePassword is a file password that meets the default rules.
const appFilePassword = "Tr4vel#Bus-ride"

// TestPasswordWorkflow runs encrypt with a password → save a record →
// decrypt (with a wrong try first) → open the record, through the Service.
func TestPasswordWorkflow(t *testing.T) {
	s, docs := newTestService(t)
	generate(t, s, "laptop")
	input := filepath.Join(docs, "notes.txt")
	writeFile(t, input, "meeting notes")

	// Rules and suggestions
	if err := s.CheckNewPassword(appFilePassword, "different"); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("mismatch: %v", err)
	}
	if err := s.CheckNewPassword("Summer26!", "Summer26!"); !errors.Is(err, core.ErrPasswordTooWeak) {
		t.Errorf("weak password: %v", err)
	}
	suggestion, err := s.SuggestPassword()
	if err != nil || s.CheckNewPassword(suggestion, suggestion) != nil {
		t.Errorf("suggestion %q: %v", suggestion, err)
	}

	// Encrypt, with the overwrite check
	res, err := s.EncryptWithPassword(input, appFilePassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EncryptWithPassword(input, appFilePassword, false); !errors.Is(err, ErrOutputExists) {
		t.Errorf("second encrypt: %v, want ErrOutputExists", err)
	}
	if m, err := s.LockMethod(res.Output); err != nil || m != core.LockedWithPassword {
		t.Fatalf("LockMethod = %v, %v", m, err)
	}

	// Save a record
	if !s.CanSavePasswordRecords() {
		t.Fatal("CanSavePasswordRecords false with a key")
	}
	names, err := s.SavePasswordRecord([]string{res.Output}, appFilePassword)
	if err != nil || len(names) != 1 || names[0] != "laptop" {
		t.Fatalf("SavePasswordRecord = %v, %v", names, err)
	}
	if !s.HasPasswordRecord(res.Output) {
		t.Error("HasPasswordRecord false after saving")
	}

	// Decrypt, after one wrong password
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	d, err := s.StartPasswordDecrypt(res.Output, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Try(pass("Wrong#pass-1")); !errors.Is(err, core.ErrWrongPassword) || d.AttemptsLeft() != 2 {
		t.Fatalf("wrong password: %v, %d left", err, d.AttemptsLeft())
	}
	out, err := d.Try(pass(appFilePassword))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out.Output); string(got) != "meeting notes" {
		t.Errorf("decrypted %q", got)
	}
	if _, err := d.Try(pass(appFilePassword)); !errors.Is(err, ErrFinished) {
		t.Errorf("Try after success: %v", err)
	}

	// Activity shows both, as password transactions
	entries, _, err := s.Activity(0)
	if err != nil {
		t.Fatal(err)
	}
	methods := 0
	for _, e := range entries {
		if e.Method == core.MethodPassword {
			methods++
		}
	}
	if methods != 2 {
		t.Errorf("%d password entries in activity, want 2", methods)
	}

	// Open the record with the key
	recs, _, err := s.PasswordRecords()
	if err != nil || len(recs) != 1 {
		t.Fatalf("PasswordRecords = %v, %v", recs, err)
	}
	keys, err := s.RecordKeys(recs[0])
	if err != nil || len(keys) != 1 || keys[0].File != "laptop.priv" || !keys[0].Protected {
		t.Fatalf("RecordKeys = %+v, %v", keys, err)
	}
	o, err := s.StartOpenRecord(recs[0], keys[0].File)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Try(pass("wrong passphrase!")); !errors.Is(err, core.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	pw, rec, err := o.Try(pass(testPass))
	if err != nil || pw != appFilePassword || len(rec.Files) != 1 {
		t.Fatalf("open record = %q, %+v, %v", pw, rec, err)
	}

	// Delete it
	if err := s.DeletePasswordRecord(recs[0].ID); err != nil {
		t.Fatal(err)
	}
	if recs, _, _ := s.PasswordRecords(); len(recs) != 0 {
		t.Errorf("records left: %+v", recs)
	}
}

// TestPasswordWorkflowLimits checks three wrong passwords, key files
// offered to the password path, and saving without a key of one's own.
func TestPasswordWorkflowLimits(t *testing.T) {
	s, docs := newTestService(t)
	input := filepath.Join(docs, "notes.txt")
	writeFile(t, input, "notes")
	res, err := s.EncryptWithPassword(input, appFilePassword, false)
	if err != nil {
		t.Fatal(err)
	}

	// No own key: records can't be saved, and the folder isn't created
	if s.CanSavePasswordRecords() {
		t.Error("CanSavePasswordRecords true without a key")
	}
	if _, err := s.SavePasswordRecord([]string{res.Output}, appFilePassword); !errors.Is(err, core.ErrNoOwnKey) {
		t.Errorf("save without key: %v", err)
	}
	if _, err := os.Stat(s.Locations.PasswordsDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("passwords folder created without a record")
	}
	if !strings.HasPrefix(s.Locations.PasswordsDir, filepath.Dir(s.KeysDir)) {
		t.Errorf("passwords folder %q isn't beside the keys", s.Locations.PasswordsDir)
	}

	// Three wrong passwords: no output
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	d, err := s.StartPasswordDecrypt(res.Output, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		_, err = d.Try(pass("Wrong#pass-1"))
	}
	if !errors.Is(err, ErrTooManyPasswordAttempts) || core.FileExists(input) {
		t.Errorf("after three wrong passwords: %v, output exists %v", err, core.FileExists(input))
	}

	// A key-locked file isn't offered a password
	generate(t, s, "laptop")
	writeFile(t, input, "notes")
	keyRes, err := s.Encrypt(input, "laptop.pub", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartPasswordDecrypt(keyRes.Output, true); !errors.Is(err, ErrNotPasswordFile) {
		t.Errorf("key file: %v, want ErrNotPasswordFile", err)
	}

	// Weak passwords are refused at encryption too
	if _, err := s.EncryptWithPassword(input, "Summer26!", true); !errors.Is(err, core.ErrPasswordTooWeak) {
		t.Errorf("weak password encrypted: %v", err)
	}
}

// TestPasswordMessages checks the new errors have plain-language messages.
func TestPasswordMessages(t *testing.T) {
	for _, err := range []error{core.ErrWrongPassword, ErrTooManyPasswordAttempts, ErrNotPasswordFile,
		ErrPasswordMismatch, core.ErrNoOwnKey, core.ErrRecordNotForKey, core.ErrRecordNotFound, core.ErrRecordDamaged} {
		if m := Message(err); m == "Something went wrong. Please try again." {
			t.Errorf("no message for %v", err)
		}
	}
	weak := core.DefaultPasswordRules.CheckPassword("abc")
	if got := PasswordProblem(weak); !strings.HasPrefix(got, "Password must use at least 8 characters") {
		t.Errorf("PasswordProblem = %q", got)
	}
	if got := PasswordAttemptsMessage(1); got != "That password is incorrect. 1 attempt left." {
		t.Errorf("PasswordAttemptsMessage(1) = %q", got)
	}
}
