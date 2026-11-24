// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package app

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"age-tool/internal/core"

	"filippo.io/age"
)

// testPass is a valid passphrase used throughout the tests.
const testPass = "correct horse battery"

// pass returns a fresh copy of a passphrase, since workflows zero the
// slices they are given.
func pass(s string) []byte { return []byte(s) }

// newTestService returns a Service whose key store, settings and central
// log live in a temporary folder, plus a separate folder for user files.
func newTestService(t *testing.T) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	loc := core.Locations{
		KeysDir:   filepath.Join(root, "data", "keys"),
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
	}
	s, err := NewWithLocations(loc)
	if err != nil {
		t.Fatal(err)
	}
	// A fixed clock, so receipts are predictable
	s.Now = func() time.Time { return time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC) }
	docs := filepath.Join(root, "docs")
	if err := os.Mkdir(docs, 0700); err != nil {
		t.Fatal(err)
	}
	return s, docs
}

// writeFile creates a file with the given contents.
func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

// generate creates a key pair in the service's key store.
func generate(t *testing.T, s *Service, name string) {
	t.Helper()
	if _, err := s.GenerateKey(name, "", pass(testPass), pass(testPass)); err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
}

// TestEncryptDecryptRoundTrip runs the whole encrypt → decrypt workflow,
// including the overwrite check, both audit logs and the activity view.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	s, docs := newTestService(t)
	if _, err := s.GenerateKey("me", "My key", pass(testPass), pass(testPass)); err != nil {
		t.Fatal(err)
	}

	// The new key appears in both pickers, by nickname
	recips, _ := s.Recipients()
	if !reflect.DeepEqual(recips, []Choice{{File: "me.pub", Name: "My key"}}) {
		t.Errorf("Recipients = %+v", recips)
	}
	ids, _ := s.Identities()
	if !reflect.DeepEqual(ids, []Choice{{File: "me.priv", Name: "My key", Protected: true}}) {
		t.Errorf("Identities = %+v", ids)
	}

	// Encrypt
	input := filepath.Join(docs, "report.txt")
	writeFile(t, input, "secret report")
	res, err := s.Encrypt(input, "me.pub", false)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res.Output != input+".age" || len(res.Warnings) != 0 {
		t.Errorf("Encrypt result = %+v", res)
	}

	// Encrypting again needs overwrite confirmation
	if _, err := s.Encrypt(input, "me.pub", false); !errors.Is(err, ErrOutputExists) {
		t.Errorf("second Encrypt err = %v, want ErrOutputExists", err)
	}
	if _, err := s.Encrypt(input, "me.pub", true); err != nil {
		t.Errorf("Encrypt with overwrite: %v", err)
	}

	// Decrypting would replace report.txt, so that needs confirmation too
	if _, err := s.StartDecrypt(res.Output, "me.priv", false); !errors.Is(err, ErrOutputExists) {
		t.Errorf("StartDecrypt err = %v, want ErrOutputExists", err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	d, err := s.StartDecrypt(res.Output, "me.priv", false)
	if err != nil {
		t.Fatalf("StartDecrypt: %v", err)
	}
	if d.Output() != input || d.AttemptsLeft() != core.MaxPassAttempts {
		t.Errorf("Decryption output %s, attempts left %d", d.Output(), d.AttemptsLeft())
	}

	// The passphrase slice is zeroed once used
	p := pass(testPass)
	dres, err := d.Try(p)
	if err != nil {
		t.Fatalf("Try: %v", err)
	}
	if strings.Trim(string(p), "\x00") != "" {
		t.Error("passphrase was not cleared")
	}
	if got, _ := os.ReadFile(dres.Output); string(got) != "secret report" {
		t.Errorf("decrypted contents = %q", got)
	}
	if _, err := d.Try(pass(testPass)); !errors.Is(err, ErrFinished) {
		t.Errorf("Try after success err = %v, want ErrFinished", err)
	}

	// The local log sits beside the files, and the central log records
	// every transaction with full paths
	if !core.FileExists(filepath.Join(docs, "age-tool.log")) {
		t.Error("local audit log not written")
	}
	entries, skipped, err := s.Activity(0)
	if err != nil || skipped != 0 {
		t.Fatalf("Activity: %v, skipped %d", err, skipped)
	}
	var types []string
	for _, e := range entries {
		types = append(types, e.Type)
	}
	// Newest first: decrypt, encrypt (overwrite), encrypt, key creation
	want := []string{"decrypt", "encrypt", "encrypt", "key-creation"}
	if !reflect.DeepEqual(types, want) {
		t.Errorf("activity types = %v, want %v", types, want)
	}
	if e := entries[0]; e.Source != res.Output || e.Output != input || e.Key != "me.priv" || e.KeyNickname != "My key" {
		t.Errorf("decrypt entry = %+v", e)
	}
	if e := entries[3]; e.KeyName != "me" {
		t.Errorf("key creation entry = %+v", e)
	}
}

// TestPassphraseAttempts checks the three-attempt limit.
func TestPassphraseAttempts(t *testing.T) {
	s, docs := newTestService(t)
	generate(t, s, "me")
	input := filepath.Join(docs, "a.txt")
	writeFile(t, input, "x")
	res, err := s.Encrypt(input, "me.pub", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}

	d, err := s.StartDecrypt(res.Output, "me.priv", false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < core.MaxPassAttempts; i++ {
		if _, err := d.Try(pass("wrong passphrase!")); !errors.Is(err, core.ErrWrongPassphrase) {
			t.Fatalf("attempt %d err = %v, want ErrWrongPassphrase", i, err)
		}
		if left := d.AttemptsLeft(); left != core.MaxPassAttempts-i {
			t.Errorf("after %d attempts, %d left", i, left)
		}
	}
	if _, err := d.Try(pass("wrong passphrase!")); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("last attempt err = %v, want ErrTooManyAttempts", err)
	}
	// Even the right passphrase is refused now
	if _, err := d.Try(pass(testPass)); !errors.Is(err, ErrFinished) {
		t.Errorf("attempt after limit err = %v, want ErrFinished", err)
	}
	if d.AttemptsLeft() != 0 || core.FileExists(input) {
		t.Error("decryption should have ended with no output")
	}
}

// TestDecryptFailures checks a file for someone else's key, a damaged
// file, an unprotected key and a file that isn't .age.
func TestDecryptFailures(t *testing.T) {
	s, docs := newTestService(t)
	generate(t, s, "me")

	// A file encrypted for someone else's key
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(docs, "theirs.txt")
	writeFile(t, src, "not for me")
	if err := core.EncryptFile(src, src+".age", other.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	d, err := s.StartDecrypt(src+".age", "me.priv", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Try(pass(testPass)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("wrong key err = %v, want ErrWrongKey", err)
	}

	// A damaged file: a valid header for my key, then truncated
	mine := filepath.Join(docs, "mine.txt")
	writeFile(t, mine, strings.Repeat("data ", 50000))
	res, err := s.Encrypt(mine, "me.pub", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mine); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(res.Output, 1000); err != nil {
		t.Fatal(err)
	}
	d, err = s.StartDecrypt(res.Output, "me.priv", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Try(pass(testPass)); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("damaged file err = %v, want ErrDecryptFailed", err)
	}
	if core.FileExists(mine) {
		t.Error("damaged file left output behind")
	}

	// An unprotected private key is refused before asking for a passphrase
	open, _ := age.GenerateX25519Identity()
	writeFile(t, filepath.Join(s.KeysDir, "open.priv"), open.String()+"\n")
	if _, err := s.StartDecrypt(res.Output, "open.priv", false); !errors.Is(err, core.ErrKeyNotProtected) {
		t.Errorf("open key err = %v, want ErrKeyNotProtected", err)
	}

	// Not a .age file, a folder, or a key outside the key folder
	if _, err := s.StartDecrypt(filepath.Join(docs, "plain.txt"), "me.priv", false); !errors.Is(err, ErrNotAgeFile) {
		t.Errorf("non-.age err = %v, want ErrNotAgeFile", err)
	}
	if err := os.Mkdir(filepath.Join(docs, "dir.age"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDecrypt(filepath.Join(docs, "dir.age"), "me.priv", false); !errors.Is(err, ErrIsFolder) {
		t.Errorf("folder err = %v, want ErrIsFolder", err)
	}
	if _, err := s.StartDecrypt(res.Output, "../keys/me.priv", false); !errors.Is(err, core.ErrInvalidName) {
		t.Errorf("path key err = %v, want ErrInvalidName", err)
	}
}

// TestEncryptFailures checks inputs Encrypt refuses.
func TestEncryptFailures(t *testing.T) {
	s, docs := newTestService(t)
	generate(t, s, "me")

	already := filepath.Join(docs, "x.age")
	writeFile(t, already, "x")
	if _, err := s.Encrypt(already, "me.pub", false); !errors.Is(err, ErrAlreadyEncrypted) {
		t.Errorf(".age input err = %v, want ErrAlreadyEncrypted", err)
	}
	if _, err := s.Encrypt(docs, "me.pub", false); !errors.Is(err, ErrIsFolder) {
		t.Errorf("folder input err = %v, want ErrIsFolder", err)
	}
	if _, err := s.Encrypt(filepath.Join(docs, "missing.txt"), "me.pub", false); !errors.Is(err, core.ErrFileUnavailable) {
		t.Errorf("missing input err = %v, want ErrFileUnavailable", err)
	}
	plain := filepath.Join(docs, "plain.txt")
	writeFile(t, plain, "x")
	if _, err := s.Encrypt(plain, "nobody.pub", false); !errors.Is(err, core.ErrFileUnavailable) {
		t.Errorf("missing key err = %v, want ErrFileUnavailable", err)
	}
	if _, err := s.Encrypt(plain, "../me.pub", false); !errors.Is(err, core.ErrInvalidName) {
		t.Errorf("path key err = %v, want ErrInvalidName", err)
	}
}

// TestKeyManagement covers generating, protecting, importing, nicknaming,
// exporting, listing and deleting keys.
func TestKeyManagement(t *testing.T) {
	s, docs := newTestService(t)

	// Generating checks the name and both passphrase entries
	cases := []struct {
		name          string
		pass, confirm string
		want          error
	}{
		{"", testPass, testPass, core.ErrInvalidName},
		{"a/b", testPass, testPass, core.ErrInvalidName},
		{"me", testPass, testPass + "x", ErrPassphraseMismatch},
		{"me", "short", "short", core.ErrPassphraseTooShort},
	}
	for _, c := range cases {
		if _, err := s.GenerateKey(c.name, "", pass(c.pass), pass(c.confirm)); !errors.Is(err, c.want) {
			t.Errorf("GenerateKey(%q) err = %v, want %v", c.name, err, c.want)
		}
	}
	generate(t, s, "me")
	if _, err := s.GenerateKey("me", "", pass(testPass), pass(testPass)); !errors.Is(err, core.ErrKeyExists) {
		t.Errorf("duplicate GenerateKey err = %v, want ErrKeyExists", err)
	}

	// Protecting an open key in place makes it usable
	open, _ := age.GenerateX25519Identity()
	writeFile(t, filepath.Join(s.KeysDir, "old.priv"), open.String()+"\n")
	if err := s.ProtectKey("old.priv", pass(testPass), pass("different passphrase")); !errors.Is(err, ErrPassphraseMismatch) {
		t.Errorf("ProtectKey mismatch err = %v", err)
	}
	if err := s.ProtectKey("old.priv", pass(testPass), pass(testPass)); err != nil {
		t.Fatalf("ProtectKey: %v", err)
	}

	// Contacts: a public key is accepted, a private key refused
	contact, _ := age.GenerateX25519Identity()
	if err := s.ImportContact("alice", "Alice Smith", "  "+contact.Recipient().String()+"\n"); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	if err := s.ImportContact("mallory", "", contact.String()); !errors.Is(err, core.ErrIsPrivateKey) {
		t.Errorf("private key import err = %v, want ErrIsPrivateKey", err)
	}
	bobFile := filepath.Join(docs, "bob.pub")
	writeFile(t, bobFile, "# created by age-keygen\n"+open.Recipient().String()+"\n")
	if err := s.ImportContactFile("bob", "", bobFile); err != nil {
		t.Errorf("ImportContactFile: %v", err)
	}

	if err := s.SetNickname("me.priv", "Laptop key"); err != nil {
		t.Fatal(err)
	}

	keys, err := s.Keys()
	if err != nil {
		t.Fatal(err)
	}
	want := []Key{
		{Base: "alice", Name: "Alice Smith", PubFile: "alice.pub", PubNickname: "Alice Smith", Contact: true},
		{Base: "bob", Name: "bob", PubFile: "bob.pub", Contact: true},
		{Base: "me", Name: "Laptop key", PubFile: "me.pub", PrivFile: "me.priv", PrivNickname: "Laptop key", Protected: true},
		{Base: "old", Name: "old", PrivFile: "old.priv", Protected: true},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("Keys =\n%+v\nwant\n%+v", keys, want)
	}

	// Sharing a public key
	text, err := s.PublicKeyText("alice.pub")
	if err != nil || text != contact.Recipient().String() {
		t.Errorf("PublicKeyText = %q, %v", text, err)
	}
	dest := filepath.Join(docs, "alice-copy.pub")
	if err := s.ExportPublicKey("alice.pub", dest); err != nil {
		t.Errorf("ExportPublicKey: %v", err)
	}
	if err := s.ExportPublicKey("alice.pub", dest); err == nil {
		t.Error("ExportPublicKey overwrote an existing file")
	}

	// Deleting removes both files and their nicknames
	if err := s.DeleteKey("me"); err != nil {
		t.Fatal(err)
	}
	if core.KeyPairExists(s.KeysDir, "me") {
		t.Error("key files not deleted")
	}
	if _, ok := core.LoadNicknames(filepath.Join(s.KeysDir, core.NicknameFileName))["me.priv"]; ok {
		t.Error("nickname not removed")
	}
	if err := s.DeleteKey("../me"); !errors.Is(err, core.ErrInvalidName) {
		t.Errorf("DeleteKey path err = %v, want ErrInvalidName", err)
	}
}

// TestMessage checks that errors map to plain language, including core
// errors that keep their own text for the CLI, and never leak Go text.
func TestMessage(t *testing.T) {
	_, nameErr := core.SanitiseInput(strings.Repeat("x", core.MaxInputLength+1))
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{ErrOutputExists, "already exists"},
		{core.ErrWrongPassphrase, "incorrect"},
		{core.ValidateFilename("a/b"), "simple name"},
		{nameErr, "simple name"},
		{core.ValidateNewPassphrase("short"), "at least 12"},
		{core.ValidatePrivKeyFile("/no/such/file.priv"), "couldn't be opened"},
		{func() error { _, err := core.ParsePublicKey("AGE-SECRET-KEY-1ABC"); return err }(), "private key"},
		{func() error { _, err := core.ParsePublicKey("hello"); return err }(), "valid public key"},
		{func() error { _, err := os.Open("/no/such/file"); return err }(), "couldn't be found"},
		{errors.New("open /tmp/x: some internal failure"), "Something went wrong"},
	}
	for _, c := range cases {
		got := Message(c.err)
		if !strings.Contains(got, c.want) {
			t.Errorf("Message(%v) = %q, want it to contain %q", c.err, got, c.want)
		}
	}
	if AttemptsMessage(1) != "That passphrase is incorrect. 1 attempt left." {
		t.Errorf("AttemptsMessage(1) = %q", AttemptsMessage(1))
	}
}

// TestParseLaunch checks the command-line forms the desktop integration uses.
func TestParseLaunch(t *testing.T) {
	cases := []struct {
		args    []string
		want    Launch
		wantErr bool
	}{
		{nil, Launch{Action: ActionHome}, false},
		{[]string{"--help"}, Launch{Action: ActionHelp}, false},
		{[]string{"-h"}, Launch{Action: ActionHelp}, false},
		{[]string{"--version"}, Launch{Action: ActionVersion}, false},
		{[]string{"--install-desktop"}, Launch{Action: ActionInstallDesktop}, false},
		{[]string{"--remove-desktop"}, Launch{Action: ActionRemoveDesktop}, false},
		{[]string{"encrypt", "a.txt", "b.pdf"}, Launch{Action: ActionEncrypt, Files: []string{"a.txt", "b.pdf"}}, false},
		{[]string{"decrypt", "a.txt.age"}, Launch{Action: ActionDecrypt, Files: []string{"a.txt.age"}}, false},
		{[]string{"encrypt", "--", "-odd.txt"}, Launch{Action: ActionEncrypt, Files: []string{"-odd.txt"}}, false},
		{[]string{"a.txt.age", "b.age"}, Launch{Action: ActionDecrypt, Files: []string{"a.txt.age", "b.age"}}, false},
		{[]string{"/home/me/report.pdf"}, Launch{Action: ActionEncrypt, Files: []string{"/home/me/report.pdf"}}, false},
		{[]string{"--", "-odd.txt"}, Launch{Action: ActionEncrypt, Files: []string{"-odd.txt"}}, false},
		{[]string{"encrypt"}, Launch{}, true},
		{[]string{"decrypt", "--"}, Launch{}, true},
		{[]string{"a.txt", "b.age"}, Launch{}, true},
		{[]string{"--bogus"}, Launch{}, true},
	}
	for _, c := range cases {
		got, err := ParseLaunch(c.args)
		if (err != nil) != c.wantErr || !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseLaunch(%q) = %+v, %v; want %+v, error %v", c.args, got, err, c.want, c.wantErr)
		}
	}
}
