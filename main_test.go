// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// ─── Input validation ───────────────────────────────────────────────────────

// TestValidateFilename checks that only simple filenames in the current
// directory are accepted.
func TestValidateFilename(t *testing.T) {
	cases := map[string]bool{ // name -> should be accepted
		"work":          true,
		"my-key_2.pub":  true,
		"":              false,
		"../etc/passwd": false,
		"..":            false,
		"/etc/passwd":   false,
		"sub/dir":       false,
		`sub\dir`:       false,
		"a..b":          false, // conservative: any ".." is rejected
	}
	for name, want := range cases {
		err := validateFilename(name)
		if got := err == nil; got != want {
			t.Errorf("validateFilename(%q): accepted=%v, want %v (err=%v)", name, got, want, err)
		}
	}
}

// TestSanitiseInput checks whitespace trimming and the length limit.
func TestSanitiseInput(t *testing.T) {
	got, err := sanitiseInput("  hello \n")
	if err != nil || got != "hello" {
		t.Errorf("sanitiseInput trim: got %q, %v", got, err)
	}
	if _, err := sanitiseInput(strings.Repeat("a", maxInputLength)); err != nil {
		t.Errorf("input at the limit should be accepted: %v", err)
	}
	if _, err := sanitiseInput(strings.Repeat("a", maxInputLength+1)); err == nil {
		t.Error("input over the limit should be rejected")
	}
}

// TestIsWeakPassphrase covers the weak-pattern checks, including multibyte
// characters, which were previously compared byte-by-byte.
func TestIsWeakPassphrase(t *testing.T) {
	cases := map[string]bool{ // passphrase -> expect a warning
		"aaaaaaaaaaaa":          true,
		"ššššššššššššš":         true,  // multibyte, all the same character
		"aššššššššššš":          false, // previously a false warning (byte('š') == 'a')
		"šaaaaaaaaaaa":          false, // previously sliced mid-character
		"123456789012":          true,
		"abcdefghijklm":         true,
		"password":              true,
		"correct horse battery": false,
	}
	for pass, want := range cases {
		if got := isWeakPassphrase(pass) != ""; got != want {
			t.Errorf("isWeakPassphrase(%q): warned=%v, want %v", pass, got, want)
		}
	}
}

// TestShortHash checks the log helper never panics on short input.
func TestShortHash(t *testing.T) {
	full := strings.Repeat("ab", 32)
	if got := shortHash(full); got != full[:16] {
		t.Errorf("shortHash(full) = %q", got)
	}
	for _, h := range []string{"", "abc"} {
		if got := shortHash(h); got != "unavailable" {
			t.Errorf("shortHash(%q) = %q, want unavailable", h, got)
		}
	}
}

// TestExtractSecretKey finds the key line and skips comments.
func TestExtractSecretKey(t *testing.T) {
	data := "# created: 2026-01-01\n# public key: age1xyz\nAGE-SECRET-KEY-1ABC\n"
	if got := extractSecretKey(data); got != "AGE-SECRET-KEY-1ABC" {
		t.Errorf("extractSecretKey = %q", got)
	}
	if got := extractSecretKey("# nothing here\n"); got != "" {
		t.Errorf("extractSecretKey with no key = %q, want empty", got)
	}
}

// ─── File encryption / decryption ───────────────────────────────────────────

// newIdentity generates a fresh X25519 key pair for a test.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// assertNoPartialFiles fails if any in-progress output file was left behind.
func assertNoPartialFiles(t *testing.T) {
	t.Helper()
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), partialFilePrefix) {
			t.Errorf("leftover partial file: %s", e.Name())
		}
	}
}

// TestEncryptDecryptRoundTrip encrypts and decrypts a file and checks the
// contents match and outputs are owner-only.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Chdir(t.TempDir())
	id := newIdentity(t)
	plaintext := []byte("top secret payload\n")
	if err := os.WriteFile("msg.txt", plaintext, 0600); err != nil {
		t.Fatal(err)
	}

	if err := encryptFile("msg.txt", "msg.txt.age", id.Recipient()); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}
	if err := decryptFile("msg.txt.age", "out.txt", id); err != nil {
		t.Fatalf("decryptFile: %v", err)
	}

	got, _ := os.ReadFile("out.txt")
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip mismatch: got %q", got)
	}
	for _, f := range []string{"msg.txt.age", "out.txt"} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0600 {
			t.Errorf("%s: want 0600, got %v (err=%v)", f, fi.Mode().Perm(), err)
		}
	}
	assertNoPartialFiles(t)
}

// TestDecryptCorruptedLeavesExistingFileIntact corrupts a later chunk of a
// multi-chunk ciphertext. Decryption fails part-way through, and the
// existing output file must be untouched with no partial file left behind.
func TestDecryptCorruptedLeavesExistingFileIntact(t *testing.T) {
	t.Chdir(t.TempDir())
	id := newIdentity(t)

	// 200 KiB spans several 64 KiB age chunks
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 200*1024/16)
	os.WriteFile("big.bin", plaintext, 0600)
	if err := encryptFile("big.bin", "big.bin.age", id.Recipient()); err != nil {
		t.Fatal(err)
	}

	// Flip a byte near the end, well past the first chunk
	ct, _ := os.ReadFile("big.bin.age")
	ct[len(ct)-100] ^= 0xFF
	os.WriteFile("big.bin.age", ct, 0600)

	// An existing file with the output name must survive the failure
	os.WriteFile("out.bin", []byte("original"), 0600)

	if err := decryptFile("big.bin.age", "out.bin", id); err == nil {
		t.Fatal("decrypting corrupted ciphertext should fail")
	}
	if got, _ := os.ReadFile("out.bin"); string(got) != "original" {
		t.Errorf("existing output was modified: %d bytes", len(got))
	}
	assertNoPartialFiles(t)
}

// TestDecryptWrongKeyCreatesNoOutput checks that using the wrong key fails
// before any output file is created.
func TestDecryptWrongKeyCreatesNoOutput(t *testing.T) {
	t.Chdir(t.TempDir())
	os.WriteFile("msg.txt", []byte("hello"), 0600)
	if err := encryptFile("msg.txt", "msg.txt.age", newIdentity(t).Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := decryptFile("msg.txt.age", "out.txt", newIdentity(t)); err == nil {
		t.Fatal("decrypting with the wrong key should fail")
	}
	if fileExists("out.txt") {
		t.Error("output file should not be created")
	}
	assertNoPartialFiles(t)
}

// ─── Passphrase-protected private keys ──────────────────────────────────────

// TestPrivateKeyPassphraseRoundTrip writes a passphrase-protected key and
// unlocks it in memory, with the right and wrong passphrase.
func TestPrivateKeyPassphraseRoundTrip(t *testing.T) {
	t.Chdir(t.TempDir())
	id := newIdentity(t)
	const pass = "correct horse battery staple"

	if err := writeEncryptedPrivateKey("k.priv", id.String(), pass); err != nil {
		t.Fatal(err)
	}
	if enc, err := isAgeEncrypted("k.priv"); err != nil || !enc {
		t.Fatalf("key should be age-encrypted: %v %v", enc, err)
	}
	if fi, _ := os.Stat("k.priv"); fi.Mode().Perm() != 0600 {
		t.Errorf("k.priv perms = %v, want 0600", fi.Mode().Perm())
	}

	// Right passphrase: the unlocked identity decrypts data for the key
	got, err := decryptKeyIdentity("k.priv", pass)
	if err != nil {
		t.Fatalf("decryptKeyIdentity: %v", err)
	}
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, id.Recipient())
	w.Write([]byte("ping"))
	w.Close()
	if _, err := age.Decrypt(&buf, got); err != nil {
		t.Errorf("unlocked identity can't decrypt: %v", err)
	}

	// Wrong passphrase: a retryable error
	if _, err := decryptKeyIdentity("k.priv", "wrong passphrase here"); !errors.Is(err, errWrongPassphrase) {
		t.Errorf("wrong passphrase: got %v, want errWrongPassphrase", err)
	}
}

// ─── Nicknames ──────────────────────────────────────────────────────────────

// TestSaveNicknamesTightensPermissions checks keys.json round-trips and an
// existing world-readable file is tightened to 0600.
func TestSaveNicknamesTightensPermissions(t *testing.T) {
	t.Chdir(t.TempDir())
	os.WriteFile(nicknameFile, []byte("{}\n"), 0644)

	if err := saveNicknames(map[string]string{"a.pub": "Alpha"}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(nicknameFile); fi.Mode().Perm() != 0600 {
		t.Errorf("keys.json perms = %v, want 0600", fi.Mode().Perm())
	}
	if got := loadNicknames()["a.pub"]; got != "Alpha" {
		t.Errorf("loadNicknames: got %q", got)
	}
}
