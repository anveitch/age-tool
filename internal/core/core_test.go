// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		err := ValidateFilename(name)
		if got := err == nil; got != want {
			t.Errorf("ValidateFilename(%q): accepted=%v, want %v (err=%v)", name, got, want, err)
		}
	}
}

// TestSanitiseInput checks whitespace trimming and the length limit.
func TestSanitiseInput(t *testing.T) {
	got, err := SanitiseInput("  hello \n")
	if err != nil || got != "hello" {
		t.Errorf("sanitiseInput trim: got %q, %v", got, err)
	}
	if _, err := SanitiseInput(strings.Repeat("a", MaxInputLength)); err != nil {
		t.Errorf("input at the limit should be accepted: %v", err)
	}
	if _, err := SanitiseInput(strings.Repeat("a", MaxInputLength+1)); err == nil {
		t.Error("input over the limit should be rejected")
	}
}

// TestPassphraseWarning covers the weak-pattern checks, including multibyte
// characters, which were previously compared byte-by-byte.
func TestPassphraseWarning(t *testing.T) {
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
		if got := PassphraseWarning(pass) != ""; got != want {
			t.Errorf("PassphraseWarning(%q): warned=%v, want %v", pass, got, want)
		}
	}
}

// TestShortHash checks the log helper never panics on short input.
func TestShortHash(t *testing.T) {
	full := strings.Repeat("ab", 32)
	if got := ShortHash(full); got != full[:16] {
		t.Errorf("ShortHash(full) = %q", got)
	}
	for _, h := range []string{"", "abc"} {
		if got := ShortHash(h); got != "unavailable" {
			t.Errorf("ShortHash(%q) = %q, want unavailable", h, got)
		}
	}
}

// TestExtractSecretKey finds the key line and skips comments.
func TestExtractSecretKey(t *testing.T) {
	data := "# created: 2026-01-01\n# public key: age1xyz\nAGE-SECRET-KEY-1ABC\n"
	if got := ExtractSecretKey(data); got != "AGE-SECRET-KEY-1ABC" {
		t.Errorf("extractSecretKey = %q", got)
	}
	if got := ExtractSecretKey("# nothing here\n"); got != "" {
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
		if strings.HasPrefix(e.Name(), PartialFilePrefix) {
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

	if err := EncryptFile("msg.txt", "msg.txt.age", id.Recipient()); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}
	if err := DecryptFile("msg.txt.age", "out.txt", id); err != nil {
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
	if err := EncryptFile("big.bin", "big.bin.age", id.Recipient()); err != nil {
		t.Fatal(err)
	}

	// Flip a byte near the end, well past the first chunk
	ct, _ := os.ReadFile("big.bin.age")
	ct[len(ct)-100] ^= 0xFF
	os.WriteFile("big.bin.age", ct, 0600)

	// An existing file with the output name must survive the failure
	os.WriteFile("out.bin", []byte("original"), 0600)

	if err := DecryptFile("big.bin.age", "out.bin", id); err == nil {
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
	if err := EncryptFile("msg.txt", "msg.txt.age", newIdentity(t).Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile("msg.txt.age", "out.txt", newIdentity(t)); err == nil {
		t.Fatal("decrypting with the wrong key should fail")
	}
	if FileExists("out.txt") {
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

	if err := WritePassphraseProtectedKey("k.priv", id.String(), pass); err != nil {
		t.Fatal(err)
	}
	if enc, err := IsAgeEncrypted("k.priv"); err != nil || !enc {
		t.Fatalf("key should be age-encrypted: %v %v", enc, err)
	}
	if fi, _ := os.Stat("k.priv"); fi.Mode().Perm() != 0600 {
		t.Errorf("k.priv perms = %v, want 0600", fi.Mode().Perm())
	}

	// Right passphrase: the unlocked identity decrypts data for the key
	got, err := UnlockIdentity("k.priv", pass)
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
	if _, err := UnlockIdentity("k.priv", "wrong passphrase here"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: got %v, want ErrWrongPassphrase", err)
	}
}

// ─── Nicknames ──────────────────────────────────────────────────────────────

// TestSaveNicknamesTightensPermissions checks keys.json round-trips and an
// existing world-readable file is tightened to 0600.
func TestSaveNicknamesTightensPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	os.WriteFile(path, []byte("{}\n"), 0644)

	if err := (Nicknames{"a.pub": "Alpha"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("keys.json perms = %v, want 0600", fi.Mode().Perm())
	}
	if got := LoadNicknames(path)["a.pub"]; got != "Alpha" {
		t.Errorf("LoadNicknames: got %q", got)
	}
}

// TestLoadNicknamesMissingOrInvalid returns a usable empty map rather than
// nil for a missing file, invalid JSON, or a JSON "null".
func TestLoadNicknamesMissingOrInvalid(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	null := filepath.Join(dir, "null.json")
	os.WriteFile(bad, []byte("{not json"), 0600)
	os.WriteFile(null, []byte("null"), 0600)

	for _, path := range []string{filepath.Join(dir, "missing.json"), bad, null} {
		n := LoadNicknames(path)
		if n == nil {
			t.Fatalf("%s: got nil map", filepath.Base(path))
		}
		n["x"] = "y" // must not panic
	}
}

// TestNicknameLabel formats keys with and without nicknames.
func TestNicknameLabel(t *testing.T) {
	n := Nicknames{"work.pub": "Work"}
	if got := n.Label("work.pub"); got != "Work (work.pub)" {
		t.Errorf("Label with nickname = %q", got)
	}
	if got := n.Label("home.pub"); got != "home.pub" {
		t.Errorf("Label without nickname = %q", got)
	}
}

// ─── Key generation, listing and deletion ───────────────────────────────────

// TestGenerateKeyPair creates a pair in a directory other than the current
// one and checks permissions, that the key unlocks, and that it can't be
// created twice.
func TestGenerateKeyPair(t *testing.T) {
	dir := t.TempDir()
	const pass = "correct horse battery staple"

	pubPath, privPath, err := GenerateKeyPair(dir, "work", pass)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pubPath != filepath.Join(dir, "work.pub") || privPath != filepath.Join(dir, "work.priv") {
		t.Errorf("unexpected paths %q %q", pubPath, privPath)
	}
	for _, p := range []string{pubPath, privPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0600 {
			t.Errorf("%s: want 0600 (err=%v)", filepath.Base(p), err)
		}
	}

	// The private key unlocks and matches the public key
	id, err := UnlockIdentity(privPath, pass)
	if err != nil {
		t.Fatalf("UnlockIdentity: %v", err)
	}
	r, err := ReadRecipient(pubPath)
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, r)
	w.Write([]byte("ping"))
	w.Close()
	if _, err := age.Decrypt(&buf, id); err != nil {
		t.Errorf("generated keys don't match: %v", err)
	}

	// A second pair with the same name is refused
	if _, _, err := GenerateKeyPair(dir, "work", pass); !errors.Is(err, ErrKeyExists) {
		t.Errorf("duplicate name: got %v, want ErrKeyExists", err)
	}
}

// TestGenerateKeyPairRejectsBadInput refuses unsafe names and short
// passphrases without creating any files.
func TestGenerateKeyPairRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := GenerateKeyPair(dir, "../escape", "correct horse battery"); err == nil {
		t.Error("path traversal name should be rejected")
	}
	if _, _, err := GenerateKeyPair(dir, "short", "tooshort"); err == nil {
		t.Error("short passphrase should be rejected")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("no files should be created, found %d", len(entries))
	}
}

// TestListKeyPairsAndStatusChecks covers grouping, sorting, detection of
// open (unprotected) private keys, and loose permissions.
func TestListKeyPairsAndStatusChecks(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)

	// b: full protected pair; a: public only; c: open private key, 0644
	os.WriteFile(filepath.Join(dir, "b.pub"), []byte(id.Recipient().String()+"\n"), 0600)
	WritePassphraseProtectedKey(filepath.Join(dir, "b.priv"), id.String(), "correct horse battery")
	os.WriteFile(filepath.Join(dir, "a.pub"), []byte(id.Recipient().String()+"\n"), 0600)
	os.WriteFile(filepath.Join(dir, "c.priv"), []byte(id.String()+"\n"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0600)

	pairs, err := ListKeyPairs(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []KeyPair{
		{Base: "a", PubFile: "a.pub"},
		{Base: "b", PubFile: "b.pub", PrivFile: "b.priv"},
		{Base: "c", PrivFile: "c.priv"},
	}
	if len(pairs) != len(want) {
		t.Fatalf("got %d pairs, want %d: %+v", len(pairs), len(want), pairs)
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Errorf("pair %d = %+v, want %+v", i, pairs[i], want[i])
		}
	}

	if open, _ := OpenPrivateKeys(dir); len(open) != 1 || open[0] != "c.priv" {
		t.Errorf("OpenPrivateKeys = %v, want [c.priv]", open)
	}
	if bad, _ := PermissiveKeyFiles(dir); len(bad) != 1 || bad[0] != "c.priv" {
		t.Errorf("PermissiveKeyFiles = %v, want [c.priv]", bad)
	}
	if err := FixKeyPermissions(filepath.Join(dir, "c.priv")); err != nil {
		t.Fatal(err)
	}
	if bad, _ := PermissiveKeyFiles(dir); len(bad) != 0 {
		t.Errorf("after fix, PermissiveKeyFiles = %v", bad)
	}
}

// TestProtectOpenKeyInPlace reads an open private key and protects it in
// place, which must also tighten an existing loose file to 0600.
func TestProtectOpenKeyInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.priv")
	id := newIdentity(t)
	os.WriteFile(path, []byte("# created by age-keygen\n"+id.String()+"\n"), 0644)

	secret, err := ReadOpenSecretKey(path)
	if err != nil || secret != id.String() {
		t.Fatalf("ReadOpenSecretKey = %q, %v", secret, err)
	}
	if err := WritePassphraseProtectedKey(path, secret, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("protected key perms = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := UnlockIdentity(path, "correct horse battery"); err != nil {
		t.Errorf("protected key doesn't unlock: %v", err)
	}

	// A file with no secret key is reported
	empty := filepath.Join(t.TempDir(), "empty.priv")
	os.WriteFile(empty, []byte("# nothing\n"), 0600)
	if _, err := ReadOpenSecretKey(empty); err == nil {
		t.Error("file without AGE-SECRET-KEY should fail")
	}
}

// TestDeleteKeyPair removes both files and their nicknames, and copes with
// a pair that only has one file.
func TestDeleteKeyPair(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "k.pub"), []byte("x"), 0600)
	os.WriteFile(filepath.Join(dir, "k.priv"), []byte("x"), 0600)
	os.WriteFile(filepath.Join(dir, "solo.pub"), []byte("x"), 0600)
	nicks := Nicknames{"k.pub": "K", "k.priv": "K priv", "solo.pub": "Solo"}

	deleted, failed := DeleteKeyPair(dir, "k", nicks)
	if len(deleted) != 2 || len(failed) != 0 {
		t.Errorf("deleted=%v failed=%v", deleted, failed)
	}
	if FileExists(filepath.Join(dir, "k.pub")) || FileExists(filepath.Join(dir, "k.priv")) {
		t.Error("key files still exist")
	}
	if _, ok := nicks["k.pub"]; ok {
		t.Error("nickname for k.pub not removed")
	}
	if nicks["solo.pub"] != "Solo" {
		t.Error("unrelated nickname was removed")
	}

	if deleted, _ := DeleteKeyPair(dir, "solo", nicks); len(deleted) != 1 || deleted[0] != "solo.pub" {
		t.Errorf("solo: deleted=%v", deleted)
	}
}

// ─── Output paths and leftovers ─────────────────────────────────────────────

// TestOutputPaths checks the .age naming convention both ways.
func TestOutputPaths(t *testing.T) {
	if got := EncryptedOutputPath("doc.txt"); got != "doc.txt.age" {
		t.Errorf("EncryptedOutputPath = %q", got)
	}
	if got := DecryptedOutputPath("doc.txt.age"); got != "doc.txt" {
		t.Errorf("DecryptedOutputPath = %q", got)
	}
}

// TestEncryptIntoOtherDirectory writes output outside the current
// directory; the temp file must be created beside the output so the final
// rename stays atomic, and nothing is left behind in either place.
func TestEncryptIntoOtherDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	outDir := t.TempDir()
	id := newIdentity(t)
	os.WriteFile("in.txt", []byte("data"), 0600)

	out := filepath.Join(outDir, "in.txt.age")
	if err := EncryptFile("in.txt", out, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if !FileExists(out) {
		t.Fatal("output not created")
	}
	for _, dir := range []string{".", outDir} {
		if left, _ := FindLeftoverTempFiles(dir); len(left) != 0 {
			t.Errorf("leftover temp files in %s: %v", dir, left)
		}
	}
}

// TestFindLeftoverTempFiles detects legacy temp keys and partial output.
func TestFindLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".tmpkey-abc", ".age-tool-partial-123", "normal.txt", ".hidden"} {
		os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600)
	}
	left, err := FindLeftoverTempFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 {
		t.Errorf("FindLeftoverTempFiles = %v, want the 2 temp files", left)
	}
}

// ─── Audit log ──────────────────────────────────────────────────────────────

// TestAuditLogRecords writes one of each transaction type and checks the
// log line, the receipt contents, the permissions, and that nothing
// secret is recorded.
func TestAuditLogRecords(t *testing.T) {
	t.Chdir(t.TempDir())
	const pass = "correct horse battery staple"
	a := AuditLog{LogFile: "age-tool.log", ReceiptsDir: "logs"}
	ts := time.Date(2026, 4, 9, 14, 30, 22, 0, time.Local)

	pubPath, privPath, err := GenerateKeyPair(".", "k", pass)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile("doc.txt", []byte("hello"), 0600)
	r, _ := ReadRecipient(pubPath)
	EncryptFile("doc.txt", "doc.txt.age", r)

	for _, warnings := range [][]error{
		a.RecordKeyCreation(ts, "k", pubPath, privPath),
		a.RecordEncrypt(ts, "doc.txt", "doc.txt.age", "k.pub", "Work"),
		a.RecordDecrypt(ts.Add(time.Second), "doc.txt.age", "doc.txt", "k.priv", ""),
	} {
		if len(warnings) != 0 {
			t.Errorf("unexpected warnings: %v", warnings)
		}
	}

	// Running log: three lines in the expected format
	logData, _ := os.ReadFile("age-tool.log")
	lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d log lines, want 3:\n%s", len(lines), logData)
	}
	if !strings.HasPrefix(lines[1], "[2026-04-09 14:30:22] ENCRYPT: doc.txt -> doc.txt.age | key: Work (k.pub) | src-sha256: ") {
		t.Errorf("encrypt line = %q", lines[1])
	}
	if strings.Contains(lines[1], "unavailable") {
		t.Errorf("hashes missing from encrypt line: %q", lines[1])
	}

	// Receipts: one per transaction, owner-only, with the right content
	if fi, _ := os.Stat("logs"); fi.Mode().Perm() != 0700 {
		t.Errorf("logs dir perms = %v, want 0700", fi.Mode().Perm())
	}
	receipt := filepath.Join("logs", "encrypt-2026-04-09-143022.json")
	if fi, err := os.Stat(receipt); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("receipt missing or wrong perms: %v", err)
	}
	var fields map[string]string
	data, _ := os.ReadFile(receipt)
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256([]byte("hello"))
	if fields["source_sha256"] != hex.EncodeToString(wantSHA[:]) || fields["key_nickname"] != "Work" {
		t.Errorf("receipt fields = %v", fields)
	}

	// Nothing secret anywhere in the logs
	all := string(logData)
	entries, _ := os.ReadDir("logs")
	for _, e := range entries {
		d, _ := os.ReadFile(filepath.Join("logs", e.Name()))
		all += string(d)
	}
	if strings.Contains(all, pass) || strings.Contains(all, "AGE-SECRET-KEY") {
		t.Error("audit log contains secret material")
	}
}

// TestAuditLogWarnings reports, rather than fails on, an unwritable log.
func TestAuditLogWarnings(t *testing.T) {
	dir := t.TempDir()
	// A file where the receipts directory should be, and a log path whose
	// folder can't be created because a file is in the way
	blocker := filepath.Join(dir, "logs")
	os.WriteFile(blocker, []byte("x"), 0600)
	a := AuditLog{LogFile: filepath.Join(blocker, "age-tool.log"), ReceiptsDir: blocker}

	warnings := a.RecordEncrypt(time.Now(), "nope", "nope.age", "k.pub", "")
	if len(warnings) != 2 {
		t.Errorf("got %d warnings, want 2: %v", len(warnings), warnings)
	}
}
