// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// testFilePassword is a password that meets the default rules.
const testFilePassword = "kettle-orange-piano-march-47!"

// TestPasswordRules checks the default rule (8+ characters, a number and a
// special character) and the weak-pattern refusals.
func TestPasswordRules(t *testing.T) {
	rules := DefaultPasswordRules
	allowed := []string{
		"Tr4vel#Bus", // 10 characters, number, special
		"k9!mzq2pw",  // random-looking
		testFilePassword,
		"Bl@ck-cat-7", // a phrase with a number and symbol
	}
	for _, p := range allowed {
		if err := rules.CheckPassword(p); err != nil {
			t.Errorf("CheckPassword(%q) = %v, want allowed", p, err)
		}
	}

	refused := map[string]string{
		"Ab1!":        "at least 8",  // too short
		"abcdefgh1":   "special",     // no special character
		"abcdefgh!":   "number",      // no number
		"abcdefgh":    "number",      // neither
		"Summer26!":   "common word", // common word plus number and symbol
		"Password1!":  "common word", // the classic
		"P@ssword1":   "common word", // look-alike swaps are undone
		"Summ3r2026#": "common word", // "3" for "e"
		"Qwerty123!":  "common word", // keyboard word
		"abcdefg1!":   "sequence",    // alphabet run
		"12345678!":   "too easy",    // no letters
		"!!!!!!!!1":   "too easy",    // no letters
	}
	for p, want := range refused {
		err := rules.CheckPassword(p)
		if err == nil {
			t.Errorf("CheckPassword(%q) allowed, want refused (%s)", p, want)
			continue
		}
		if !errors.Is(err, ErrPasswordTooWeak) {
			t.Errorf("CheckPassword(%q) error %v is not ErrPasswordTooWeak", p, err)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPassword(%q) = %q, want it to mention %q", p, err, want)
		}
	}

	// Every problem is listed at once, so the user can fix them together
	err := rules.CheckPassword("abc")
	for _, want := range []string{"at least 8", "number", "special"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPassword(\"abc\") = %v, want it to mention %q", err, want)
		}
	}
}

// TestPasswordRulesOnlyStricter checks that settings can raise the rules
// but never lower them below the floor.
func TestPasswordRulesOnlyStricter(t *testing.T) {
	weaker := PasswordRules{MinLength: 4, RequireNumber: false, RequireSpecial: false}
	if got := weaker.Effective(); got != DefaultPasswordRules {
		t.Errorf("weaker rules gave %+v, want the floor %+v", got, DefaultPasswordRules)
	}
	if err := weaker.CheckPassword("abcd"); err == nil {
		t.Error("weakened rules allowed a 4-character password")
	}

	stricter := PasswordRules{MinLength: 16}
	if got := stricter.Effective(); got.MinLength != 16 || !got.RequireNumber || !got.RequireSpecial {
		t.Errorf("stricter rules gave %+v", got)
	}
	if err := stricter.CheckPassword("Tr4vel#Bus"); err == nil {
		t.Error("16-character rule allowed a 10-character password")
	}
	if got := stricter.Describe(); !strings.Contains(got, "16 characters") {
		t.Errorf("Describe() = %q", got)
	}
	if got := DefaultPasswordRules.Describe(); got != "At least 8 characters, including a number and a special character (such as ! or #)." {
		t.Errorf("Describe() = %q", got)
	}
}

// TestPasswordRulesFromSettings checks the settings file's password_rules,
// including an attempt to weaken them.
func TestPasswordRulesFromSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	// No setting: the defaults
	if got := LoadSettings(path).PasswordRules(); got != DefaultPasswordRules {
		t.Errorf("no settings gave %+v", got)
	}

	// Stricter: used; weaker parts: ignored
	writeTestFile(t, path, `{"password_rules": {"min_length": 12, "require_number": false, "require_special": true}}`)
	got := LoadSettings(path).PasswordRules()
	want := PasswordRules{MinLength: 12, RequireNumber: true, RequireSpecial: true}
	if got != want {
		t.Errorf("settings gave %+v, want %+v", got, want)
	}

	// Saving other settings keeps the rules
	s := LoadSettings(path)
	s.DismissMigration(t.TempDir())
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if got := LoadSettings(path).PasswordRules(); got != want {
		t.Errorf("after saving, rules are %+v, want %+v", got, want)
	}
}

// TestSuggestPassword checks suggested passwords always meet the rules
// (including stricter ones), look as documented, and differ each time.
func TestSuggestPassword(t *testing.T) {
	seen := map[string]bool{}
	for _, rules := range []PasswordRules{DefaultPasswordRules, {MinLength: 30}, {MinLength: 60}} {
		for range 200 {
			p, err := SuggestPassword(rules)
			if err != nil {
				t.Fatal(err)
			}
			if err := rules.CheckPassword(p); err != nil {
				t.Fatalf("suggestion %q breaks %+v: %v", p, rules, err)
			}
			// Words, then "-NN" and a special character
			parts := strings.Split(p, "-")
			if len(parts) < 5 {
				t.Fatalf("suggestion %q has fewer than 4 words", p)
			}
			seen[p] = true
		}
	}
	if len(seen) < 590 {
		t.Errorf("only %d different suggestions out of 600", len(seen))
	}
	if n := len(suggestionWords()); n != 1295 {
		t.Errorf("word list has %d words, want 1295", n)
	}
}

// TestPasswordRoundTrip encrypts and decrypts a file with a password,
// checks a wrong password is refused without writing anything, and checks
// the lock method is detected from the file.
func TestPasswordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "notes.txt")
	enc := filepath.Join(dir, "notes.txt.age")
	out := filepath.Join(dir, "notes-out.txt")
	writeTestFile(t, plain, "meeting notes\n")

	if err := EncryptFileWithPassword(plain, enc, testFilePassword); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(enc); info.Mode().Perm() != 0600 {
		t.Errorf("encrypted file mode %v, want 0600", info.Mode().Perm())
	}
	if m, err := FileLockMethod(enc); err != nil || m != LockedWithPassword {
		t.Fatalf("FileLockMethod = %v, %v; want LockedWithPassword", m, err)
	}

	// Wrong password: refused, nothing written
	if err := DecryptFileWithPassword(enc, out, "wrong-password-1!"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password gave %v, want ErrWrongPassword", err)
	}
	if FileExists(out) {
		t.Fatal("output written for a wrong password")
	}

	if err := DecryptFileWithPassword(enc, out, testFilePassword); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "meeting notes\n" {
		t.Errorf("decrypted %q", got)
	}
}

// TestFileLockMethod checks detection for key files, password files and
// files that aren't age files, without needing any secret.
func TestFileLockMethod(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "a.txt")
	writeTestFile(t, plain, "hello")

	// Encrypted for two keys: locked with keys
	id1, _ := age.GenerateX25519Identity()
	id2, _ := age.GenerateX25519Identity()
	keyFile := filepath.Join(dir, "keys.age")
	f, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(f, id1.Recipient(), id2.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()
	_ = f.Close()
	if m, err := FileLockMethod(keyFile); err != nil || m != LockedWithKey {
		t.Errorf("key file: %v, %v", m, err)
	}

	// Not age files
	for name, content := range map[string]string{"plain.txt": "hello", "empty.age": "", "truncated.age": "age-encryption.org/v1\n-> X25519 abc\n"} {
		p := filepath.Join(dir, name)
		writeTestFile(t, p, content)
		if _, err := FileLockMethod(p); !errors.Is(err, ErrNotAgeFile) {
			t.Errorf("%s: got %v, want ErrNotAgeFile", name, err)
		}
	}

	// Missing file
	if _, err := FileLockMethod(filepath.Join(dir, "missing.age")); !errors.Is(err, ErrFileUnavailable) {
		t.Errorf("missing file: got %v, want ErrFileUnavailable", err)
	}

	// A private key file (.priv) is itself password-protected by age
	priv := filepath.Join(dir, "k.priv")
	if err := WritePassphraseProtectedKey(priv, id1.String(), "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if m, err := FileLockMethod(priv); err != nil || m != LockedWithPassword {
		t.Errorf(".priv file: %v, %v; want LockedWithPassword", m, err)
	}
}

// TestPasswordFileFromAgeCLI decrypts a file made by the real "age -p"
// (testdata/made-by-age-p.txt.age, made with age v1.2.1), proving files
// from the age tool open in age-tool.
func TestPasswordFileFromAgeCLI(t *testing.T) {
	enc := filepath.Join("testdata", "made-by-age-p.txt.age")
	if m, err := FileLockMethod(enc); err != nil || m != LockedWithPassword {
		t.Fatalf("FileLockMethod = %v, %v", m, err)
	}
	out := filepath.Join(t.TempDir(), "out.txt")
	if err := DecryptFileWithPassword(enc, out, testFilePassword); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "Made by age -p for the interop test.\n" {
		t.Errorf("decrypted %q", got)
	}
}

// TestPasswordFileOpensInAgeCLI encrypts with age-tool and decrypts with
// the real "age -d", typing the password through expect (age reads it
// from the terminal). Skipped when age or expect isn't installed.
func TestPasswordFileOpensInAgeCLI(t *testing.T) {
	ageBin, err1 := exec.LookPath("age")
	expectBin, err2 := exec.LookPath("expect")
	if err1 != nil || err2 != nil {
		t.Skip("needs the age and expect commands")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.age")
	out := filepath.Join(dir, "out.txt")
	writeTestFile(t, plain, "Made by age-tool.\n")
	if err := EncryptFileWithPassword(plain, enc, testFilePassword); err != nil {
		t.Fatal(err)
	}

	script := `set timeout 30
spawn ` + ageBin + ` -d -o [lindex $argv 1] [lindex $argv 0]
expect "passphrase"
send -- "[lindex $argv 2]\r"
expect eof
catch wait result
exit [lindex $result 3]`
	scriptFile := filepath.Join(dir, "age-d.exp")
	writeTestFile(t, scriptFile, script)
	cmd := exec.Command(expectBin, scriptFile, enc, out, testFilePassword) // #nosec G204 -- test-only, fixed paths
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("age -d failed: %v\n%s", err, output)
	}
	if got, _ := os.ReadFile(out); string(got) != "Made by age-tool.\n" {
		t.Errorf("age -d gave %q", got)
	}
}

// TestPasswordAuditRecords checks password transactions are logged with
// the method "password", read back as such, and never contain the password.
func TestPasswordAuditRecords(t *testing.T) {
	dir := t.TempDir()
	log := AuditLog{LogFile: filepath.Join(dir, "age-tool.log"), ReceiptsDir: filepath.Join(dir, "logs")}
	plain := filepath.Join(dir, "notes.txt")
	enc := filepath.Join(dir, "notes.txt.age")
	writeTestFile(t, plain, "notes")
	if err := EncryptFileWithPassword(plain, enc, testFilePassword); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if w := log.RecordPasswordEncrypt(now, plain, enc); len(w) > 0 {
		t.Fatal(w)
	}
	if w := log.RecordPasswordDecrypt(now.Add(time.Second), enc, plain); len(w) > 0 {
		t.Fatal(w)
	}

	entries, skipped, err := ReadActivity(log.ReceiptsDir, 0)
	if err != nil || skipped != 0 || len(entries) != 2 {
		t.Fatalf("ReadActivity = %d entries, %d skipped, %v", len(entries), skipped, err)
	}
	for _, e := range entries {
		if e.Method != MethodPassword || e.Key != "" {
			t.Errorf("%s entry: method %q, key %q", e.Type, e.Method, e.Key)
		}
	}

	// The password appears nowhere in the logs
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(path, ".age") {
			return err
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), testFilePassword) {
			t.Errorf("password found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	line, _ := os.ReadFile(log.LogFile)
	if !strings.Contains(string(line), "| password |") {
		t.Errorf("log line doesn't name the method:\n%s", line)
	}
}

// writeTestFile writes content to path, failing the test on error.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
