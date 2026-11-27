// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ─── Locations ──────────────────────────────────────────────────────────────

// env returns a getenv function backed by a map.
func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// TestLocationsPerOS checks the standard locations on each OS, with and
// without the environment variables that override them.
func TestLocationsPerOS(t *testing.T) {
	cases := []struct {
		name string
		goos string
		vars map[string]string
		home string
		want Locations
	}{
		{"linux defaults", "linux", nil, "/home/u", Locations{
			KeysDir:   "/home/u/.local/share/age-tool/keys",
			ConfigDir: "/home/u/.config/age-tool",
			StateDir:  "/home/u/.local/state/age-tool",
		}},
		{"linux XDG", "linux", map[string]string{
			"XDG_DATA_HOME": "/data", "XDG_CONFIG_HOME": "/cfg", "XDG_STATE_HOME": "/state",
		}, "/home/u", Locations{
			KeysDir:   "/data/age-tool/keys",
			ConfigDir: "/cfg/age-tool",
			StateDir:  "/state/age-tool",
		}},
		{"linux relative XDG ignored", "linux", map[string]string{"XDG_DATA_HOME": "relative/dir"}, "/home/u", Locations{
			KeysDir:   "/home/u/.local/share/age-tool/keys",
			ConfigDir: "/home/u/.config/age-tool",
			StateDir:  "/home/u/.local/state/age-tool",
		}},
		{"macOS", "darwin", nil, "/Users/u", Locations{
			KeysDir:   "/Users/u/Library/Application Support/age-tool/keys",
			ConfigDir: "/Users/u/Library/Application Support/age-tool",
			StateDir:  "/Users/u/Library/Logs/age-tool",
		}},
		{"windows", "windows", map[string]string{
			"APPDATA": `C:\Users\u\AppData\Roaming`, "LOCALAPPDATA": `C:\Users\u\AppData\Local`,
		}, `C:\Users\u`, Locations{
			KeysDir:   `C:\Users\u\AppData\Roaming\age-tool\keys`,
			ConfigDir: `C:\Users\u\AppData\Roaming\age-tool`,
			StateDir:  `C:\Users\u\AppData\Local\age-tool\logs`,
		}},
		{"windows without env", "windows", nil, `C:\Users\u`, Locations{
			KeysDir:   `C:\Users\u\AppData\Roaming\age-tool\keys`,
			ConfigDir: `C:\Users\u\AppData\Roaming\age-tool`,
			StateDir:  `C:\Users\u\AppData\Local\age-tool\logs`,
		}},
	}
	for _, c := range cases {
		// Unix-style expectations only hold on Unix-style hosts
		if c.goos != "windows" && runtime.GOOS == "windows" {
			continue
		}
		got, err := locationsFor(c.goos, env(c.vars), c.home)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
	if _, err := locationsFor("linux", env(nil), ""); err == nil {
		t.Error("an empty home directory should be an error")
	}
}

// TestEnsurePrivateDir creates nested folders owner-only and tightens an
// existing loose folder.
func TestEnsurePrivateDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "keys")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0700 {
		t.Errorf("new dir perms = %v, want 0700", fi.Mode().Perm())
	}

	loose := filepath.Join(base, "loose")
	os.Mkdir(loose, 0755)
	os.Chmod(loose, 0755) // undo any umask
	if DirPermissionWarning(loose) == "" {
		t.Error("expected a warning for a 0755 folder")
	}
	if err := EnsurePrivateDir(loose); err != nil {
		t.Fatal(err)
	}
	if DirPermissionWarning(loose) != "" {
		t.Error("folder should have been tightened to 0700")
	}

	file := filepath.Join(base, "file")
	os.WriteFile(file, []byte("x"), 0600)
	if err := EnsurePrivateDir(file); err == nil {
		t.Error("a file in place of the folder should be an error")
	}
}

// ─── Settings ───────────────────────────────────────────────────────────────

// TestSettingsMigrationDismissal round-trips the "don't ask again" list.
func TestSettingsMigrationDismissal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "settings.json")
	folder := t.TempDir()

	s := LoadSettings(path) // missing file gives defaults
	if s.IsMigrationDismissed(folder) {
		t.Fatal("nothing should be dismissed by default")
	}
	s.DismissMigration(folder)
	s.DismissMigration(folder) // no duplicates
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("settings perms = %v, want 0600", fi.Mode().Perm())
	}

	loaded := LoadSettings(path)
	if !loaded.IsMigrationDismissed(folder) || len(loaded.MigrationDismissed) != 1 {
		t.Errorf("loaded settings = %+v", loaded)
	}
	if loaded.IsMigrationDismissed(t.TempDir()) {
		t.Error("another folder should not be dismissed")
	}
}

// ─── Public keys ────────────────────────────────────────────────────────────

// TestParsePublicKey accepts a bare key or an age-keygen style file, and
// refuses private keys, junk and multiple keys.
func TestParsePublicKey(t *testing.T) {
	id := newIdentity(t)
	pub := id.Recipient().String()

	for _, ok := range []string{pub, "  " + pub + "  \n", "# public key for alice\n\n" + pub + "\n"} {
		if got, err := ParsePublicKey(ok); err != nil || got != pub {
			t.Errorf("ParsePublicKey(%q) = %q, %v", ok, got, err)
		}
	}

	bad := map[string]string{
		"private key":       id.String(),
		"lowercase private": strings.ToLower(id.String()),
		"empty":             "",
		"comments only":     "# nothing\n",
		"junk":              "hello world",
		"two keys":          pub + "\n" + newIdentity(t).Recipient().String(),
	}
	for name, text := range bad {
		_, err := ParsePublicKey(text)
		if err == nil {
			t.Errorf("%s: should be rejected", name)
			continue
		}
		// The secret must never be echoed back in an error message
		if strings.Contains(strings.ToUpper(err.Error()), "AGE-SECRET-KEY-1") {
			t.Errorf("%s: error message contains the secret key", name)
		}
	}
}

// TestImportExportPublicKey imports a contact's key, refuses duplicates and
// bad names, and exports a shareable copy without overwriting.
func TestImportExportPublicKey(t *testing.T) {
	keys := t.TempDir()
	pub := newIdentity(t).Recipient().String()

	path, err := ImportPublicKey(keys, "alice", "# from alice\n"+pub+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("imported key perms = %v, want 0600", fi.Mode().Perm())
	}
	if got, _ := ReadPublicKeyString(path); got != pub {
		t.Errorf("stored key = %q", got)
	}
	if _, err := ImportPublicKey(keys, "alice", pub); err != ErrKeyExists {
		t.Errorf("duplicate import: got %v, want ErrKeyExists", err)
	}
	if _, err := ImportPublicKey(keys, "../alice", pub); err == nil {
		t.Error("unsafe name should be rejected")
	}

	// The imported key can be used for encryption
	if _, err := ReadRecipient(path); err != nil {
		t.Errorf("imported key not usable: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "alice.pub")
	if err := ExportPublicKey(path, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadPublicKeyString(dest); got != pub {
		t.Errorf("exported key = %q", got)
	}
	if err := ExportPublicKey(path, dest); err == nil {
		t.Error("export should not overwrite an existing file")
	}
}

// ─── Migration ──────────────────────────────────────────────────────────────

// TestImportKeyFiles copies a 1.x folder's keys and nicknames into the key
// store without changing the originals, overwriting anything, or
// replacing existing nicknames.
func TestImportKeyFiles(t *testing.T) {
	src := t.TempDir()
	store := filepath.Join(t.TempDir(), "keys") // doesn't exist yet

	os.WriteFile(filepath.Join(src, "work.pub"), []byte("work-pub\n"), 0644)
	os.WriteFile(filepath.Join(src, "work.priv"), []byte("work-priv\n"), 0644)
	os.WriteFile(filepath.Join(src, "same.pub"), []byte("same\n"), 0600)
	os.WriteFile(filepath.Join(src, "clash.pub"), []byte("from-1x\n"), 0600)
	os.WriteFile(filepath.Join(src, "notes.txt"), []byte("not a key"), 0600)
	(Nicknames{"work.pub": "Work", "work.priv": "Work Laptop", "clash.pub": "Old"}).Save(filepath.Join(src, NicknameFileName))

	// Pre-existing key store content
	EnsurePrivateDir(store)
	os.WriteFile(filepath.Join(store, "same.pub"), []byte("same\n"), 0600)
	os.WriteFile(filepath.Join(store, "clash.pub"), []byte("already-here\n"), 0600)
	(Nicknames{"work.priv": "Keep Me"}).Save(filepath.Join(store, NicknameFileName))

	result, err := ImportKeyFiles(src, store)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Imported, ",") != "work.priv,work.pub" ||
		strings.Join(result.AlreadyPresent, ",") != "same.pub" ||
		strings.Join(result.Conflicts, ",") != "clash.pub" || len(result.Failed) != 0 {
		t.Errorf("result = %+v", result)
	}

	// Copies are owner-only even though the originals were 0644
	if fi, _ := os.Stat(filepath.Join(store, "work.priv")); fi.Mode().Perm() != 0600 {
		t.Errorf("copied key perms = %v, want 0600", fi.Mode().Perm())
	}
	// The clashing file in the store is untouched
	if data, _ := os.ReadFile(filepath.Join(store, "clash.pub")); string(data) != "already-here\n" {
		t.Errorf("clash.pub was overwritten: %q", data)
	}
	// Originals are unchanged
	if data, _ := os.ReadFile(filepath.Join(src, "work.priv")); string(data) != "work-priv\n" {
		t.Error("original key was changed")
	}
	// Nicknames: new ones carried over, existing ones kept, clashes not carried
	nicks := LoadNicknames(filepath.Join(store, NicknameFileName))
	if nicks["work.pub"] != "Work" || nicks["work.priv"] != "Keep Me" || nicks["clash.pub"] != "" {
		t.Errorf("nicknames = %v", nicks)
	}

	// Running again imports nothing new
	again, _ := ImportKeyFiles(src, store)
	if len(again.Imported) != 0 || len(again.AlreadyPresent) != 3 {
		t.Errorf("second import = %+v", again)
	}
}

// ─── Audit logs ─────────────────────────────────────────────────────────────

// TestCentralAndLocalAudit records one encryption to both logs: the local
// log beside the file with relative paths (1.x format), the central log
// with full paths, and each with its own receipt.
func TestCentralAndLocalAudit(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	loc := Locations{StateDir: filepath.Join(t.TempDir(), "state")}
	logs := NewAuditLogs(loc.CentralAudit(), LocalAudit("."))

	os.WriteFile("doc.txt", []byte("hello"), 0600)
	os.WriteFile("doc.txt.age", []byte("ciphertext"), 0600)
	if w := logs.RecordEncrypt(time.Now(), "doc.txt", "doc.txt.age", "k.pub", ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}

	local, _ := os.ReadFile("age-tool.log")
	if !strings.Contains(string(local), "ENCRYPT: doc.txt -> doc.txt.age |") {
		t.Errorf("local log = %q", local)
	}
	central, _ := os.ReadFile(loc.CentralAudit().LogFile)
	absDoc, _ := filepath.Abs("doc.txt")
	if !strings.Contains(string(central), "ENCRYPT: "+absDoc+" -> "+absDoc+".age |") {
		t.Errorf("central log = %q", central)
	}
	for _, dir := range []string{"logs", loc.CentralAudit().ReceiptsDir} {
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%s: want 1 receipt, got %d", dir, len(entries))
		}
	}
}

// TestNewAuditLogsDropsDuplicates writes once when both logs are the same.
func TestNewAuditLogsDropsDuplicates(t *testing.T) {
	t.Chdir(t.TempDir())
	if logs := NewAuditLogs(LocalAudit("."), LocalAudit(".")); len(logs) != 1 {
		t.Errorf("got %d logs, want 1", len(logs))
	}
}

// TestLocalAuditPathsRelativeToLog records files in the log's own folder
// by name, and files elsewhere in full.
func TestLocalAuditPathsRelativeToLog(t *testing.T) {
	t.Chdir(t.TempDir())
	os.Mkdir("keys", 0700)
	keysLog := LocalAudit("keys")
	if got := keysLog.displayPath(filepath.Join("keys", "k.pub")); got != "k.pub" {
		t.Errorf("file in log folder = %q, want k.pub", got)
	}
	elsewhere, _ := filepath.Abs("doc.txt")
	if got := keysLog.displayPath("doc.txt"); got != elsewhere {
		t.Errorf("file outside log folder = %q, want %q", got, elsewhere)
	}
}

// TestReceiptsNeverOverwrite gives same-second receipts distinct names.
func TestReceiptsNeverOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())
	a := LocalAudit(".")
	ts := time.Date(2026, 4, 9, 14, 30, 22, 0, time.Local)
	for i := 0; i < 3; i++ {
		if w := a.RecordEncrypt(ts, "x", "x.age", "k.pub", ""); len(w) != 0 {
			t.Fatalf("warnings: %v", w)
		}
	}
	entries, _ := os.ReadDir("logs")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := "encrypt-2026-04-09-143022-2.json,encrypt-2026-04-09-143022-3.json,encrypt-2026-04-09-143022.json"
	if strings.Join(names, ",") != want {
		t.Errorf("receipts = %v", names)
	}
}

// TestAuditLogCreatesMissingFolder writes the log line even when the
// receipt can't be written and the log's folder doesn't exist yet.
func TestAuditLogCreatesMissingFolder(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocked")
	os.WriteFile(blocker, []byte("x"), 0600) // a file where the receipts folder should be
	a := AuditLog{LogFile: filepath.Join(base, "new", "state", "age-tool.log"), ReceiptsDir: blocker}

	warnings := a.RecordEncrypt(time.Now(), "x", "x.age", "k.pub", "")
	if len(warnings) != 1 {
		t.Errorf("want only the receipt warning, got %v", warnings)
	}
	if !FileExists(a.LogFile) {
		t.Fatal("log line was not written")
	}
	if fi, _ := os.Stat(filepath.Dir(a.LogFile)); fi.Mode().Perm() != 0700 {
		t.Errorf("new log folder perms = %v, want 0700", fi.Mode().Perm())
	}
}
