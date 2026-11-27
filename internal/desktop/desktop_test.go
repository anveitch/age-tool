// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package desktop

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newTest returns an Integration installing into a temporary home, with a
// program path containing a space and a quote (as a real path might), and
// a list recording which helpers were run.
func newTest(t *testing.T) (Integration, *[]string) {
	t.Helper()
	home := t.TempDir()
	var ran []string
	// No system-wide Thunar actions unless a test provides them
	old := systemThunarActions
	systemThunarActions = filepath.Join(home, "no-system-uca.xml")
	t.Cleanup(func() { systemThunarActions = old })
	return Integration{
		DataHome:   filepath.Join(home, ".local", "share"),
		ConfigHome: filepath.Join(home, ".config"),
		Exe:        filepath.Join(home, "My Apps", "age-tool's.AppImage"),
		Run: func(name string, args ...string) error {
			ran = append(ran, name)
			return exec.ErrNotFound // as on a system without the helpers
		},
	}, &ran
}

// readFile returns a file's contents, failing the test if it can't.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestInstallAndUninstall checks every file is written with the right
// permissions, the status, and that uninstalling removes everything.
func TestInstallAndUninstall(t *testing.T) {
	in, ran := newTest(t)
	if in.Status() != NotInstalled {
		t.Fatal("status before install should be NotInstalled")
	}

	report, err := in.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(report.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", report.Warnings)
	}
	if in.Status() != Installed {
		t.Error("status after install should be Installed")
	}

	// Scripts and KDE service menus must be executable; the rest not
	executable := map[string]bool{}
	for _, f := range append(in.nautilusScripts(), in.dolphinMenus()...) {
		executable[f] = true
	}
	for _, f := range in.ownedFiles() {
		info, err := os.Stat(f)
		if err != nil {
			t.Errorf("not installed: %s", f)
			continue
		}
		want := os.FileMode(0644)
		if executable[f] {
			want = 0755
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %04o, want %04o", filepath.Base(f), info.Mode().Perm(), want)
		}
	}
	if !strings.Contains(readFile(t, in.mimeApps()), MimeType+"="+AppID+".desktop;") {
		t.Error("not made the default app for .age files")
	}
	if !strings.Contains(readFile(t, in.thunarActions()), "<unique-id>age-tool-encrypt</unique-id>") {
		t.Error("Thunar actions not added")
	}
	if len(*ran) != 3 {
		t.Errorf("helpers run = %v", *ran)
	}

	// A moved program makes the installation outdated
	moved := in
	moved.Exe = "/opt/elsewhere/age-tool-gui"
	if moved.Status() != Outdated {
		t.Error("status with a moved program should be Outdated")
	}

	// Installing again replaces rather than duplicates
	if _, err := in.Install(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, in.thunarActions()), "<unique-id>age-tool-"); n != 2 {
		t.Errorf("Thunar has %d age-tool actions after reinstalling, want 2", n)
	}

	if _, err := in.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, f := range in.ownedFiles() {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("not removed: %s", f)
		}
	}
	if strings.Contains(readFile(t, in.thunarActions()), "age-tool") {
		t.Error("Thunar actions not removed")
	}
	if strings.Contains(readFile(t, in.mimeApps()), AppID) {
		t.Error("default app entry not removed")
	}
	if in.Status() != NotInstalled {
		t.Error("status after uninstall should be NotInstalled")
	}

	// Uninstalling again is harmless
	if _, err := in.Uninstall(); err != nil {
		t.Errorf("second Uninstall: %v", err)
	}
}

// TestHelperFailuresAreWarnings checks a failing cache helper doesn't
// stop the installation.
func TestHelperFailuresAreWarnings(t *testing.T) {
	in, _ := newTest(t)
	in.Run = func(name string, args ...string) error { return errors.New("exit status 1") }
	report, err := in.Install()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Warnings) != 3 {
		t.Errorf("warnings = %v, want one per helper", report.Warnings)
	}
}

// TestRefusesUnsafeProgramPath checks paths that can't be written safely.
func TestRefusesUnsafeProgramPath(t *testing.T) {
	in, _ := newTest(t)
	for _, exe := range []string{"age-tool-gui", "/opt/100%/age-tool", "/opt/a\nb"} {
		in.Exe = exe
		if _, err := in.Install(); err == nil {
			t.Errorf("Install accepted program path %q", exe)
		}
	}
}

// TestThunarKeepsUserActions checks the user's own actions survive an
// install and uninstall unchanged, and that the system defaults are kept
// when the user had no file of their own.
func TestThunarKeepsUserActions(t *testing.T) {
	in, _ := newTest(t)
	userFile := `<?xml version="1.0" encoding="UTF-8"?>
<actions>
<action>
	<icon>utilities-terminal</icon>
	<name>Open Terminal Here</name>
	<unique-id>1700000000-1</unique-id>
	<command>exo-open --working-directory %f --launch TerminalEmulator</command>
	<patterns>*</patterns>
	<directories/>
</action>
</actions>
`
	if err := os.MkdirAll(filepath.Dir(in.thunarActions()), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.thunarActions(), []byte(userFile), 0600); err != nil {
		t.Fatal(err)
	}
	if err := in.installThunarActions(); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, in.thunarActions())
	if !strings.Contains(got, "Open Terminal Here") || !strings.Contains(got, EncryptMenu) {
		t.Errorf("after install:\n%s", got)
	}
	if info, _ := os.Stat(in.thunarActions()); info.Mode().Perm() != 0600 {
		t.Error("the user's file permissions were changed")
	}
	if _, err := in.removeThunarActions(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, in.thunarActions()); got != userFile {
		t.Errorf("after uninstall the file differs from the original:\n%s", got)
	}

	// No user file: start from the system defaults
	in2, _ := newTest(t)
	if err := os.WriteFile(systemThunarActions, []byte(userFile), 0644); err != nil {
		t.Fatal(err)
	}
	if err := in2.installThunarActions(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, in2.thunarActions()); !strings.Contains(got, "Open Terminal Here") {
		t.Error("system default actions were lost")
	}
}

// TestDefaultAppKeepsOtherSettings checks mimeapps.list editing.
func TestDefaultAppKeepsOtherSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mimeapps.list")
	original := "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\ntext/plain=gedit.desktop;\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if err := setDefaultApp(path, MimeType, "ours.desktop"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, "[Default Applications]\n"+MimeType+"=ours.desktop;\ntext/plain=gedit.desktop;") {
		t.Errorf("after set:\n%s", got)
	}
	// Setting again replaces the entry
	if err := setDefaultApp(path, MimeType, "ours.desktop"); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, path), MimeType); n != 1 {
		t.Errorf("%d entries for the type after setting twice", n)
	}
	if changed, err := unsetDefaultApp(path, MimeType, "ours.desktop"); err != nil || !changed {
		t.Fatalf("unset = %v, %v", changed, err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("after unset:\n%q\nwant\n%q", got, original)
	}

	// If the user picked another app since, it is left alone
	if err := setDefaultApp(path, MimeType, "theirs.desktop"); err != nil {
		t.Fatal(err)
	}
	if changed, _ := unsetDefaultApp(path, MimeType, "ours.desktop"); changed {
		t.Error("removed the user's own choice of app")
	}

	// A missing file gets created with just our section
	fresh := filepath.Join(t.TempDir(), "mimeapps.list")
	if err := setDefaultApp(fresh, MimeType, "ours.desktop"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, fresh); got != "[Default Applications]\n"+MimeType+"=ours.desktop;\n" {
		t.Errorf("new file = %q", got)
	}
}

// TestQuoting checks the program path is quoted correctly for each format.
func TestQuoting(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/bin/age-tool-gui", "/usr/bin/age-tool-gui"},
		{"/home/me/My Apps/age-tool", `"/home/me/My Apps/age-tool"`},
		{`/home/me/a"b$c`, `"/home/me/a\"b\$c"`},
	}
	for _, c := range cases {
		if got := quoteExecArg(c.in); got != c.want {
			t.Errorf("quoteExecArg(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	// In the file itself, each backslash is doubled
	if got := desktopExec(`/a b\c`, "%F"); got != `"/a b\\\\c" %F` {
		t.Errorf("desktopExec = %s", got)
	}
	if got := shellQuote("/home/me/age-tool's"); got != `'/home/me/age-tool'\''s'` {
		t.Errorf("shellQuote = %s", got)
	}
}

// TestNautilusScriptPassesFiles runs the generated script with a stand-in
// program, checking awkward file names arrive intact.
func TestNautilusScriptPassesFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	in, _ := newTest(t)
	dir := filepath.Dir(in.Exe)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// The stand-in prints each argument on its own line
	out := filepath.Join(t.TempDir(), "args")
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + shellQuote(out) + "\n"
	if err := os.WriteFile(in.Exe, []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(script, in.nautilusScript("decrypt"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script, "my file.age", "-odd.age", "it's.age").Run(); err != nil {
		t.Fatal(err)
	}
	want := "decrypt\n--\nmy file.age\n-odd.age\nit's.age\n"
	if got := readFile(t, out); got != want {
		t.Errorf("program received:\n%s\nwant\n%s", got, want)
	}
}

// TestWithLinuxTools installs into a temporary home and checks the result
// with the real Linux desktop tools: the launcher passes
// desktop-file-validate, .age files are recognised (by name and by
// content) and age-tool is their default app. It needs those tools, so it
// only runs when AGE_TOOL_LINUX_CHECK=1, e.g. in an Ubuntu container with
// desktop-file-utils, shared-mime-info, xdg-utils and libxml2-utils.
func TestWithLinuxTools(t *testing.T) {
	if os.Getenv("AGE_TOOL_LINUX_CHECK") != "1" {
		t.Skip("set AGE_TOOL_LINUX_CHECK=1 to run with the Linux desktop tools")
	}
	in, _ := newTest(t)
	in.Run = runQuietly // really run update-mime-database and friends
	report, err := in.Install()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("warnings: %v", report.Warnings)

	// run runs a tool with the test's XDG folders, returning its output
	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = append(os.Environ(),
			"XDG_DATA_HOME="+in.DataHome, "XDG_CONFIG_HOME="+in.ConfigHome,
			"XDG_CURRENT_DESKTOP=X-Generic")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s %v: %v\n%s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// The launcher follows the Desktop Entry spec
	run("desktop-file-validate", in.launcherFile())
	// The MIME definition and Thunar's actions are well-formed XML
	run("xmllint", "--noout", in.mimePackage(), in.thunarActions())
	// The Nautilus scripts are valid shell
	for _, s := range in.nautilusScripts() {
		run("sh", "-n", s)
	}

	// .age files are recognised by name, and by content without the name
	dir := t.TempDir()
	byName := filepath.Join(dir, "report.pdf.age")
	byContent := filepath.Join(dir, "renamed-file")
	for _, f := range []string{byName, byContent} {
		if err := os.WriteFile(f, []byte("age-encryption.org/v1\n-> X25519 abc\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{byName, byContent} {
		if got := run("xdg-mime", "query", "filetype", f); got != MimeType {
			t.Errorf("type of %s = %q, want %s", filepath.Base(f), got, MimeType)
		}
	}
	// age-tool opens them
	if got := run("xdg-mime", "query", "default", MimeType); got != AppID+".desktop" {
		t.Errorf("default app = %q, want %s.desktop", got, AppID)
	}

	// Removing it leaves no age-tool type behind
	if _, err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if got := run("xdg-mime", "query", "filetype", byName); got == MimeType {
		t.Error(".age files are still recognised after uninstalling")
	}
}

// TestLauncherMatchesWindow checks the menu entry names the app window's
// class (its title, AppName), so desktops show age-tool's icon for the
// running window rather than a generic one.
func TestLauncherMatchesWindow(t *testing.T) {
	entry := string(Integration{Exe: "/opt/age-tool"}.launcherEntry())
	if !strings.Contains(entry, "\nStartupWMClass="+AppName+"\n") {
		t.Fatalf("launcher entry lacks StartupWMClass=%s:\n%s", AppName, entry)
	}
}
