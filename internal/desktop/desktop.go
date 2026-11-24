// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Package desktop installs and removes age-tool's Linux desktop
// integration for the current user, with no root access needed:
//
//   - a launcher entry and icons, so age-tool appears in the app menu
//   - a file type for .age files, with age-tool as the default app, so
//     double-clicking one opens the decrypt screen
//   - right-click Encrypt / Decrypt entries in Nautilus (GNOME), Dolphin
//     (KDE), Nemo (Cinnamon) and Thunar (XFCE)
//
// Everything is written under the user's XDG data and config folders.
// Removing it deletes only what Install added: files age-tool owns, its
// own entries in shared files (Thunar's actions, the default-app list),
// and nothing else. No toolkit code is used, so it can all be tested on
// any OS against a temporary home folder.
package desktop

import (
	"bytes"
	_ "embed" // for the icon files
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Names shown in menus. The app's display name and icon are open decision
// D6 in the 2.0 plan; change them here.
const (
	AppID       = "io.github.anveitch.age-tool" // Reverse-DNS ID: desktop file and icon names
	AppName     = "age-tool"                    // Name in the app menu
	GenericName = "File Encryption"             // Shown under the name by some menus
	Comment     = "Encrypt and decrypt files with age keys"
	MimeType    = "application/x-age-encrypted" // File type registered for .age files
	EncryptMenu = "Encrypt with age-tool"       // Right-click menu entries
	DecryptMenu = "Decrypt with age-tool"
)

// mimeIcon is the icon name for .age files: the MIME type with "/" as "-",
// as the icon theme spec expects.
var mimeIcon = strings.ReplaceAll(MimeType, "/", "-")

//go:embed icons/app.svg
var appIconSVG []byte

//go:embed icons/file.svg
var fileIconSVG []byte

// AppIcon returns the app icon (SVG), for the GUI's window icon.
func AppIcon() []byte { return appIconSVG }

// Integration describes where to install for one user, and which program
// the menu entries start.
type Integration struct {
	DataHome   string // $XDG_DATA_HOME, normally ~/.local/share
	ConfigHome string // $XDG_CONFIG_HOME, normally ~/.config
	Exe        string // Absolute path of the GUI program (or AppImage) to run

	// Run runs a helper program (update-mime-database and the like) to
	// refresh the desktop's caches. It reports exec.ErrNotFound when the
	// program isn't installed. Nil means don't run any.
	Run func(name string, args ...string) error
}

// Default returns the integration for the current user, starting the
// running program. Inside an AppImage the AppImage file itself is used
// (its $APPIMAGE path), since the program's own path changes every run.
func Default() (Integration, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Integration{}, errors.New("cannot determine home directory")
	}
	exe := os.Getenv("APPIMAGE")
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return Integration{}, errors.New("cannot find the age-tool program")
		}
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return Integration{}, err
	}
	return Integration{
		DataHome:   xdgDir(os.Getenv("XDG_DATA_HOME"), home, ".local", "share"),
		ConfigHome: xdgDir(os.Getenv("XDG_CONFIG_HOME"), home, ".config"),
		Exe:        exe,
		Run:        runQuietly,
	}, nil
}

// xdgDir returns an XDG variable's value if it is an absolute path (as the
// spec requires), otherwise the default under home.
func xdgDir(value, home string, fallback ...string) string {
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(append([]string{home}, fallback...)...)
}

// runQuietly runs a helper program, discarding its output.
func runQuietly(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return exec.ErrNotFound
	}
	return exec.Command(path, args...).Run() // #nosec G204 -- fixed helper names; arguments are our own folders
}

// ─── Where each piece goes ──────────────────────────────────────────────────

// launcherFile is the app menu entry.
func (in Integration) launcherFile() string {
	return filepath.Join(in.DataHome, "applications", AppID+".desktop")
}

// mimeDir is the user's MIME database, and mimePackage our definition in it.
func (in Integration) mimeDir() string { return filepath.Join(in.DataHome, "mime") }
func (in Integration) mimePackage() string {
	return filepath.Join(in.mimeDir(), "packages", AppID+".xml")
}

// appIconFile and fileIconFile are the scalable icons in the hicolor theme.
func (in Integration) appIconFile() string {
	return filepath.Join(in.DataHome, "icons", "hicolor", "scalable", "apps", AppID+".svg")
}
func (in Integration) fileIconFile() string {
	return filepath.Join(in.DataHome, "icons", "hicolor", "scalable", "mimetypes", mimeIcon+".svg")
}

// nautilusScripts are the Nautilus Scripts-menu entries (named as shown).
func (in Integration) nautilusScripts() []string {
	dir := filepath.Join(in.DataHome, "nautilus", "scripts")
	return []string{filepath.Join(dir, EncryptMenu), filepath.Join(dir, DecryptMenu)}
}

// dolphinMenus are the KDE service menus, in the Plasma 6 and Plasma 5
// locations, one file for encrypting and one for decrypting.
func (in Integration) dolphinMenus() []string {
	var files []string
	for _, dir := range []string{
		filepath.Join(in.DataHome, "kio", "servicemenus"),        // Plasma 6
		filepath.Join(in.DataHome, "kservices5", "ServiceMenus"), // Plasma 5
	} {
		files = append(files, filepath.Join(dir, AppID+"-encrypt.desktop"), filepath.Join(dir, AppID+"-decrypt.desktop"))
	}
	return files
}

// nemoActions are the Nemo right-click actions.
func (in Integration) nemoActions() []string {
	dir := filepath.Join(in.DataHome, "nemo", "actions")
	return []string{filepath.Join(dir, AppID+"-encrypt.nemo_action"), filepath.Join(dir, AppID+"-decrypt.nemo_action")}
}

// thunarActions is Thunar's custom actions file, shared with the user's
// own actions.
func (in Integration) thunarActions() string {
	return filepath.Join(in.ConfigHome, "Thunar", "uca.xml")
}

// mimeApps is the user's default-applications list.
func (in Integration) mimeApps() string {
	return filepath.Join(in.ConfigHome, "mimeapps.list")
}

// ownedFiles lists every file that belongs entirely to age-tool.
func (in Integration) ownedFiles() []string {
	files := []string{in.launcherFile(), in.mimePackage(), in.appIconFile(), in.fileIconFile()}
	files = append(files, in.nautilusScripts()...)
	files = append(files, in.dolphinMenus()...)
	return append(files, in.nemoActions()...)
}

// ─── Status ─────────────────────────────────────────────────────────────────

// Status describes whether the integration is installed.
type Status int

// Installation states.
const (
	NotInstalled Status = iota // No launcher entry
	Installed                  // Installed, starting this program
	Outdated                   // Installed, but starting a different (moved or older) program
)

// Status reports whether the integration is installed, and whether it
// starts this program. An AppImage that has been moved shows as Outdated,
// and installing again fixes every entry.
func (in Integration) Status() Status {
	data, err := os.ReadFile(in.launcherFile())
	if err != nil {
		return NotInstalled
	}
	if bytes.Contains(data, []byte("\nExec="+desktopExec(in.Exe, "%F")+"\n")) {
		return Installed
	}
	return Outdated
}

// ─── Install / remove ───────────────────────────────────────────────────────

// Report says what Install or Uninstall did.
type Report struct {
	Changed  []string // Files written, edited or removed
	Warnings []string // Problems that don't stop the rest working
}

// Install writes every piece of the integration, replacing an earlier
// installation. An error means something essential failed; problems with
// optional pieces (e.g. refreshing a cache) are returned as warnings.
func (in Integration) Install() (Report, error) {
	var r Report
	if err := in.check(); err != nil {
		return r, err
	}

	// Files that belong entirely to age-tool. Scripts and KDE service menus
	// must be executable to be trusted; the rest are ordinary data files.
	type file struct {
		path       string
		content    []byte
		executable bool
	}
	scripts := in.nautilusScripts()
	dolphin := in.dolphinMenus()
	nemo := in.nemoActions()
	files := []file{
		{in.launcherFile(), in.launcherEntry(), false},
		{in.mimePackage(), mimePackageXML(), false},
		{in.appIconFile(), appIconSVG, false},
		{in.fileIconFile(), fileIconSVG, false},
		{scripts[0], in.nautilusScript("encrypt"), true},
		{scripts[1], in.nautilusScript("decrypt"), true},
		{nemo[0], in.nemoAction("encrypt"), false},
		{nemo[1], in.nemoAction("decrypt"), false},
	}
	for i := 0; i < len(dolphin); i += 2 {
		files = append(files,
			file{dolphin[i], in.dolphinMenu("encrypt"), true},
			file{dolphin[i+1], in.dolphinMenu("decrypt"), true})
	}
	for _, f := range files {
		if err := writeFile(f.path, f.content, f.executable); err != nil {
			return r, fmt.Errorf("could not write %s: %w", f.path, err)
		}
		r.Changed = append(r.Changed, f.path)
	}

	// Shared files: add our entries alongside the user's own
	if err := in.installThunarActions(); err != nil {
		r.Warnings = append(r.Warnings, "Thunar right-click entries not added: "+err.Error())
	} else {
		r.Changed = append(r.Changed, in.thunarActions())
	}
	if err := setDefaultApp(in.mimeApps(), MimeType, AppID+".desktop"); err != nil {
		r.Warnings = append(r.Warnings, "age-tool could not be made the default app for .age files: "+err.Error())
	} else {
		r.Changed = append(r.Changed, in.mimeApps())
	}

	r.Warnings = append(r.Warnings, in.refreshCaches()...)
	return r, nil
}

// Uninstall removes everything Install added, leaving the user's own
// entries in shared files untouched. Missing files are not an error.
func (in Integration) Uninstall() (Report, error) {
	var r Report
	var failed []string
	for _, path := range in.ownedFiles() {
		err := os.Remove(path)
		switch {
		case err == nil:
			r.Changed = append(r.Changed, path)
		case !os.IsNotExist(err):
			failed = append(failed, path)
		}
	}

	if changed, err := in.removeThunarActions(); err != nil {
		r.Warnings = append(r.Warnings, "Thunar right-click entries not removed: "+err.Error())
	} else if changed {
		r.Changed = append(r.Changed, in.thunarActions())
	}
	if changed, err := unsetDefaultApp(in.mimeApps(), MimeType, AppID+".desktop"); err != nil {
		r.Warnings = append(r.Warnings, "default app for .age files not reset: "+err.Error())
	} else if changed {
		r.Changed = append(r.Changed, in.mimeApps())
	}

	r.Warnings = append(r.Warnings, in.refreshCaches()...)
	if len(failed) > 0 {
		return r, fmt.Errorf("could not remove %s", strings.Join(failed, ", "))
	}
	return r, nil
}

// check refuses a program path that can't be written safely into the
// menu entries.
func (in Integration) check() error {
	if !filepath.IsAbs(in.Exe) {
		return errors.New("the program path must be absolute")
	}
	if strings.ContainsAny(in.Exe, "\n\r%") {
		return errors.New("the program path contains characters that can't be used in menu entries")
	}
	if in.DataHome == "" || in.ConfigHome == "" {
		return errors.New("the user's data and config folders are unknown")
	}
	return nil
}

// refreshCaches asks the desktop to notice the new or removed files.
// These helpers are optional: without them the menus update after the
// next login. Returns warnings only for helpers that ran and failed.
func (in Integration) refreshCaches() []string {
	if in.Run == nil {
		return nil
	}
	var warnings []string
	helpers := [][]string{
		{"update-mime-database", in.mimeDir()},
		{"update-desktop-database", filepath.Join(in.DataHome, "applications")},
		{"gtk-update-icon-cache", "--ignore-theme-index", filepath.Join(in.DataHome, "icons", "hicolor")},
	}
	for _, h := range helpers {
		if err := in.Run(h[0], h[1:]...); err != nil && !errors.Is(err, exec.ErrNotFound) {
			warnings = append(warnings, fmt.Sprintf("%s failed; changes may only appear after logging out and in", h[0]))
		}
	}
	return warnings
}

// writeFile writes content to path, creating its folders. Executable
// files get 0755, others 0644: desktop entries and icons are read by the
// desktop, not secret, and match what every other app installs.
func writeFile(path string, content []byte, executable bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- standard XDG folders, readable like any app's
		return err
	}
	mode := os.FileMode(0644)
	if executable {
		mode = 0755
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode) // WriteFile keeps an existing file's mode
}
