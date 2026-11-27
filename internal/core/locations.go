// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// appDirName is the per-user directory name used under each OS location.
const appDirName = "age-tool"

// NicknameFileName is the nickname file kept beside the keys it names.
const NicknameFileName = "keys.json"

// Locations says where age-tool keeps its files.
type Locations struct {
	KeysDir   string // .pub / .priv key files and their keys.json nicknames
	ConfigDir string // settings.json
	StateDir  string // central audit log and receipts
}

// NicknameFile returns the path of the nickname file for the keys.
func (l Locations) NicknameFile() string {
	return filepath.Join(l.KeysDir, NicknameFileName)
}

// SettingsFile returns the path of the settings file.
func (l Locations) SettingsFile() string {
	return filepath.Join(l.ConfigDir, "settings.json")
}

// CentralAudit returns the central audit log, which records full paths so
// entries are meaningful regardless of which folder they came from.
func (l Locations) CentralAudit() AuditLog {
	return AuditLog{
		LogFile:       filepath.Join(l.StateDir, "age-tool.log"),
		ReceiptsDir:   filepath.Join(l.StateDir, "receipts"),
		AbsolutePaths: true,
	}
}

// LocalAudit returns the 1.x-style audit log kept in dir: age-tool.log and
// a logs/ directory of receipts, recording paths as given.
func LocalAudit(dir string) AuditLog {
	return AuditLog{
		LogFile:     filepath.Join(dir, "age-tool.log"),
		ReceiptsDir: filepath.Join(dir, "logs"),
	}
}

// DefaultLocations returns the standard per-user locations for this OS:
//
//	Linux:   keys   $XDG_DATA_HOME/age-tool/keys  (~/.local/share/age-tool/keys)
//	         config $XDG_CONFIG_HOME/age-tool     (~/.config/age-tool)
//	         state  $XDG_STATE_HOME/age-tool      (~/.local/state/age-tool)
//	macOS:   keys   ~/Library/Application Support/age-tool/keys
//	         config ~/Library/Application Support/age-tool
//	         state  ~/Library/Logs/age-tool
//	Windows: keys   %AppData%\age-tool\keys
//	         config %AppData%\age-tool
//	         state  %LocalAppData%\age-tool\logs
func DefaultLocations() (Locations, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Locations{}, fmt.Errorf("cannot determine home directory")
	}
	return locationsFor(runtime.GOOS, os.Getenv, home)
}

// locationsFor computes the locations for a given OS, environment and home
// directory. It is separate from DefaultLocations so every OS can be tested.
func locationsFor(goos string, getenv func(string) string, home string) (Locations, error) {
	if home == "" {
		return Locations{}, errors.New("cannot determine home directory")
	}
	join := filepath.Join
	if goos == "windows" {
		// Build Windows paths with backslashes even when tested elsewhere
		join = func(parts ...string) string {
			p := parts[0]
			for _, s := range parts[1:] {
				p += `\` + s
			}
			return p
		}
	}

	switch goos {
	case "windows":
		roaming := getenv("APPDATA")
		if roaming == "" {
			roaming = join(home, "AppData", "Roaming")
		}
		local := getenv("LOCALAPPDATA")
		if local == "" {
			local = join(home, "AppData", "Local")
		}
		return Locations{
			KeysDir:   join(roaming, appDirName, "keys"),
			ConfigDir: join(roaming, appDirName),
			StateDir:  join(local, appDirName, "logs"),
		}, nil

	case "darwin":
		support := join(home, "Library", "Application Support", appDirName)
		return Locations{
			KeysDir:   join(support, "keys"),
			ConfigDir: support,
			StateDir:  join(home, "Library", "Logs", appDirName),
		}, nil

	default:
		// Linux and other Unix systems follow the XDG Base Directory spec.
		// Per the spec, only absolute paths in the variables are honoured.
		xdg := func(variable string, fallback ...string) string {
			if v := getenv(variable); filepath.IsAbs(v) {
				return v
			}
			return join(append([]string{home}, fallback...)...)
		}
		return Locations{
			KeysDir:   join(xdg("XDG_DATA_HOME", ".local", "share"), appDirName, "keys"),
			ConfigDir: join(xdg("XDG_CONFIG_HOME", ".config"), appDirName),
			StateDir:  join(xdg("XDG_STATE_HOME", ".local", "state"), appDirName),
		}, nil
	}
}

// EnsurePrivateDir creates dir (and any parents) if needed, and makes sure
// dir itself is owner-only (0700). Returns an error if it can't be created
// or tightened.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("could not create %s", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("could not access %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if info.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(dir, 0700); err != nil { // #nosec G302 -- directories need the execute bit; 0700 is owner-only
			return fmt.Errorf("could not restrict permissions on %s", dir)
		}
	}
	return nil
}

// DirPermissionWarning returns a warning if dir allows any group or world
// access, or "" if it is owner-only or doesn't exist.
func DirPermissionWarning(dir string) string {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ""
	}
	if mode := info.Mode().Perm(); mode&0077 != 0 {
		return fmt.Sprintf("folder has overly permissive permissions (%04o)", mode)
	}
	return ""
}

// SameDir reports whether two paths refer to the same directory.
func SameDir(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(ia, ib)
	}
	absA, _ := filepath.Abs(a)
	absB, _ := filepath.Abs(b)
	return absA == absB
}
