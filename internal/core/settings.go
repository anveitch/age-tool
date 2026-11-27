// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
)

// Settings holds user preferences that persist between runs.
type Settings struct {
	// MigrationDismissed lists folders (absolute paths) where the user chose
	// "don't ask again" when offered to import 1.x keys into the key store.
	MigrationDismissed []string `json:"migration_dismissed,omitempty"`

	// FilePasswordRules, if set, makes the rules for file passwords
	// stricter than the defaults (see PasswordRules.Effective). It can't
	// make them weaker.
	FilePasswordRules *PasswordRules `json:"password_rules,omitempty"`
}

// PasswordRules returns the rules for file passwords: those in the
// settings file, never weaker than DefaultPasswordRules.
func (s Settings) PasswordRules() PasswordRules {
	if s.FilePasswordRules == nil {
		return DefaultPasswordRules
	}
	return s.FilePasswordRules.Effective()
}

// LoadSettings reads the settings file at path. A missing or unreadable
// file gives default settings.
func LoadSettings(path string) Settings {
	var s Settings
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Settings{}
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}
	}
	return s
}

// Save writes the settings to path (owner-only, 0600), creating its
// directory (0700) if needed.
func (s Settings) Save(path string) error {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// IsMigrationDismissed reports whether the user asked not to be offered a
// key import from dir again.
func (s Settings) IsMigrationDismissed(dir string) bool {
	abs, err := filepath.Abs(dir)
	return err == nil && slices.Contains(s.MigrationDismissed, abs)
}

// DismissMigration records that the user doesn't want to be offered a key
// import from dir again.
func (s *Settings) DismissMigration(dir string) {
	abs, err := filepath.Abs(dir)
	if err == nil && !slices.Contains(s.MigrationDismissed, abs) {
		s.MigrationDismissed = append(s.MigrationDismissed, abs)
	}
}
