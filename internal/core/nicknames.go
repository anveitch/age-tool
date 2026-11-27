// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Nicknames maps key filenames (e.g. "work.pub") to human-readable
// nicknames. Each file is nicknamed independently, so a .pub and its
// matching .priv can have different nicknames.
type Nicknames map[string]string

// LoadNicknames reads the nickname file at path. Returns an empty map if
// the file does not exist or cannot be parsed.
func LoadNicknames(path string) Nicknames {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return make(Nicknames)
	}
	var nicks Nicknames
	if err := json.Unmarshal(data, &nicks); err != nil || nicks == nil {
		return make(Nicknames)
	}
	return nicks
}

// Save writes the nicknames to path as readable JSON. The file is
// owner-only (0600). os.WriteFile only applies permissions when creating a
// file, so an existing file from an older version (0644) is explicitly
// tightened as well.
func (n Nicknames) Save(path string) error {
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// Label returns "Nickname (filename)" if the file has a nickname, or just
// "filename" if it does not.
func (n Nicknames) Label(filename string) string {
	if nick, ok := n[filename]; ok && nick != "" {
		return fmt.Sprintf("%s (%s)", nick, filename)
	}
	return filename
}
