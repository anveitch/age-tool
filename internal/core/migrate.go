// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"bytes"
	"os"
	"path/filepath"
)

// ImportResult reports what ImportKeyFiles did with each key file.
type ImportResult struct {
	Imported       []string // Copied into the key store
	AlreadyPresent []string // An identical file was already in the key store
	Conflicts      []string // A different file with the same name is already in the key store; skipped
	Failed         []string // Couldn't be read or written
}

// ImportKeyFiles copies every .pub and .priv file from srcDir (a 1.x-style
// folder) into keysDir, the key store, along with their nicknames from
// srcDir's keys.json. Nothing in srcDir is changed or deleted.
//
// Existing files in the key store are never overwritten: an identical file
// counts as already present, and a different one is reported as a
// conflict. Existing nicknames in the key store are kept. Copies are
// owner-only (0600), and keysDir is created owner-only (0700) if needed.
func ImportKeyFiles(srcDir, keysDir string) (ImportResult, error) {
	var result ImportResult
	files, err := ListKeyFiles(srcDir)
	if err != nil {
		return result, err
	}
	if err := EnsurePrivateDir(keysDir); err != nil {
		return result, err
	}

	for _, name := range files {
		data, err := readLimited(filepath.Join(srcDir, name), maxKeyFileSize)
		if err != nil {
			result.Failed = append(result.Failed, name)
			continue
		}
		dest := filepath.Join(keysDir, name)
		if existing, err := os.ReadFile(filepath.Clean(dest)); err == nil {
			if bytes.Equal(existing, data) {
				result.AlreadyPresent = append(result.AlreadyPresent, name)
			} else {
				result.Conflicts = append(result.Conflicts, name)
			}
			ClearBytes(existing)
			ClearBytes(data)
			continue
		}
		if err := writeNewFile(dest, data); err != nil {
			result.Failed = append(result.Failed, name)
		} else {
			result.Imported = append(result.Imported, name)
		}
		// Key files may hold (protected or not) private key material
		ClearBytes(data)
	}

	// Carry over nicknames for imported files, without replacing any the
	// key store already has
	if len(result.Imported) > 0 {
		srcNicks := LoadNicknames(filepath.Join(srcDir, NicknameFileName))
		destPath := filepath.Join(keysDir, NicknameFileName)
		destNicks := LoadNicknames(destPath)
		changed := false
		for _, name := range result.Imported {
			if nick := srcNicks[name]; nick != "" && destNicks[name] == "" {
				destNicks[name] = nick
				changed = true
			}
		}
		if changed {
			if err := destNicks.Save(destPath); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}
