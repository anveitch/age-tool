// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Shared files hold the user's own settings alongside ours, so they are
// edited, never replaced: only entries age-tool added are touched.

// ─── Thunar custom actions (uca.xml) ────────────────────────────────────────

// thunarIDPrefix marks Thunar actions that age-tool added.
const thunarIDPrefix = "age-tool-"

// systemThunarActions is Thunar's system-wide default actions file. When a
// user has no uca.xml of their own, Thunar shows these defaults; ours is
// started from a copy so they don't disappear. A variable for tests.
var systemThunarActions = "/etc/xdg/Thunar/uca.xml"

// emptyThunarActions is a uca.xml with no actions.
const emptyThunarActions = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n</actions>\n"

// installThunarActions adds (or replaces) age-tool's Encrypt and Decrypt
// actions in the user's uca.xml, keeping their other actions.
func (in Integration) installThunarActions() error {
	path := in.thunarActions()
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		data, err = os.ReadFile(systemThunarActions)
		if err != nil {
			data, err = []byte(emptyThunarActions), nil
		}
	}
	if err != nil {
		return err
	}

	text, _ := removeThunarBlocks(string(data))
	end := strings.LastIndex(text, "</actions>")
	if end < 0 {
		return errors.New("uca.xml is not in the expected format")
	}
	ours := in.thunarAction("encrypt") + in.thunarAction("decrypt")
	text = text[:end] + ours + text[end:]
	return writeShared(path, text)
}

// removeThunarActions removes age-tool's actions from the user's uca.xml.
// Reports whether the file changed; a missing file is not an error.
func (in Integration) removeThunarActions() (bool, error) {
	path := in.thunarActions()
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	text, changed := removeThunarBlocks(string(data))
	if !changed {
		return false, nil
	}
	return true, writeShared(path, text)
}

// removeThunarBlocks removes every <action>…</action> block whose
// unique-id marks it as age-tool's, with its indentation and line break.
// Reports whether anything was removed.
func removeThunarBlocks(text string) (string, bool) {
	changed := false
	var out strings.Builder
	rest := text
	for {
		start := strings.Index(rest, "<action>")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], "</action>")
		if end < 0 {
			break
		}
		end += start + len("</action>")
		block := rest[start:end]
		if !strings.Contains(block, "<unique-id>"+thunarIDPrefix) {
			// Someone else's action: keep it
			out.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		// Ours: drop it, with the indentation before it and the line
		// break after it
		before := strings.TrimRight(rest[:start], " \t")
		out.WriteString(before)
		rest = strings.TrimPrefix(rest[end:], "\n")
		changed = true
	}
	out.WriteString(rest)
	return out.String(), changed
}

// ─── Default applications (mimeapps.list) ───────────────────────────────────

// defaultSection is the mimeapps.list section naming default apps.
const defaultSection = "[Default Applications]"

// setDefaultApp makes app (a .desktop file name) the default for
// mimeType in the mimeapps.list at path, replacing any previous default
// for that type and keeping everything else.
func setDefaultApp(path, mimeType, app string) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := splitLines(string(data))
	entry := mimeType + "=" + app + ";"

	// Find the section, and any existing line for the type within it
	section := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == defaultSection {
			section = i
			continue
		}
		if section >= 0 && strings.HasPrefix(trimmed, "[") {
			break // past the end of the section
		}
		if section >= 0 && strings.HasPrefix(trimmed, mimeType+"=") {
			lines[i] = entry
			return writeShared(path, joinLines(lines))
		}
	}
	if section >= 0 {
		// Add the entry at the start of the existing section
		lines = append(lines[:section+1], append([]string{entry}, lines[section+1:]...)...)
	} else {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, defaultSection, entry)
	}
	return writeShared(path, joinLines(lines))
}

// unsetDefaultApp removes app from the default apps for mimeType, leaving
// any other app the user chose. Reports whether the file changed; a
// missing file is not an error.
func unsetDefaultApp(path, mimeType, app string) (bool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lines := splitLines(string(data))
	inSection, changed := false, false
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inSection = trimmed == defaultSection
		}
		if inSection && strings.HasPrefix(trimmed, mimeType+"=") {
			// Keep any other apps listed for the type
			var keep []string
			found := false
			for a := range strings.SplitSeq(strings.TrimPrefix(trimmed, mimeType+"="), ";") {
				switch {
				case a == app:
					found = true
				case a != "":
					keep = append(keep, a)
				}
			}
			if !found {
				out = append(out, line) // the user chose another app: leave it
				continue
			}
			changed = true
			if len(keep) > 0 {
				out = append(out, mimeType+"="+strings.Join(keep, ";")+";")
			}
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return false, nil
	}
	return true, writeShared(path, joinLines(out))
}

// splitLines splits text into lines, without a trailing empty line.
func splitLines(text string) []string {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// joinLines joins lines, ending with a line break.
func joinLines(lines []string) string {
	return strings.Join(lines, "\n") + "\n"
}

// writeShared writes a shared settings file, keeping its permissions if it
// exists (0644 if new) and creating its folder if needed.
func writeShared(path, text string) error {
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- standard XDG config folders
		return err
	}
	// The path is built from the user's own XDG folders, for their own files
	return os.WriteFile(filepath.Clean(path), []byte(text), mode) // #nosec G703 -- user's own XDG config folder
}
