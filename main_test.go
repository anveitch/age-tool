// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// input returns a reader that supplies the given lines as typed input.
func input(lines ...string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(strings.Join(lines, "\n") + "\n"))
}

// TestPromptSelectionOrBack covers choosing an item, choosing Go Back, and
// re-prompting after invalid input.
func TestPromptSelectionOrBack(t *testing.T) {
	cases := []struct {
		name    string
		in      *bufio.Reader
		wantIdx int
		wantOK  bool
	}{
		{"first item", input("1"), 0, true},
		{"last item", input("3"), 2, true},
		{"go back", input("4"), 3, false},
		{"invalid then valid", input("0", "abc", "9", "2"), 1, true},
	}
	for _, c := range cases {
		idx, ok := promptSelectionOrBack(c.in, "Pick", 3)
		if idx != c.wantIdx || ok != c.wantOK {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, idx, ok, c.wantIdx, c.wantOK)
		}
	}
}

// TestConfirmDefaultYes treats empty input as yes and anything else but
// y/yes as no.
func TestConfirmDefaultYes(t *testing.T) {
	for answer, want := range map[string]bool{"": true, "y": true, "YES": true, "n": false, "no": false, "maybe": false} {
		if got := confirmDefaultYes(input(answer)); got != want {
			t.Errorf("confirmDefaultYes(%q) = %v, want %v", answer, got, want)
		}
	}
}

// TestConfirmOverwrite only asks when the file exists, and defaults to no.
func TestConfirmOverwrite(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	existing := filepath.Join(dir, "existing.txt")
	os.WriteFile(existing, []byte("x"), 0600)

	if !confirmOverwrite(input(), missing) {
		t.Error("a missing file should not need confirmation")
	}
	if confirmOverwrite(input(""), existing) {
		t.Error("an existing file should default to not overwriting")
	}
	if !confirmOverwrite(input("y"), existing) {
		t.Error("answering y should allow overwriting")
	}
}

// TestParseArgs covers the supported options, both -flag and --flag forms,
// and rejection of unknown options and stray arguments.
func TestParseArgs(t *testing.T) {
	cases := []struct {
		args    []string
		want    options
		wantErr bool
	}{
		{nil, options{}, false},
		{[]string{"--keys", "/media/usb/keys"}, options{keysDir: "/media/usb/keys"}, false},
		{[]string{"-keys=."}, options{keysDir: "."}, false},
		{[]string{"--version"}, options{showVersion: true}, false},
		{[]string{"--help"}, options{showHelp: true}, false},
		{[]string{"-h"}, options{showHelp: true}, false},
		{[]string{"--bogus"}, options{}, true},
		{[]string{"--keys"}, options{}, true},
		{[]string{"stray"}, options{}, true},
	}
	for _, c := range cases {
		got, err := parseArgs(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("parseArgs(%q): err = %v, wantErr %v", c.args, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parseArgs(%q) = %+v, want %+v", c.args, got, c.want)
		}
	}
}
