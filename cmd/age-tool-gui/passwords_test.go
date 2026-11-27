// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// guiFilePassword is a file password that meets the default rules.
const guiFilePassword = "Tr4vel#Bus-ride"

// layers returns what's on screen, top first: open dialogs, then the
// window content.
func layers(g *gui) []fyne.CanvasObject {
	overlays := g.win.Canvas().Overlays().List()
	var out []fyne.CanvasObject
	for i := len(overlays) - 1; i >= 0; i-- {
		out = append(out, overlays[i])
	}
	return append(out, g.win.Content())
}

// findButton returns the button labelled text, searching the top dialog
// first, or nil.
func findButton(g *gui, text string) *widget.Button {
	for _, layer := range layers(g) {
		var found *widget.Button
		walk(layer, func(o fyne.CanvasObject) {
			if b, ok := o.(*widget.Button); ok && b.Text == text && found == nil {
				found = b
			}
		})
		if found != nil {
			return found
		}
	}
	return nil
}

// tapButton taps the button labelled text, failing if there is none or it
// is disabled.
func tapButton(t *testing.T, g *gui, text string) {
	t.Helper()
	b := findButton(g, text)
	if b == nil {
		t.Fatalf("no %q button on screen:\n%s", text, screenText(g))
	}
	if b.Disabled() {
		t.Fatalf("%q button is disabled", text)
	}
	test.Tap(b)
}

// passwordEntries returns the password fields in the top layer.
func passwordEntries(g *gui) []*widget.Entry {
	var entries []*widget.Entry
	walk(layers(g)[0], func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.Password {
			entries = append(entries, e)
		}
	})
	return entries
}

// screenText returns all label text on screen, top layer first.
func screenText(g *gui) string {
	var b strings.Builder
	for _, layer := range layers(g) {
		walk(layer, func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok && l.Text != "" {
				b.WriteString(l.Text + "\n")
			}
		})
	}
	return b.String()
}

// findRadio returns the first radio group in the window content.
func findRadio(g *gui) *widget.RadioGroup {
	var found *widget.RadioGroup
	walk(g.win.Content(), func(o fyne.CanvasObject) {
		if r, ok := o.(*widget.RadioGroup); ok && found == nil {
			found = r
		}
	})
	return found
}

// TestEncryptWithPasswordNoKeys encrypts with a typed password when the
// user has no keys: the password option is chosen for them, and the
// password is shown once since no record can be saved.
func TestEncryptWithPasswordNoKeys(t *testing.T) {
	g, docs := newTestGUI(t)
	input := filepath.Join(docs, "notes.txt")
	if err := os.WriteFile(input, []byte("meeting notes"), 0600); err != nil {
		t.Fatal(err)
	}

	g.showEncrypt([]string{input})
	if r := findRadio(g); r == nil || r.Selected != passwordChoice {
		t.Fatal("password option not chosen when there are no keys")
	}
	encrypt := findButton(g, "Encrypt")
	entries := passwordEntries(g)
	if len(entries) != 2 {
		t.Fatalf("%d password fields, want 2", len(entries))
	}

	// A weak password: refused, Encrypt stays disabled
	test.Type(entries[0], "Summer26!")
	test.Type(entries[1], "Summer26!")
	if !encrypt.Disabled() || !strings.Contains(screenText(g), "too easy to guess") {
		t.Fatalf("weak password accepted:\n%s", screenText(g))
	}

	// A good one
	entries[0].SetText("")
	entries[1].SetText("")
	test.Type(entries[0], guiFilePassword)
	test.Type(entries[1], guiFilePassword)
	if encrypt.Disabled() {
		t.Fatalf("Encrypt disabled for a good password:\n%s", screenText(g))
	}
	capture(t, g, "pw-01-encrypt")

	test.Tap(encrypt)
	waitIdle(t, g)
	if !strings.Contains(screenText(g), guiFilePassword) {
		t.Fatalf("password not shown once:\n%s", screenText(g))
	}
	capture(t, g, "pw-02-shown-once")
	tapButton(t, g, "I've noted it")

	if m, err := core.FileLockMethod(input + ".age"); err != nil || m != core.LockedWithPassword {
		t.Fatalf("FileLockMethod = %v, %v", m, err)
	}
	if recs, _, _ := g.svc.PasswordRecords(); len(recs) != 0 {
		t.Errorf("a record was saved without a key: %+v", recs)
	}
}

// TestPasswordJourney takes a suggested password with a key of one's own,
// saves a record, decrypts the file (a wrong try first) and shows the
// saved password.
func TestPasswordJourney(t *testing.T) {
	g, docs := newTestGUI(t)
	if _, err := g.svc.GenerateKey("laptop", "My laptop key", []byte(testPass), []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(docs, "notes.txt")
	if err := os.WriteFile(input, []byte("meeting notes"), 0600); err != nil {
		t.Fatal(err)
	}

	// Encrypt with a suggested password
	g.showEncrypt([]string{input})
	findRadio(g).SetSelected(passwordChoice)
	tapButton(t, g, "Suggest a password")
	entries := passwordEntries(g)
	suggested := entries[0].Text
	if suggested == "" || entries[1].Text != suggested || !strings.Contains(screenText(g), suggested) {
		t.Fatalf("suggestion not filled in and shown: %q", suggested)
	}
	capture(t, g, "pw-03-suggested")
	tapButton(t, g, "Encrypt")
	waitIdle(t, g)

	// Keep a record (the default)
	if !strings.Contains(screenText(g), "Keep a record of this password?") {
		t.Fatalf("record question not asked:\n%s", screenText(g))
	}
	capture(t, g, "pw-04-keep-record")
	tapButton(t, g, "Continue")
	if !strings.Contains(screenText(g), "A record of the password is saved") {
		t.Fatalf("record not confirmed:\n%s", screenText(g))
	}
	recs, _, _ := g.svc.PasswordRecords()
	if len(recs) != 1 {
		t.Fatalf("%d records, want 1", len(recs))
	}
	closeDialogs(g)

	// Decrypt: step 2 explains no key is needed
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	g.showDecrypt([]string{input + ".age"})
	if !strings.Contains(screenText(g), "protected with a password, so no key is needed") {
		t.Fatalf("decrypt screen doesn't explain the password:\n%s", screenText(g))
	}
	capture(t, g, "pw-05-decrypt")
	tapButton(t, g, "Decrypt")
	if !strings.Contains(screenText(g), "You have a saved record of this file's password") {
		t.Errorf("saved record not mentioned:\n%s", screenText(g))
	}

	// A wrong password, then the right one
	test.Type(passwordEntries(g)[0], "Wrong#pass-1")
	tapButton(t, g, "Decrypt")
	waitIdle(t, g)
	if !strings.Contains(screenText(g), "That password is incorrect. 2 attempts left.") {
		t.Fatalf("wrong password not reported:\n%s", screenText(g))
	}
	capture(t, g, "pw-06-wrong-password")
	test.Type(passwordEntries(g)[0], suggested)
	tapButton(t, g, "Decrypt")
	waitIdle(t, g)
	if got, _ := os.ReadFile(input); string(got) != "meeting notes" {
		t.Fatalf("decrypted %q", got)
	}
	closeDialogs(g)

	// Saved passwords: select it, show it with the key's passphrase
	g.showSavedPasswords()
	list := findList(g.win.Content())
	if list == nil {
		t.Fatal("saved passwords list not found")
	}
	list.Select(0)
	capture(t, g, "pw-07-saved")
	tapButton(t, g, "Show password")
	test.Type(passwordEntries(g)[0], testPass)
	tapButton(t, g, "Show")
	waitIdle(t, g)
	if !strings.Contains(screenText(g), suggested) || !strings.Contains(screenText(g), input+".age") {
		t.Fatalf("saved password not shown:\n%s", screenText(g))
	}
	capture(t, g, "pw-08-shown")
	tapButton(t, g, "Close")

	// Delete it
	list = findList(g.win.Content())
	list.Select(0)
	tapButton(t, g, "Delete")
	tapButton(t, g, "Delete") // the confirmation dialog's button
	if recs, _, _ := g.svc.PasswordRecords(); len(recs) != 0 {
		t.Errorf("record not deleted: %+v", recs)
	}
	if !strings.Contains(screenText(g), "No saved passwords yet") {
		t.Errorf("empty list not shown:\n%s", screenText(g))
	}

	// The activity view describes both as password transactions
	g.showActivity()
	text := screenText(g)
	for _, want := range []string{"Encrypted notes.txt with a password", "Decrypted notes.txt.age with a password"} {
		if !strings.Contains(text, want) {
			t.Errorf("activity lacks %q:\n%s", want, text)
		}
	}
	capture(t, g, "pw-09-activity")
}

// TestDecryptMixedFiles decrypts a password file and a key file chosen
// together: each is decrypted its own way.
func TestDecryptMixedFiles(t *testing.T) {
	g, docs := newTestGUI(t)
	if _, err := g.svc.GenerateKey("laptop", "", []byte(testPass), []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(docs, "a.txt")
	keyFile := filepath.Join(docs, "b.txt")
	for _, f := range []string{pwFile, keyFile} {
		if err := os.WriteFile(f, []byte("content of "+filepath.Base(f)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.svc.EncryptWithPassword(pwFile, guiFilePassword, false); err != nil {
		t.Fatal(err)
	}
	if _, err := g.svc.Encrypt(keyFile, "laptop.pub", false); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(pwFile)
	_ = os.Remove(keyFile)

	// A key file is chosen too, so step 2 asks for a key
	g.showDecrypt([]string{pwFile + ".age", keyFile + ".age"})
	if r := findRadio(g); r == nil || r.Selected == "" {
		t.Fatal("key choice not offered for a key file")
	}
	tapButton(t, g, "Decrypt")
	test.Type(passwordEntries(g)[0], guiFilePassword) // a.txt.age: its password
	tapButton(t, g, "Decrypt")
	waitIdle(t, g)
	test.Type(passwordEntries(g)[0], testPass) // b.txt.age: the key's passphrase
	tapButton(t, g, "Decrypt")
	waitIdle(t, g)
	for _, f := range []string{pwFile, keyFile} {
		if got, _ := os.ReadFile(f); string(got) != "content of "+filepath.Base(f) {
			t.Errorf("%s decrypted as %q", filepath.Base(f), got)
		}
	}
}
