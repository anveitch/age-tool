// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"age-tool/internal/app"
	"age-tool/internal/core"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// testPass is a valid passphrase for test keys.
const testPass = "correct horse battery"

// newTestGUI returns a gui using Fyne's headless test driver, with its key
// store and logs in a temporary folder, plus a folder for user files.
func newTestGUI(t *testing.T) (*gui, string) {
	t.Helper()
	root := t.TempDir()
	svc, err := app.NewWithLocations(core.Locations{
		KeysDir:   filepath.Join(root, "keys"),
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := test.NewTempApp(t)
	g := &gui{fy: a, win: a.NewWindow("age-tool"), svc: svc}
	g.win.Resize(fyne.NewSize(620, 520))
	docs := filepath.Join(root, "docs")
	if err := os.Mkdir(docs, 0700); err != nil {
		t.Fatal(err)
	}
	return g, docs
}

// capture saves the window as name.png in $AGE_TOOL_SCREENSHOTS, if set,
// so the screens can be checked by eye.
func capture(t *testing.T, g *gui, name string) {
	t.Helper()
	dir := os.Getenv("AGE_TOOL_SCREENSHOTS")
	if dir == "" {
		return
	}
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// A real window lays out again once wrapped text knows its width;
	// nudge the size so the headless window does the same before capturing
	size := g.win.Canvas().Size()
	g.win.Resize(size.AddWidthHeight(1, 0))
	g.win.Resize(size)
	if err := png.Encode(f, g.win.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

// closeDialogs removes any open dialogs, so each screenshot shows only
// the step being checked.
func closeDialogs(g *gui) {
	for top := g.win.Canvas().Overlays().Top(); top != nil; top = g.win.Canvas().Overlays().Top() {
		g.win.Canvas().Overlays().Remove(top)
	}
}

// waitIdle waits for background work started with runBusy to finish.
func waitIdle(t *testing.T, g *gui) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for g.busy {
		if time.Now().After(deadline) {
			t.Fatal("background work did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// findList returns the first widget.List in the window's content.
func findList(o fyne.CanvasObject) *widget.List {
	switch v := o.(type) {
	case *widget.List:
		return v
	case *fyne.Container:
		for _, c := range v.Objects {
			if l := findList(c); l != nil {
				return l
			}
		}
	}
	return nil
}

// TestScreens builds every screen and dialog with real keys and files, so
// a broken layout or list row panics here rather than in front of a user.
func TestScreens(t *testing.T) {
	g, docs := newTestGUI(t)

	// Empty states first
	closeDialogs(g)
	g.showHome()
	capture(t, g, "01-home")
	closeDialogs(g)
	g.showKeys()
	capture(t, g, "02-keys-empty")
	closeDialogs(g)
	g.showEncrypt(nil)
	capture(t, g, "03-encrypt-no-keys")
	closeDialogs(g)
	g.showActivity()

	// A protected key, an unprotected one, and a contact
	if _, err := g.svc.GenerateKey("laptop", "My laptop key", []byte(testPass), []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	open, _ := age.GenerateX25519Identity()
	if err := os.WriteFile(filepath.Join(g.svc.KeysDir, "old.priv"), []byte(open.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	contact, _ := age.GenerateX25519Identity()
	if err := g.svc.ImportContact("alice", "Alice Smith", contact.Recipient().String()); err != nil {
		t.Fatal(err)
	}

	closeDialogs(g)
	g.showKeys()
	list := findList(g.win.Content())
	if list == nil {
		t.Fatal("keys list not found")
	}
	list.Select(1) // laptop
	capture(t, g, "04-keys")

	// Each dialog on the keys screen
	closeDialogs(g)
	g.showCreateKey("", "", "")
	capture(t, g, "05-create-key")
	closeDialogs(g)
	g.showKeys()
	closeDialogs(g)
	g.showAddContact("", "", "", "That isn't a valid public key.")
	capture(t, g, "06-add-contact")
	closeDialogs(g)
	g.showKeys()
	keys, _ := g.svc.Keys()
	closeDialogs(g)
	g.showShareKey(keys[1])
	capture(t, g, "07-share-key")
	closeDialogs(g)
	g.showKeys()
	closeDialogs(g)
	g.showProtectKey(keys[2], "")
	closeDialogs(g)
	g.showKeys()
	closeDialogs(g)
	g.showRenameKey(keys[0])
	closeDialogs(g)
	g.showKeys()
	closeDialogs(g)
	g.confirmDeleteKey(keys[0])

	// Encrypt and decrypt screens, with a file chosen
	input := filepath.Join(docs, "report.txt")
	if err := os.WriteFile(input, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	closeDialogs(g)
	g.showEncrypt([]string{input})
	capture(t, g, "08-encrypt")

	// Encrypt through the GUI's own flow, for the laptop key
	recipients, _ := g.svc.Recipients()
	var mine app.Choice
	for _, r := range recipients {
		if r.File == "laptop.pub" {
			mine = r
		}
	}
	g.encryptFiles([]string{input}, mine, 0, nil)
	waitIdle(t, g)
	capture(t, g, "09-encrypted")
	if !core.FileExists(input + ".age") {
		t.Fatal("encrypt flow did not write the .age file")
	}

	closeDialogs(g)
	g.showDecrypt([]string{input + ".age"})
	capture(t, g, "10-decrypt")
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	ids, _ := g.svc.Identities()
	var laptop app.Choice
	for _, id := range ids {
		if id.File == "laptop.priv" {
			laptop = id
		}
	}
	d, err := g.svc.StartDecrypt(input+".age", laptop.File, false)
	if err != nil {
		t.Fatal(err)
	}
	closeDialogs(g)
	g.askPassphrase(d, laptop, input+".age", app.AttemptsMessage(2), func(string) {}, func() {})
	capture(t, g, "11-passphrase")

	closeDialogs(g)
	g.showActivity()
	capture(t, g, "12-activity")

	// Only reads the integration status; nothing is installed
	closeDialogs(g)
	g.showIntegration()
	capture(t, g, "13-integration")
}

// TestDroppedFilesChooseWorkflow checks that dropping files opens the
// matching screen, and that a mixture is refused.
func TestDroppedFilesChooseWorkflow(t *testing.T) {
	g, docs := newTestGUI(t)
	closeDialogs(g)
	g.showHome()
	home := g.win.Content()

	// A mixture of encrypted and other files is refused
	plain := storage.NewFileURI(filepath.Join(docs, "a.txt"))
	encrypted := storage.NewFileURI(filepath.Join(docs, "b.txt.age"))
	g.openDropped([]fyne.URI{plain, encrypted})
	if g.win.Content() != home {
		t.Error("a mixed drop changed the screen")
	}

	// Other files open the encrypt screen (which, with no keys, explains
	// that a key is needed)
	g.openDropped([]fyne.URI{plain})
	if g.win.Content() == home {
		t.Error("dropping a file didn't open a workflow")
	}
}
