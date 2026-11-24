//go:build screenshots

// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Screenshot tour, for checking the real window and for the user guide's
// screenshots. It is only compiled with the "screenshots" build tag:
//
//	go build -tags screenshots -o /tmp/age-tool-tour ./cmd/age-tool-gui
//	mkdir -p /tmp/tour/Library/Caches /tmp/shots
//	HOME=/tmp/tour AGE_TOOL_SCREENSHOTS=/tmp/shots /tmp/age-tool-tour
//
// (Build first: running "go run" with a different HOME re-downloads every
// module into it.)
//
// It walks through every screen in the real window, saving a PNG of each
// to $AGE_TOOL_SCREENSHOTS, then quits. It creates sample keys and files,
// so ALWAYS run it with HOME set to a throwaway folder as above.
package main

import (
	"image/png"
	"os"
	"path/filepath"
	"time"

	"age-tool/internal/app"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

func init() {
	devHook = func(g *gui) {
		dir := os.Getenv("AGE_TOOL_SCREENSHOTS")
		if dir == "" {
			return // no output folder: behave as the normal app
		}
		go func() {
			// shot shows a screen on the UI thread, waits for it to settle,
			// then saves the window's own rendering
			shot := func(name string, show func()) {
				fyne.DoAndWait(func() {
					for top := g.win.Canvas().Overlays().Top(); top != nil; top = g.win.Canvas().Overlays().Top() {
						g.win.Canvas().Overlays().Remove(top)
					}
					show()
				})
				time.Sleep(800 * time.Millisecond)
				fyne.DoAndWait(func() {
					f, err := os.Create(filepath.Join(dir, name+".png"))
					if err == nil {
						_ = png.Encode(f, g.win.Canvas().Capture())
						_ = f.Close()
					}
				})
			}
			time.Sleep(time.Second)
			shot("01-home", g.showHome)
			shot("02-encrypt-no-keys", func() { g.showEncrypt(nil) })
			shot("03-keys-empty", g.showKeys)

			// Sample keys and a file
			_, _ = g.svc.GenerateKey("laptop", "My laptop key", []byte("correct horse battery"), []byte("correct horse battery"))
			open, _ := age.GenerateX25519Identity()
			_ = os.WriteFile(filepath.Join(g.svc.KeysDir, "old.priv"), []byte(open.String()+"\n"), 0600)
			c, _ := age.GenerateX25519Identity()
			_ = g.svc.ImportContact("alice", "Alice Smith", c.Recipient().String())
			docs := filepath.Join(os.Getenv("HOME"), "Documents")
			_ = os.MkdirAll(docs, 0700)
			input := filepath.Join(docs, "Quarterly report with a long name.pdf")
			_ = os.WriteFile(input, []byte("secret"), 0600)

			shot("04-keys", func() { g.showKeys(); devFindList(g.win.Content()).Select(1) })
			shot("05-create-key", func() { g.showCreateKey("", "", "") })
			shot("06-add-contact", func() { g.showAddContact("", "", "", "") })
			keys, _ := g.svc.Keys()
			shot("07-share", func() { g.showShareKey(keys[1]) })
			shot("08-protect", func() { g.showProtectKey(keys[2], "") })
			shot("09-delete", func() { g.confirmDeleteKey(keys[1]) })
			shot("10-encrypt", func() { g.showEncrypt([]string{input}) })
			_, _ = g.svc.Encrypt(input, "laptop.pub", false)
			shot("11-decrypt", func() { g.showDecrypt([]string{input + ".age"}) })
			shot("12-replace", func() { g.confirmReplace(input, func() {}, func() {}) })
			d, err := g.svc.StartDecrypt(input+".age", "laptop.priv", true)
			if err == nil {
				ch := app.Choice{File: "laptop.priv", Name: "My laptop key", Protected: true}
				shot("13-passphrase", func() { g.askPassphrase(d, ch, input+".age", app.AttemptsMessage(2), func(string) {}, func() {}) })
			}
			shot("14-saved", func() { g.reportSaved("Encrypted", []string{input + ".age"}, "Alice Smith") })
			shot("15-activity", g.showActivity)
			fyne.Do(g.fy.Quit)
		}()
	}
}

// devFindList returns the first list in the content.
func devFindList(o fyne.CanvasObject) *widget.List {
	switch v := o.(type) {
	case *widget.List:
		return v
	case *fyne.Container:
		for _, c := range v.Objects {
			if l := devFindList(c); l != nil {
				return l
			}
		}
	}
	return nil
}
