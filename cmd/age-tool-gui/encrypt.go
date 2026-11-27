// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"age-tool/internal/app"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showEncrypt shows the encrypt screen: 1. choose a file, 2. choose who
// it's for, then Encrypt. files pre-fills step 1 (from the command line or
// a drop); with several files, each is encrypted for the same person.
func (g *gui) showEncrypt(files []string) {
	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.ConfirmIcon(), nil)
	encryptBtn.Importance = widget.HighImportance

	// Step 2: the people (keys) a file can be encrypted for
	recipients, err := g.svc.Recipients()
	if err != nil {
		g.problem("Couldn't read your keys", err, g.showHome)
		return
	}
	if len(recipients) == 0 {
		g.showNoKeys("Encrypt a file", "You need a key before you can encrypt files. "+
			"Create your own key, or add a contact's public key to encrypt files for them.")
		return
	}
	labels, byLabel := g.recipientLabels(recipients)
	who := widget.NewRadioGroup(labels, nil)
	if len(labels) == 1 {
		who.SetSelected(labels[0]) // Only one choice: pick it
	}

	// Encrypt is enabled once both steps are complete
	update := func() {
		if len(files) > 0 && who.Selected != "" {
			encryptBtn.Enable()
		} else {
			encryptBtn.Disable()
		}
	}
	who.OnChanged = func(string) { update() }
	fileStep := g.fileStep(files, false, func(chosen []string) {
		files = chosen
		update()
	})
	update()

	encryptBtn.OnTapped = func() {
		g.encryptFiles(files, byLabel[who.Selected], 0, nil)
	}

	g.showScreen("Encrypt a file", true, workflowLayout(
		[]fyne.CanvasObject{
			stepHeading("1. Choose the file to encrypt"),
			fileStep,
			widget.NewSeparator(),
			stepHeading("2. Who is it for?"),
		},
		who,
		"The encrypted copy is saved next to the original, ending in .age. The original is not changed.",
		encryptBtn))
}

// recipientLabels makes a label for each public key: its name, marked
// "(you)" when it is one of the user's own keys. Duplicate names get the
// file name added so every label is unique. Returns the labels in order
// and the choice each label stands for.
func (g *gui) recipientLabels(recipients []app.Choice) ([]string, map[string]app.Choice) {
	own := map[string]bool{}
	if keys, err := g.svc.Keys(); err == nil {
		for _, k := range keys {
			if !k.Contact {
				own[k.PubFile] = true
			}
		}
	}
	count := map[string]int{}
	for _, r := range recipients {
		count[r.Name]++
	}
	labels := make([]string, 0, len(recipients))
	byLabel := map[string]app.Choice{}
	for _, r := range recipients {
		label := r.Name
		if count[r.Name] > 1 {
			label = fmt.Sprintf("%s (%s)", r.Name, r.File)
		}
		if own[r.File] {
			label += " (you)"
		}
		labels = append(labels, label)
		byLabel[label] = r
	}
	return labels, byLabel
}

// encryptFiles encrypts files[i:] one at a time for recipient, asking
// before replacing an existing .age file, then reports what was saved.
func (g *gui) encryptFiles(files []string, recipient app.Choice, i int, saved []string) {
	if i == len(files) {
		g.reportSaved("Encrypted", saved, recipient.Name)
		return
	}
	input := files[i]
	next := func() { g.encryptFiles(files, recipient, i+1, saved) }

	var run func(overwrite bool)
	run = func(overwrite bool) {
		runBusy(g, "Encrypting "+filepath.Base(input)+"…",
			func() (app.Result, error) { return g.svc.Encrypt(input, recipient.File, overwrite) },
			func(res app.Result, err error) {
				switch {
				case errors.Is(err, app.ErrOutputExists):
					g.confirmReplace(app.EncryptOutput(input), func() { run(true) }, next)
				case err != nil:
					g.problem("Couldn't encrypt "+filepath.Base(input), err, next)
				default:
					saved = append(saved, res.Output)
					g.warn(res.Warnings, func() { g.encryptFiles(files, recipient, i+1, saved) })
				}
			})
	}
	run(false)
}

// confirmReplace asks before replacing an existing file, then calls
// replace or skip.
func (g *gui) confirmReplace(path string, replace, skip func()) {
	d := dialog.NewConfirm("Replace existing file?",
		fmt.Sprintf("%s already exists in\n%s\n\nDo you want to replace it?", filepath.Base(path), filepath.Dir(path)),
		func(yes bool) {
			if yes {
				replace()
			} else {
				skip()
			}
		}, g.win)
	d.SetConfirmText("Replace")
	d.SetDismissText("Skip")
	d.Show()
}

// reportSaved tells the user which files were written, then returns home.
// verb is "Encrypted" or "Decrypted"; forName, if set, names who the files
// were encrypted for.
func (g *gui) reportSaved(verb string, saved []string, forName string) {
	if len(saved) == 0 {
		g.showHome()
		return
	}
	msg := ""
	for _, s := range saved {
		msg += fmt.Sprintf("Saved %s\n", filepath.Base(s))
	}
	msg += fmt.Sprintf("\nin %s", filepath.Dir(saved[0]))
	if forName != "" {
		msg += fmt.Sprintf("\n\nIt can only be decrypted with the private key for \"%s\".", forName)
	}
	g.tell(verb, msg, g.showHome)
}

// showNoKeys explains that a key is needed first, with a way to get one.
func (g *gui) showNoKeys(title, message string) {
	text := widget.NewLabel(message)
	text.Wrapping = fyne.TextWrapWord
	keys := widget.NewButtonWithIcon("Go to My keys", theme.AccountIcon(), g.showKeys)
	keys.Importance = widget.HighImportance
	g.showScreen(title, true, textScreen(text, container.NewHBox(keys)))
}
