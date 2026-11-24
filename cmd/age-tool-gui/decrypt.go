// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"age-tool/internal/app"
	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showDecrypt shows the decrypt screen: 1. choose a .age file, 2. choose
// your key, then Decrypt (which asks for the key's passphrase). files
// pre-fills step 1; with several files, each is decrypted in turn.
func (g *gui) showDecrypt(files []string) {
	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.ConfirmIcon(), nil)
	decryptBtn.Importance = widget.HighImportance

	// Step 2: the user's private keys. Unprotected keys are listed but
	// can't be chosen, with an explanation.
	identities, err := g.svc.Identities()
	if err != nil {
		g.problem("Couldn't read your keys", err, g.showHome)
		return
	}
	var usable []app.Choice
	unprotected := 0
	for _, id := range identities {
		if id.Protected {
			usable = append(usable, id)
		} else {
			unprotected++
		}
	}
	if len(usable) == 0 {
		msg := "You need your own key to decrypt files. Files can only be decrypted with the key they were encrypted for."
		if unprotected > 0 {
			msg = "Your private key isn't protected by a passphrase yet, so it can't be used. " +
				"Go to My keys and choose Protect."
		}
		g.showNoKeys("Decrypt a file", msg)
		return
	}
	labels := make([]string, len(usable))
	byLabel := map[string]app.Choice{}
	for i, id := range usable {
		labels[i] = id.Name
		if _, dup := byLabel[id.Name]; dup {
			labels[i] = fmt.Sprintf("%s (%s)", id.Name, id.File)
		}
		byLabel[labels[i]] = id
	}
	key := widget.NewRadioGroup(labels, nil)
	if len(labels) == 1 {
		key.SetSelected(labels[0])
	}

	// Decrypt is enabled once both steps are complete
	update := func() {
		if len(files) > 0 && key.Selected != "" {
			decryptBtn.Enable()
		} else {
			decryptBtn.Disable()
		}
	}
	key.OnChanged = func(string) { update() }
	fileStep := g.fileStep(files, true, func(chosen []string) {
		files = chosen
		update()
	})
	update()

	decryptBtn.OnTapped = func() {
		g.decryptFiles(files, byLabel[key.Selected], 0, nil)
	}

	top := []fyne.CanvasObject{
		stepHeading("1. Choose the encrypted file (.age)"),
		fileStep,
		widget.NewSeparator(),
		stepHeading("2. Which of your keys?"),
	}
	note := "The decrypted copy is saved next to the encrypted file, without the .age ending."
	if unprotected > 0 {
		note = fmt.Sprintf("%d of your private keys can't be used until it is protected with a passphrase (see My keys).\n", unprotected) + note
	}
	g.showScreen("Decrypt a file", true, workflowLayout(top, key, note, decryptBtn))
}

// decryptFiles decrypts files[i:] one at a time with key, then reports
// what was saved. The passphrase is asked for each file and never kept.
func (g *gui) decryptFiles(files []string, key app.Choice, i int, saved []string) {
	if i == len(files) {
		g.reportSaved("Decrypted", saved, "")
		return
	}
	input := files[i]
	title := "Couldn't decrypt " + filepath.Base(input)
	next := func() { g.decryptFiles(files, key, i+1, saved) }
	succeeded := func(output string) {
		g.decryptFiles(files, key, i+1, append(saved, output))
	}

	// Check the file, key and output before asking for the passphrase
	d, err := g.svc.StartDecrypt(input, key.File, false)
	if errors.Is(err, app.ErrOutputExists) {
		g.confirmReplace(app.DecryptOutput(input), func() {
			d, err := g.svc.StartDecrypt(input, key.File, true)
			if err != nil {
				g.problem(title, err, next)
				return
			}
			g.askPassphrase(d, key, input, "", succeeded, next)
		}, next)
		return
	}
	if err != nil {
		g.problem(title, err, next)
		return
	}
	g.askPassphrase(d, key, input, "", succeeded, next)
}

// askPassphrase asks for the key's passphrase and tries it, allowing the
// number of attempts the Decryption permits. note is shown above the
// field (e.g. "That passphrase is incorrect. 2 attempts left."). On
// success it calls succeeded with the output path; on giving up, failure
// or cancel it calls next.
func (g *gui) askPassphrase(d *app.Decryption, key app.Choice, input, note string, succeeded func(string), next func()) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("Passphrase")

	prompt := fmt.Sprintf("Enter the passphrase for your key \"%s\" to decrypt %s.", key.Name, filepath.Base(input))
	info := widget.NewLabel(prompt)
	info.Wrapping = fyne.TextWrapWord
	content := []fyne.CanvasObject{info}
	if note != "" {
		warning := widget.NewLabel(note)
		warning.Importance = widget.DangerImportance
		content = append(content, warning)
	}
	content = append(content, entry)

	// submit runs once the dialog has closed with Decrypt (button or Enter)
	submit := func() {
		// Take the passphrase out of the field straight away. Try zeroes
		// the byte copy; the field's own string can't be zeroed, but is
		// dropped as soon as the dialog closes.
		pass := []byte(entry.Text)
		entry.SetText("")
		if len(pass) == 0 {
			g.askPassphrase(d, key, input, note, succeeded, next)
			return
		}
		runBusy(g, "Unlocking your key…",
			func() (app.Result, error) { return d.Try(pass) },
			func(res app.Result, err error) {
				switch {
				case err == nil:
					g.warn(res.Warnings, func() { succeeded(res.Output) })
				case errors.Is(err, core.ErrWrongPassphrase):
					g.askPassphrase(d, key, input, app.AttemptsMessage(d.AttemptsLeft()), succeeded, next)
				default:
					g.problem("Couldn't decrypt "+filepath.Base(input), err, next)
				}
			})
	}
	// Note: Hide() on a Fyne dialog reports Cancel, so Enter must press the
	// Decrypt button (Confirm) rather than hide the dialog itself
	form := dialog.NewCustomConfirm("Passphrase", "Decrypt", "Cancel", container.NewVBox(content...),
		func(ok bool) {
			if ok {
				submit()
			} else {
				entry.SetText("")
				next()
			}
		}, g.win)
	entry.OnSubmitted = func(string) { form.Confirm() }
	form.Resize(fyne.NewSize(420, form.MinSize().Height))
	form.Show()
	g.win.Canvas().Focus(entry)
}
