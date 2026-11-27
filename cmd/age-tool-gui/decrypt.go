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
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showDecrypt shows the decrypt screen: 1. choose a .age file, 2. choose
// your key, then Decrypt (which asks for the key's passphrase). Files
// encrypted with a password need no key: step 2 says so, and Decrypt asks
// for the password instead. files pre-fills step 1; with several files,
// each is decrypted in turn, the right way for each.
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

	// What step 2 shows instead of the keys: a note when every chosen file
	// uses a password, or why there's no key to choose
	passwordNote := wrapped("The chosen file is protected with a password, so no key is needed. " +
		"You'll be asked for the password when you choose Decrypt.")
	noKeysMsg := "You need your own key to decrypt files encrypted for a key. Files can only be decrypted with the key they were encrypted for. " +
		"(Files protected with a password don't need a key.)"
	if unprotected > 0 {
		noKeysMsg = "Your private key isn't protected by a passphrase yet, so it can't be used. " +
			"Go to My keys and choose Protect. (Files protected with a password don't need a key.)"
	}
	goToKeys := widget.NewButtonWithIcon("Go to My keys", theme.AccountIcon(), g.showKeys)
	noKeys := container.NewVBox(wrapped(noKeysMsg), container.NewHBox(goToKeys))
	step2 := container.NewVBox()

	// allPassword reports whether every chosen file is a password file
	allPassword := func() bool {
		if len(files) == 0 {
			return false
		}
		for _, f := range files {
			if m, err := g.svc.LockMethod(f); err != nil || m != core.LockedWithPassword {
				return false
			}
		}
		return true
	}

	// Decrypt is enabled once both steps are complete
	update := func() {
		needKey := !allPassword()
		switch {
		case !needKey:
			step2.Objects = []fyne.CanvasObject{passwordNote}
		case len(usable) == 0:
			step2.Objects = []fyne.CanvasObject{noKeys}
		default:
			step2.Objects = []fyne.CanvasObject{key}
		}
		step2.Refresh()
		setEnabled(decryptBtn, len(files) > 0 && (!needKey || key.Selected != ""))
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
	if unprotected > 0 && len(usable) > 0 {
		note = fmt.Sprintf("%d of your private keys can't be used until it is protected with a passphrase (see My keys).\n", unprotected) + note
	}
	g.showScreen("Decrypt a file", true, workflowLayout(top, step2, note, decryptBtn))
}

// decryptFiles decrypts files[i:] one at a time, then reports what was
// saved. Each file is decrypted the way it was locked: with a password, or
// with key (whose passphrase is asked for each file and never kept).
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

	// A password file needs its password, not a key
	method, err := g.svc.LockMethod(input)
	if err != nil {
		g.problem(title, err, next)
		return
	}
	if method == core.LockedWithPassword {
		g.decryptWithPassword(input, succeeded, next)
		return
	}
	if key.File == "" {
		g.tell(title, filepath.Base(input)+" was encrypted for a key. Choose one of your keys to decrypt it.", next)
		return
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
// number of attempts the Decryption permits. note, if set, is shown above
// the field (e.g. "That passphrase is incorrect. 2 attempts left."). On
// success it calls succeeded with the output path; on giving up, failure
// or cancel it calls next.
func (g *gui) askPassphrase(d *app.Decryption, key app.Choice, input, note string, succeeded func(string), next func()) {
	var res app.Result
	g.askSecret(secretPrompt{
		title:        "Passphrase",
		prompt:       fmt.Sprintf("Enter the passphrase for your key \"%s\" to decrypt %s.", key.Name, filepath.Base(input)),
		placeholder:  "Passphrase",
		confirm:      "Decrypt",
		busy:         "Unlocking your key…",
		wrong:        core.ErrWrongPassphrase,
		attemptsLeft: d.AttemptsLeft,
		wrongMessage: app.AttemptsMessage,
		try: func(secret []byte) error {
			r, err := d.Try(secret)
			res = r
			return err
		},
		succeeded: func() { g.warn(res.Warnings, func() { succeeded(res.Output) }) },
		failTitle: "Couldn't decrypt " + filepath.Base(input),
		next:      next,
	}, note)
}
