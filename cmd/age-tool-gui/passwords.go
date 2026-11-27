// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

// Encrypting with a password, the "Keep a record?" choice, decrypting
// password files, and the Saved passwords screen. The rules and the
// cryptography are in internal/app and internal/core.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"age-tool/internal/app"
	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// passwordChoice is the "Who is it for?" option for encrypting with a
// password rather than for a key.
const passwordChoice = "A password instead of a key"

// ─── Asking for a passphrase or password ────────────────────────────────────

// secretPrompt describes a dialog that asks for a passphrase or password
// and tries it, allowing a limited number of attempts.
type secretPrompt struct {
	title        string                    // Dialog title, e.g. "Password"
	prompt       string                    // What to type, and why
	hint         string                    // Optional extra line under the prompt
	placeholder  string                    // Shown in the empty field
	confirm      string                    // The confirm button, e.g. "Decrypt"
	busy         string                    // Progress text while trying
	wrong        error                     // The error meaning "wrong, try again"
	attemptsLeft func() int                // Tries remaining after a wrong one
	wrongMessage func(left int) string     // E.g. "That password is incorrect. 2 attempts left."
	try          func(secret []byte) error // Runs off the UI thread; zeroes secret
	succeeded    func()                    // Called on the UI thread after a successful try
	failTitle    string                    // Title for any other failure
	next         func()                    // Called on cancel, failure or giving up
}

// askSecret shows the dialog described by p. note, if set, is shown in
// red above the field (e.g. after a wrong attempt).
func (g *gui) askSecret(p secretPrompt, note string) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder(p.placeholder)

	content := []fyne.CanvasObject{wrapped(p.prompt)}
	if p.hint != "" {
		hint := wrapped(p.hint)
		hint.TextStyle = fyne.TextStyle{Italic: true}
		content = append(content, hint)
	}
	if note != "" {
		warning := wrapped(note)
		warning.Importance = widget.DangerImportance
		content = append(content, warning)
	}
	content = append(content, entry)

	// submit runs once the dialog has closed with the confirm button or Enter
	submit := func() {
		// Take the secret out of the field straight away. try zeroes the
		// byte copy; the field's own string is dropped with the dialog.
		secret := []byte(entry.Text)
		entry.SetText("")
		if len(secret) == 0 {
			g.askSecret(p, note)
			return
		}
		runBusy(g, p.busy,
			func() (struct{}, error) { return struct{}{}, p.try(secret) },
			func(_ struct{}, err error) {
				switch {
				case err == nil:
					p.succeeded()
				case errors.Is(err, p.wrong):
					g.askSecret(p, p.wrongMessage(p.attemptsLeft()))
				default:
					g.problem(p.failTitle, err, p.next)
				}
			})
	}
	// Note: Hide() on a Fyne dialog reports Cancel, so Enter must press the
	// confirm button rather than hide the dialog itself
	form := dialog.NewCustomConfirm(p.title, p.confirm, "Cancel", container.NewVBox(content...),
		func(ok bool) {
			if ok {
				submit()
			} else {
				entry.SetText("")
				p.next()
			}
		}, g.win)
	entry.OnSubmitted = func(string) { form.Confirm() }
	form.Resize(fyne.NewSize(440, form.MinSize().Height))
	form.Show()
	g.win.Canvas().Focus(entry)
}

// ─── Encrypt with a password ────────────────────────────────────────────────

// passwordPanel is the part of the encrypt screen shown when "A password
// instead of a key" is chosen: the rule, the password typed twice, a
// suggestion button, and whether the password can be used.
type passwordPanel struct {
	box      *fyne.Container
	password *widget.Entry
	confirm  *widget.Entry
	status   *widget.Label
	valid    bool // The password meets the rules and both fields match
}

// newPasswordPanel builds the panel. changed is called whenever the
// password becomes valid or invalid, to update the Encrypt button.
func (g *gui) newPasswordPanel(changed func()) *passwordPanel {
	p := &passwordPanel{
		password: widget.NewPasswordEntry(),
		confirm:  widget.NewPasswordEntry(),
		status:   wrapped(""),
	}
	rule := g.svc.PasswordRules().Describe()

	// The suggestion is shown in full so it can be written down or copied
	suggestion := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		g.fy.Clipboard().SetContent(suggestion.Text)
	})
	suggestion.Hide()
	copyBtn.Hide()
	suggestBtn := widget.NewButtonWithIcon("Suggest a password", theme.ViewRefreshIcon(), func() {
		s, err := g.svc.SuggestPassword()
		if err != nil {
			g.problem("Couldn't suggest a password", err, nil)
			return
		}
		suggestion.SetText(s)
		suggestion.Show()
		copyBtn.Show()
		p.password.SetText(s)
		p.confirm.SetText(s)
	})

	// Check the password as it's typed
	check := func(string) {
		pw, again := p.password.Text, p.confirm.Text
		wasValid := p.valid
		p.valid = false
		switch err := g.svc.CheckNewPassword(pw, again); {
		case pw == "":
			p.setStatus(rule, widget.MediumImportance)
		case errors.Is(err, app.ErrPasswordMismatch):
			if again == "" {
				// Not typed the confirmation yet: only check the rule
				if ruleErr := g.svc.PasswordRules().CheckPassword(pw); ruleErr != nil {
					p.setStatus(app.PasswordProblem(ruleErr), widget.DangerImportance)
				} else {
					p.setStatus("Now type it again below.", widget.MediumImportance)
				}
			} else {
				p.setStatus(app.Message(err), widget.DangerImportance)
			}
		case err != nil:
			p.setStatus(app.PasswordProblem(err), widget.DangerImportance)
		default:
			p.valid = true
			p.setStatus("This password can be used.", widget.SuccessImportance)
		}
		if p.valid != wasValid {
			changed()
		}
	}
	p.password.OnChanged = check
	p.confirm.OnChanged = check

	form := widget.NewForm(
		widget.NewFormItem("Password", p.password),
		widget.NewFormItem("Type it again", p.confirm),
	)
	p.setStatus(rule, widget.MediumImportance)
	p.box = container.NewVBox(form, p.status, container.NewHBox(suggestBtn, suggestion, copyBtn))
	p.box.Hide()
	return p
}

// setStatus shows text under the password fields, coloured by importance.
func (p *passwordPanel) setStatus(text string, importance widget.Importance) {
	p.status.Importance = importance
	p.status.SetText(text)
}

// encryptFilesWithPassword encrypts files[i:] one at a time with
// password, asking before replacing an existing .age file, then asks
// whether to keep a record of the password.
func (g *gui) encryptFilesWithPassword(files []string, password string, i int, saved []string) {
	if i == len(files) {
		g.afterPasswordEncrypt(saved, password)
		return
	}
	input := files[i]
	next := func() { g.encryptFilesWithPassword(files, password, i+1, saved) }

	var run func(overwrite bool)
	run = func(overwrite bool) {
		runBusy(g, "Encrypting "+filepath.Base(input)+"…",
			func() (app.Result, error) { return g.svc.EncryptWithPassword(input, password, overwrite) },
			func(res app.Result, err error) {
				switch {
				case errors.Is(err, app.ErrOutputExists):
					g.confirmReplace(app.EncryptOutput(input), func() { run(true) }, next)
				case err != nil:
					g.problem("Couldn't encrypt "+filepath.Base(input), err, next)
				default:
					saved = append(saved, res.Output)
					g.warn(res.Warnings, func() { g.encryptFilesWithPassword(files, password, i+1, saved) })
				}
			})
	}
	run(false)
}

// Choices in the "Keep a record?" dialog.
const (
	recordSave = "Save it, protected by my key (recommended)"
	recordSkip = "Don't save it"
)

// afterPasswordEncrypt asks whether to keep a record of the password used
// for the saved files, then reports what was saved. Without a key of the
// user's own, the password is shown once instead.
func (g *gui) afterPasswordEncrypt(saved []string, password string) {
	if len(saved) == 0 {
		g.showHome()
		return
	}
	if !g.svc.CanSavePasswordRecords() {
		g.showPasswordOnce(saved, password,
			"A record of this password can't be saved, because you don't have a key of your own to protect it. "+
				"(You can create one in My keys.)")
		return
	}

	saveNote := wrapped("You can look it up later in My keys > Saved passwords, using your key's passphrase. " +
		"If you forget your key's passphrase, you lose this record too.")
	skipNote := wrapped("The password is shown once, so you can write it down or store it somewhere safe.")
	skipNote.Hide()
	choice := widget.NewRadioGroup([]string{recordSave, recordSkip}, func(selected string) {
		saveNote.Hidden = selected == recordSkip
		skipNote.Hidden = selected != recordSkip
		saveNote.Refresh()
		skipNote.Refresh()
	})
	choice.Required = true
	choice.SetSelected(recordSave)
	content := container.NewVBox(
		wrapped("Encrypted with a password. Keep a record of the password?"),
		choice, saveNote, skipNote,
	)
	d := dialog.NewCustom("Keep a record of this password?", "Continue", content, g.win)
	d.SetOnClosed(func() {
		if choice.Selected == recordSkip {
			g.showPasswordOnce(saved, password, "")
			return
		}
		names, err := g.svc.SavePasswordRecord(saved, password)
		if err != nil {
			g.showPasswordOnce(saved, password, "The record couldn't be saved: "+app.Message(err))
			return
		}
		g.reportPasswordEncrypted(saved, fmt.Sprintf(
			"A record of the password is saved, protected by your key \"%s\". "+
				"Find it in My keys > Saved passwords.", strings.Join(names, "\", \"")))
	})
	d.Resize(fyne.NewSize(480, content.MinSize().Height))
	d.Show()
}

// reportPasswordEncrypted tells the user which files were encrypted with a
// password, with the reminder about sharing it, then returns home.
func (g *gui) reportPasswordEncrypted(saved []string, extra string) {
	msg := ""
	for _, s := range saved {
		msg += fmt.Sprintf("Saved %s\n", filepath.Base(s))
	}
	msg += fmt.Sprintf("\nin %s\n\nIt can only be opened with the password. "+
		"If you send it to someone, tell them the password a different way, for example by phone.", filepath.Dir(saved[0]))
	if extra != "" {
		msg += "\n\n" + extra
	}
	g.tell("Encrypted", msg, g.showHome)
}

// showPasswordOnce shows the password used for the saved files, once, with
// a Copy button, then reports what was saved. Nothing is stored. reason,
// if set, says why no record was saved.
func (g *gui) showPasswordOnce(saved []string, password, reason string) {
	pwLabel := widget.NewLabelWithStyle(password, fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	status := widget.NewLabel("")
	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		g.fy.Clipboard().SetContent(password)
		status.SetText("Copied.")
	})
	var parts []fyne.CanvasObject
	if reason != "" {
		parts = append(parts, wrapped(reason))
	}
	parts = append(parts,
		wrapped("The password is:"),
		container.NewHBox(pwLabel, copyBtn, status),
		wrapped("Write it down or store it somewhere safe. Without it, the file can't be opened, "+
			"and it won't be shown again."),
	)
	content := container.NewVBox(parts...)
	d := dialog.NewCustom("Your password", "I've noted it", content, g.win)
	d.SetOnClosed(func() { g.reportPasswordEncrypted(saved, "") })
	d.Resize(fyne.NewSize(480, content.MinSize().Height))
	d.Show()
}

// ─── Decrypt a password file ────────────────────────────────────────────────

// decryptWithPassword decrypts one password-locked file, asking before
// replacing an existing output, then for the password (3 attempts).
func (g *gui) decryptWithPassword(input string, succeeded func(string), next func()) {
	title := "Couldn't decrypt " + filepath.Base(input)
	start := func(overwrite bool) {
		d, err := g.svc.StartPasswordDecrypt(input, overwrite)
		if err != nil {
			g.problem(title, err, next)
			return
		}
		hint := ""
		if g.svc.HasPasswordRecord(input) {
			hint = "You have a saved record of this file's password: see My keys > Saved passwords."
		}
		var res app.Result
		g.askSecret(secretPrompt{
			title:        "Password",
			prompt:       fmt.Sprintf("%s is protected with a password. Enter it to decrypt the file.", filepath.Base(input)),
			hint:         hint,
			placeholder:  "Password",
			confirm:      "Decrypt",
			busy:         "Decrypting…",
			wrong:        core.ErrWrongPassword,
			attemptsLeft: d.AttemptsLeft,
			wrongMessage: app.PasswordAttemptsMessage,
			try: func(secret []byte) error {
				r, err := d.Try(secret)
				res = r
				return err
			},
			succeeded: func() { g.warn(res.Warnings, func() { succeeded(res.Output) }) },
			failTitle: title,
			next:      next,
		}, "")
	}

	// Ask about replacing first, so the user doesn't type the password for nothing
	if core.FileExists(app.DecryptOutput(input)) {
		g.confirmReplace(app.DecryptOutput(input), func() { start(true) }, next)
		return
	}
	start(false)
}

// ─── Saved passwords ────────────────────────────────────────────────────────

// showSavedPasswords shows the saved password records, with buttons to
// show or delete the selected one.
func (g *gui) showSavedPasswords() {
	records, skipped, err := g.svc.PasswordRecords()
	if err != nil {
		g.problem("Couldn't read your saved passwords", err, g.showKeys)
		return
	}
	back := widget.NewButtonWithIcon("My keys", theme.NavigateBackIcon(), g.showKeys)
	if len(records) == 0 {
		g.showScreen("Saved passwords", true, textScreen(
			wrapped("No saved passwords yet.\n\nWhen you encrypt a file with a password, age-tool offers to keep a record of it here, "+
				"protected by your key, so you can look it up if you forget it."),
			container.NewHBox(back)))
		return
	}

	showBtn := widget.NewButtonWithIcon("Show password", theme.VisibilityIcon(), nil)
	showBtn.Importance = widget.HighImportance
	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), nil)
	deleteBtn.Importance = widget.DangerImportance
	showBtn.Disable()
	deleteBtn.Disable()

	list := widget.NewList(
		func() int { return len(records) },
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			name.Truncation = fyne.TextTruncateEllipsis
			when := widget.NewLabel("")
			when.Truncation = fyne.TextTruncateEllipsis
			return container.NewBorder(nil, nil, widget.NewIcon(theme.VisibilityOffIcon()), nil, container.NewVBox(name, when))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			r := records[i]
			box := o.(*fyne.Container).Objects[0].(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(recordTitle(r))
			box.Objects[1].(*widget.Label).SetText("Saved " + r.Created.Local().Format("2 Jan 2006, 15:04") +
				", in " + filepath.Dir(r.Files[0].Path))
		})
	list.OnSelected = func(i widget.ListItemID) {
		rec := records[i]
		showBtn.OnTapped = func() { g.openPasswordRecord(rec) }
		deleteBtn.OnTapped = func() { g.confirmDeleteRecord(rec) }
		showBtn.Enable()
		deleteBtn.Enable()
	}

	note := "Each saved password is protected by your key. Showing it asks for your key's passphrase."
	if skipped > 0 {
		note = fmt.Sprintf("%d saved password file(s) couldn't be read. ", skipped) + note
	}
	g.showScreen("Saved passwords", true, container.NewBorder(
		nil,
		container.NewVBox(widget.NewSeparator(), wrapped(note), container.NewHBox(back, showBtn, deleteBtn)),
		nil, nil, list))
}

// recordTitle names a record's files: the first file, plus how many more.
func recordTitle(r core.PasswordRecord) string {
	if len(r.Files) == 0 {
		return "(no files)"
	}
	title := filepath.Base(r.Files[0].Path)
	if n := len(r.Files) - 1; n > 0 {
		title += fmt.Sprintf(" and %d more", n)
	}
	return title
}

// openPasswordRecord asks which key to use (if more than one can open the
// record), then for its passphrase, then shows the password.
func (g *gui) openPasswordRecord(rec core.PasswordRecord) {
	keys, err := g.svc.RecordKeys(rec)
	if err != nil {
		g.problem("Couldn't read your keys", err, g.showSavedPasswords)
		return
	}
	var usable []app.Choice
	for _, k := range keys {
		if k.Protected {
			usable = append(usable, k)
		}
	}
	switch len(usable) {
	case 0:
		g.tell("Can't open this saved password",
			"It was saved for a key that's no longer in My keys, or isn't protected by a passphrase.", g.showSavedPasswords)
	case 1:
		g.unlockRecord(rec, usable[0])
	default:
		names := make([]string, len(usable))
		for i, k := range usable {
			names[i] = k.Name
		}
		pick := widget.NewRadioGroup(names, nil)
		pick.SetSelected(names[0])
		d := dialog.NewCustomConfirm("Which key?", "Next", "Cancel",
			container.NewVBox(wrapped("This password is protected by several of your keys. Which one do you want to unlock it with?"), pick),
			func(ok bool) {
				if !ok {
					return
				}
				for _, k := range usable {
					if k.Name == pick.Selected {
						g.unlockRecord(rec, k)
					}
				}
			}, g.win)
		d.Show()
	}
}

// unlockRecord asks for key's passphrase (3 attempts) and shows the
// record's password.
func (g *gui) unlockRecord(rec core.PasswordRecord, key app.Choice) {
	o, err := g.svc.StartOpenRecord(rec, key.File)
	if err != nil {
		g.problem("Couldn't open this saved password", err, g.showSavedPasswords)
		return
	}
	var password string
	var opened core.PasswordRecord
	g.askSecret(secretPrompt{
		title:        "Passphrase",
		prompt:       fmt.Sprintf("Enter the passphrase for your key \"%s\" to show this saved password.", key.Name),
		placeholder:  "Passphrase",
		confirm:      "Show",
		busy:         "Unlocking your key…",
		wrong:        core.ErrWrongPassphrase,
		attemptsLeft: o.AttemptsLeft,
		wrongMessage: app.AttemptsMessage,
		try: func(secret []byte) error {
			pw, r, err := o.Try(secret)
			password, opened = pw, r
			return err
		},
		succeeded: func() { g.showRecordPassword(opened, password) },
		failTitle: "Couldn't open this saved password",
		next:      g.showSavedPasswords,
	}, "")
}

// showRecordPassword shows a saved password and the files it opens.
func (g *gui) showRecordPassword(rec core.PasswordRecord, password string) {
	pwLabel := widget.NewLabelWithStyle(password, fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	status := widget.NewLabel("")
	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		g.fy.Clipboard().SetContent(password)
		status.SetText("Copied.")
	})
	files := make([]string, len(rec.Files))
	for i, f := range rec.Files {
		files[i] = f.Path
	}
	content := container.NewVBox(
		wrapped("The password is:"),
		container.NewHBox(pwLabel, copyBtn, status),
		wrapped("It opens:\n"+strings.Join(files, "\n")),
	)
	d := dialog.NewCustom("Saved password", "Close", content, g.win)
	d.SetOnClosed(g.showSavedPasswords)
	d.Resize(fyne.NewSize(480, content.MinSize().Height))
	d.Show()
}

// confirmDeleteRecord asks before deleting a saved password.
func (g *gui) confirmDeleteRecord(rec core.PasswordRecord) {
	d := dialog.NewConfirm("Delete saved password?",
		fmt.Sprintf("Delete the saved password for %s? This can't be undone.\n\n"+
			"The encrypted files aren't affected, but if you don't know the password another way, "+
			"you won't be able to open them.", recordTitle(rec)),
		func(yes bool) {
			if !yes {
				return
			}
			if err := g.svc.DeletePasswordRecord(rec.ID); err != nil {
				g.problem("Couldn't delete the saved password", err, g.showSavedPasswords)
				return
			}
			g.showSavedPasswords()
		}, g.win)
	d.SetConfirmText("Delete")
	d.Show()
}
