// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"fmt"
	"path/filepath"

	"age-tool/internal/app"
	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showKeys shows "My keys": the user's own keys and their contacts, with
// buttons to create a key, add a contact, and share, rename, protect or
// delete the selected key.
func (g *gui) showKeys() {
	keys, err := g.svc.Keys()
	if err != nil {
		g.problem("Couldn't read your keys", err, g.showHome)
		return
	}

	createBtn := widget.NewButtonWithIcon("Create a key", theme.ContentAddIcon(), func() { g.showCreateKey("", "", "") })
	createBtn.Importance = widget.HighImportance
	contactBtn := widget.NewButtonWithIcon("Add a contact", theme.AccountIcon(), func() { g.showAddContact("", "", "", "") })
	top := container.NewHBox(createBtn, contactBtn)

	if len(keys) == 0 {
		intro := widget.NewLabel("You don't have any keys yet.\n\n" +
			"Create your own key to receive encrypted files: you share its public half with others, " +
			"and keep the private half, protected by a passphrase.\n\n" +
			"Add a contact's public key to encrypt files for them.")
		intro.Wrapping = fyne.TextWrapWord
		g.showScreen("My keys", true, textScreen(top, widget.NewSeparator(), intro))
		return
	}

	// The action buttons act on the selected key
	shareBtn := widget.NewButtonWithIcon("Share public key", theme.MailSendIcon(), nil)
	renameBtn := widget.NewButtonWithIcon("Rename", theme.DocumentCreateIcon(), nil)
	protectBtn := widget.NewButtonWithIcon("Protect", theme.WarningIcon(), nil)
	protectBtn.Importance = widget.WarningImportance
	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), nil)
	deleteBtn.Importance = widget.DangerImportance
	actions := []*widget.Button{shareBtn, renameBtn, protectBtn, deleteBtn}
	for _, b := range actions {
		b.Disable()
	}

	list := widget.NewList(
		func() int { return len(keys) },
		// Each row: an icon, with the key's name above a description
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			name.Truncation = fyne.TextTruncateEllipsis
			detail := widget.NewLabel("")
			detail.Truncation = fyne.TextTruncateEllipsis
			return container.NewBorder(nil, nil, widget.NewIcon(theme.AccountIcon()), nil,
				container.New(layout.NewCustomPaddedVBoxLayout(0), name, detail))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			k := keys[id]
			row := obj.(*fyne.Container)
			icon, detail := keyIconAndDetail(k)
			// Border stores its centre object first, then the left one
			text := row.Objects[0].(*fyne.Container)
			row.Objects[1].(*widget.Icon).SetResource(icon)
			text.Objects[0].(*widget.Label).SetText(k.Name)
			label := text.Objects[1].(*widget.Label)
			label.SetText(detail)
			if k.PrivFile != "" && !k.Protected {
				label.Importance = widget.DangerImportance
			} else {
				label.Importance = widget.MediumImportance
			}
			label.Refresh()
		})

	list.OnSelected = func(id widget.ListItemID) {
		k := keys[id]
		setEnabled(shareBtn, k.PubFile != "")
		renameBtn.Enable()
		setEnabled(protectBtn, k.PrivFile != "" && !k.Protected)
		deleteBtn.Enable()
		shareBtn.OnTapped = func() { g.showShareKey(k) }
		renameBtn.OnTapped = func() { g.showRenameKey(k) }
		protectBtn.OnTapped = func() { g.showProtectKey(k, "") }
		deleteBtn.OnTapped = func() { g.confirmDeleteKey(k) }
	}
	list.OnUnselected = func(widget.ListItemID) {
		for _, b := range actions {
			b.Disable()
		}
	}

	g.showScreen("My keys", true, container.NewBorder(
		container.NewVBox(top, widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), container.NewHBox(shareBtn, renameBtn, protectBtn, deleteBtn)),
		nil, nil,
		list))
}

// keyIconAndDetail describes a key for the list: your own key (and
// whether it's protected), a contact, or a lone private key.
func keyIconAndDetail(k app.Key) (fyne.Resource, string) {
	switch {
	case k.Contact:
		return theme.AccountIcon(), "Contact: you can encrypt files for them"
	case !k.Protected:
		return theme.WarningIcon(), "Your key: NOT protected, choose Protect"
	case k.PubFile == "":
		return theme.HomeIcon(), "Your key (private half only)"
	default:
		return theme.HomeIcon(), "Your key: protected by a passphrase"
	}
}

// setEnabled enables or disables a button.
func setEnabled(b *widget.Button, enabled bool) {
	if enabled {
		b.Enable()
	} else {
		b.Disable()
	}
}

// wrapped returns a word-wrapping label.
func wrapped(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Wrapping = fyne.TextWrapWord
	return l
}

// errorLabel returns a red label for a problem shown inside a dialog, or
// nil if there is none.
func errorLabel(note string) fyne.CanvasObject {
	if note == "" {
		return nil
	}
	l := wrapped(note)
	l.Importance = widget.DangerImportance
	return l
}

// vbox stacks objects vertically, skipping any that are nil.
func vbox(objects ...fyne.CanvasObject) *fyne.Container {
	c := container.NewVBox()
	for _, o := range objects {
		if o != nil {
			c.Add(o)
		}
	}
	return c
}

// passphraseFields returns a new-passphrase field, its confirmation, and a
// strength label that updates as the user types.
func passphraseFields() (pass, confirm *widget.Entry, strength *widget.Label) {
	pass = widget.NewPasswordEntry()
	confirm = widget.NewPasswordEntry()
	strength = widget.NewLabel(app.StrengthLabel(core.StrengthTooShort))
	pass.OnChanged = func(text string) {
		rating := core.RatePassphrase(text)
		strength.SetText(app.StrengthLabel(rating))
		switch rating {
		case core.StrengthTooShort, core.StrengthWeak:
			strength.Importance = widget.DangerImportance
		case core.StrengthFair:
			strength.Importance = widget.WarningImportance
		default:
			strength.Importance = widget.SuccessImportance
		}
		strength.Refresh()
	}
	return pass, confirm, strength
}

// takePassphrases copies both passphrase fields into byte slices (which
// the workflow zeroes) and empties the fields.
func takePassphrases(pass, confirm *widget.Entry) ([]byte, []byte) {
	p, c := []byte(pass.Text), []byte(confirm.Text)
	pass.SetText("")
	confirm.SetText("")
	return p, c
}

// ─── Create a key ───────────────────────────────────────────────────────────

// showCreateKey asks for a new key's name, an optional nickname and a
// passphrase, then creates it. After a problem it reopens with the name
// and nickname kept (never the passphrase) and note explaining what to fix.
func (g *gui) showCreateKey(name, nickname, note string) {
	nameEntry := widget.NewEntry()
	nameEntry.SetText(name)
	nameEntry.SetPlaceHolder("e.g. laptop")
	nickEntry := widget.NewEntry()
	nickEntry.SetText(nickname)
	nickEntry.SetPlaceHolder("Optional, e.g. My work key")
	pass, confirm, strength := passphraseFields()

	form := widget.NewForm(
		widget.NewFormItem("Name", nameEntry),
		widget.NewFormItem("Nickname", nickEntry),
		widget.NewFormItem("Passphrase", pass),
		widget.NewFormItem("", strength),
		widget.NewFormItem("Type it again", confirm),
	)
	help := wrapped(fmt.Sprintf("Choose a passphrase of at least %d characters that you will remember. "+
		"A few unrelated words work well. If you forget it, files encrypted for this key can't be recovered.", core.MinPassphraseLen))

	d := dialog.NewCustomConfirm("Create a key", "Create", "Cancel", vbox(errorLabel(note), help, form), func(ok bool) {
		p, c := takePassphrases(pass, confirm)
		if !ok {
			core.ClearBytes(p)
			core.ClearBytes(c)
			return
		}
		name, nickname := nameEntry.Text, nickEntry.Text
		runBusy(g, "Creating your key…",
			func() (app.KeyCreated, error) { return g.svc.GenerateKey(name, nickname, p, c) },
			func(created app.KeyCreated, err error) {
				if err != nil {
					g.showCreateKey(name, nickname, app.Message(err))
					return
				}
				g.warn(created.Warnings, func() {
					g.tell("Your key is ready",
						"Share your public key with people who will send you encrypted files: "+
							"select the key in My keys and choose Share public key.\n\n"+
							"Never share your passphrase.", g.showKeys)
				})
			})
	}, g.win)
	confirm.OnSubmitted = func(string) { d.Confirm() }
	d.Resize(fyne.NewSize(480, d.MinSize().Height))
	d.Show()
	g.win.Canvas().Focus(nameEntry)
}

// ─── Contacts ───────────────────────────────────────────────────────────────

// showAddContact asks for a contact's name, optional nickname and public
// key (pasted, or loaded from their .pub file), then saves it. After a
// problem it reopens with the entries kept and note explaining what to fix.
func (g *gui) showAddContact(name, nickname, keyText, note string) {
	nameEntry := widget.NewEntry()
	nameEntry.SetText(name)
	nameEntry.SetPlaceHolder("e.g. alice")
	nickEntry := widget.NewEntry()
	nickEntry.SetText(nickname)
	nickEntry.SetPlaceHolder("Optional, e.g. Alice Smith")
	keyEntry := widget.NewMultiLineEntry()
	keyEntry.Wrapping = fyne.TextWrapBreak
	keyEntry.SetText(keyText)
	keyEntry.SetPlaceHolder("age1…")
	keyEntry.SetMinRowsVisible(3)

	// Loading a .pub file fills in the key text, so the user sees it
	var d *dialog.ConfirmDialog
	load := widget.NewButtonWithIcon("Load from a .pub file…", theme.FolderOpenIcon(), func() {
		g.pickFile(false, func(path string) {
			text, err := core.ReadPublicKeyString(path)
			if err != nil {
				g.tell("Couldn't load the key", app.Message(err), nil)
				return
			}
			keyEntry.SetText(text)
			if nameEntry.Text == "" {
				nameEntry.SetText(trimExt(filepath.Base(path)))
			}
		})
	})

	form := widget.NewForm(
		widget.NewFormItem("Name", nameEntry),
		widget.NewFormItem("Nickname", nickEntry),
		widget.NewFormItem("Public key", keyEntry),
		widget.NewFormItem("", load),
	)
	help := wrapped("Ask the person for their public key. It is a single line starting with \"age1\" " +
		"and is safe to send by email or message.")

	d = dialog.NewCustomConfirm("Add a contact", "Add", "Cancel", vbox(errorLabel(note), help, form), func(ok bool) {
		if !ok {
			return
		}
		name, nickname, text := nameEntry.Text, nickEntry.Text, keyEntry.Text
		if err := g.svc.ImportContact(name, nickname, text); err != nil {
			// Never put a pasted private key back on screen
			if core.ContainsSecretKey(text) {
				text = ""
			}
			g.showAddContact(name, nickname, text, app.Message(err))
			return
		}
		g.tell("Contact added", fmt.Sprintf("You can now encrypt files for %s.", displayName(name, nickname)), g.showKeys)
	}, g.win)
	d.Resize(fyne.NewSize(520, d.MinSize().Height))
	d.Show()
	g.win.Canvas().Focus(nameEntry)
}

// displayName is a nickname if given, otherwise the name.
func displayName(name, nickname string) string {
	if nickname != "" {
		return nickname
	}
	return name
}

// trimExt removes a file name's extension.
func trimExt(name string) string {
	return name[:len(name)-len(filepath.Ext(name))]
}

// ─── Share, rename, protect, delete ─────────────────────────────────────────

// showShareKey shows a public key with buttons to copy it or save a copy
// as a file, to send to people who will encrypt files for the user.
func (g *gui) showShareKey(k app.Key) {
	text, err := g.svc.PublicKeyText(k.PubFile)
	if err != nil {
		g.problem("Couldn't read the public key", err, nil)
		return
	}
	keyText := widget.NewLabel(text)
	keyText.Wrapping = fyne.TextWrapBreak
	keyText.Selectable = true
	keyText.TextStyle = fyne.TextStyle{Monospace: true}

	status := widget.NewLabel("")
	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		g.fy.Clipboard().SetContent(text)
		status.SetText("Copied. Paste it into an email or message.")
	})
	copyBtn.Importance = widget.HighImportance
	saveBtn := widget.NewButtonWithIcon("Save a copy…", theme.DocumentSaveIcon(), func() {
		g.pickFolder(func(dir string) {
			dest := filepath.Join(dir, k.PubFile)
			if err := g.svc.ExportPublicKey(k.PubFile, dest); err != nil {
				status.SetText(fmt.Sprintf("Couldn't save: %s already exists there, or the folder can't be written to.", k.PubFile))
				return
			}
			status.SetText("Saved " + dest)
		})
	})

	intro := fmt.Sprintf("This is the public key for \"%s\". ", k.Name)
	if k.Contact {
		intro += "It belongs to your contact."
	} else {
		intro += "Send it to anyone who will encrypt files for you. It is safe to share. Never share your passphrase or private key."
	}
	content := vbox(wrapped(intro), keyText, container.NewHBox(copyBtn, saveBtn), status)
	d := dialog.NewCustom("Share public key", "Close", content, g.win)
	d.Resize(fyne.NewSize(520, d.MinSize().Height))
	d.Show()
}

// showRenameKey sets the nickname shown for a key (both halves).
func (g *gui) showRenameKey(k app.Key) {
	entry := widget.NewEntry()
	entry.SetText(k.Name)
	content := vbox(wrapped("Choose the name shown for this key. Leave it empty to show "+k.Base+"."), entry)
	d := dialog.NewCustomConfirm("Rename", "Save", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		nick := entry.Text
		if nick == k.Base {
			nick = "" // the file name is shown anyway
		}
		for _, f := range []string{k.PubFile, k.PrivFile} {
			if f == "" {
				continue
			}
			if err := g.svc.SetNickname(f, nick); err != nil {
				g.problem("Couldn't rename the key", err, g.showKeys)
				return
			}
		}
		g.showKeys()
	}, g.win)
	entry.OnSubmitted = func(string) { d.Confirm() }
	d.Resize(fyne.NewSize(420, d.MinSize().Height))
	d.Show()
	g.win.Canvas().Focus(entry)
}

// showProtectKey protects an unprotected private key with a passphrase.
func (g *gui) showProtectKey(k app.Key, note string) {
	pass, confirm, strength := passphraseFields()
	form := widget.NewForm(
		widget.NewFormItem("Passphrase", pass),
		widget.NewFormItem("", strength),
		widget.NewFormItem("Type it again", confirm),
	)
	help := wrapped(fmt.Sprintf("\"%s\" is stored without a passphrase, so anyone who copies it can decrypt your files. "+
		"Protect it with a passphrase of at least %d characters.", k.Name, core.MinPassphraseLen))
	d := dialog.NewCustomConfirm("Protect your key", "Protect", "Cancel", vbox(errorLabel(note), help, form), func(ok bool) {
		p, c := takePassphrases(pass, confirm)
		if !ok {
			core.ClearBytes(p)
			core.ClearBytes(c)
			return
		}
		runBusy(g, "Protecting your key…",
			func() (struct{}, error) { return struct{}{}, g.svc.ProtectKey(k.PrivFile, p, c) },
			func(_ struct{}, err error) {
				if err != nil {
					g.showProtectKey(k, app.Message(err))
					return
				}
				g.tell("Key protected", "Your key is now protected by your passphrase.", g.showKeys)
			})
	}, g.win)
	confirm.OnSubmitted = func(string) { d.Confirm() }
	d.Resize(fyne.NewSize(480, d.MinSize().Height))
	d.Show()
	g.win.Canvas().Focus(pass)
}

// confirmDeleteKey asks before deleting a key, explaining the consequence.
func (g *gui) confirmDeleteKey(k app.Key) {
	msg := fmt.Sprintf("Delete \"%s\"? This can't be undone.", k.Name)
	if k.PrivFile != "" {
		msg += "\n\nYou will no longer be able to decrypt any file that was encrypted for this key."
	} else {
		msg += "\n\nYou will no longer be able to encrypt files for this contact until you add their key again."
	}
	d := dialog.NewConfirm("Delete key?", msg, func(yes bool) {
		if !yes {
			return
		}
		if err := g.svc.DeleteKey(k.Base); err != nil {
			g.problem("Couldn't delete the key", err, g.showKeys)
			return
		}
		g.showKeys()
	}, g.win)
	d.SetConfirmText("Delete")
	d.SetConfirmImportance(widget.DangerImportance)
	d.Show()
}
