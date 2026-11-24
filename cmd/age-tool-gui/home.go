// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showHome shows the home screen: three large actions, plus the activity
// view. Files can also be dropped anywhere on the window.
func (g *gui) showHome() {
	// bigButton makes a tall, clearly labelled action button
	bigButton := func(label string, icon fyne.Resource, tapped func()) fyne.CanvasObject {
		b := widget.NewButtonWithIcon(label, icon, tapped)
		b.Importance = widget.HighImportance
		return container.NewGridWrap(fyne.NewSize(360, 56), b)
	}

	intro := widget.NewLabel("Keep files private by encrypting them for a key. Only the matching private key, " +
		"protected by its passphrase, can decrypt them.")
	intro.Wrapping = fyne.TextWrapWord

	actions := container.NewVBox(
		container.NewCenter(bigButton("Encrypt a file", theme.ContentAddIcon(), func() { g.showEncrypt(nil) })),
		container.NewCenter(bigButton("Decrypt a file", theme.VisibilityIcon(), func() { g.showDecrypt(nil) })),
		container.NewCenter(bigButton("My keys", theme.AccountIcon(), g.showKeys)),
	)
	activity := widget.NewButtonWithIcon("View activity", theme.HistoryIcon(), g.showActivity)
	activity.Importance = widget.LowImportance
	hint := widget.NewLabelWithStyle("Tip: you can also drop files onto this window.",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	g.showScreen("age-tool", false, container.NewVBox(
		intro,
		layoutSpacer(),
		actions,
		layoutSpacer(),
		container.NewCenter(activity),
		hint,
	))
}

// layoutSpacer is a small fixed gap between groups of widgets.
func layoutSpacer() fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(1, theme.Padding()*3))
}

// ─── Choosing files ─────────────────────────────────────────────────────────

// pickFile shows a file dialog and calls chosen with the selected file's
// path. With encrypted true, only .age files are offered. The dialog opens
// in the folder of the last file chosen.
func (g *gui) pickFile(encrypted bool, chosen func(path string)) {
	d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return // cancelled
		}
		// Only the path is needed; the workflows open the file themselves
		path := r.URI().Path()
		_ = r.Close()
		g.lastDir = filepath.Dir(path)
		chosen(path)
	}, g.win)
	if encrypted {
		d.SetFilter(storage.NewExtensionFileFilter([]string{core.AgeExt}))
	}
	if g.lastDir != "" {
		if dir, err := storage.ListerForURI(storage.NewFileURI(g.lastDir)); err == nil {
			d.SetLocation(dir)
		}
	}
	d.Resize(g.win.Canvas().Size())
	d.Show()
}

// pickFolder shows a folder dialog and calls chosen with the folder's path.
func (g *gui) pickFolder(chosen func(path string)) {
	d := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
		if err != nil || dir == nil {
			return // cancelled
		}
		chosen(dir.Path())
	}, g.win)
	if g.lastDir != "" {
		if dir, err := storage.ListerForURI(storage.NewFileURI(g.lastDir)); err == nil {
			d.SetLocation(dir)
		}
	}
	d.Resize(g.win.Canvas().Size())
	d.Show()
}

// describeFiles names the chosen files for display: the file name, or a
// count when there are several.
func describeFiles(files []string) string {
	switch len(files) {
	case 0:
		return "No file chosen"
	case 1:
		return filepath.Base(files[0])
	default:
		names := make([]string, 0, 3)
		for _, f := range files[:min(3, len(files))] {
			names = append(names, filepath.Base(f))
		}
		more := ""
		if len(files) > 3 {
			more = fmt.Sprintf(" and %d more", len(files)-3)
		}
		return fmt.Sprintf("%d files: %s%s", len(files), strings.Join(names, ", "), more)
	}
}

// fileStep is the "choose a file" part of the encrypt and decrypt
// screens: the chosen file's name and folder (or how many files), and a
// button to choose another. changed is called with the new list after a
// choice. Long names are shortened with "…" rather than wrapped.
func (g *gui) fileStep(files []string, encrypted bool, changed func([]string)) fyne.CanvasObject {
	name := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	name.Truncation = fyne.TextTruncateEllipsis
	folder := widget.NewLabel("")
	folder.Truncation = fyne.TextTruncateEllipsis
	show := func(files []string) {
		switch len(files) {
		case 0:
			name.SetText("No file chosen yet")
			folder.SetText("")
		case 1:
			name.SetText(filepath.Base(files[0]))
			folder.SetText("in " + filepath.Dir(files[0]))
		default:
			name.SetText(describeFiles(files))
			folder.SetText("in " + filepath.Dir(files[0]))
		}
	}
	show(files)
	choose := widget.NewButtonWithIcon("Choose a file…", theme.FolderOpenIcon(), func() {
		g.pickFile(encrypted, func(path string) {
			show([]string{path})
			changed([]string{path})
		})
	})
	return container.NewBorder(nil, nil, nil, container.NewCenter(choose),
		container.New(layout.NewCustomPaddedVBoxLayout(0), name, folder))
}

// workflowLayout arranges an encrypt or decrypt screen: the steps at the
// top, the list of keys filling the space in the middle (scrolling if
// long), and the note and action button at the bottom.
func workflowLayout(top []fyne.CanvasObject, choices fyne.CanvasObject, note string, action *widget.Button) fyne.CanvasObject {
	// The note gets the full width: Fyne sizes a wrapping label correctly
	// only when nothing sits beside it
	noteLabel := widget.NewLabel(note)
	noteLabel.Wrapping = fyne.TextWrapWord
	return container.NewBorder(
		container.NewVBox(top...),
		container.NewVBox(widget.NewSeparator(), noteLabel, container.NewHBox(layout.NewSpacer(), action)),
		nil, nil,
		container.NewVScroll(choices))
}

// stepHeading is a bold numbered heading for a step of a workflow.
func stepHeading(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}
