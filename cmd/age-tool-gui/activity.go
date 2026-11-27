// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"fmt"
	"path/filepath"

	"age-tool/internal/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// activityLimit is how many recent transactions the activity view shows.
const activityLimit = 500

// showActivity shows a read-only list of recent transactions from the
// central audit log, newest first.
func (g *gui) showActivity() {
	entries, skipped, err := g.svc.Activity(activityLimit)
	if err != nil {
		g.problem("Couldn't read the activity log", err, g.showHome)
		return
	}

	// The log's location, shortened with "…" if long; it can be selected
	// and copied
	where := widget.NewLabel("Full log: " + g.svc.Locations.CentralAudit().LogFile)
	where.Truncation = fyne.TextTruncateEllipsis
	where.Selectable = true
	var footer fyne.CanvasObject = where
	if skipped > 0 {
		footer = vbox(wrapped(fmt.Sprintf("%d log entries couldn't be read and are not shown.", skipped)), where)
	}

	if len(entries) == 0 {
		g.showScreen("Activity", true, textScreen(wrapped("Nothing yet. Files you encrypt or decrypt, and keys you create, will be listed here."), footer))
		return
	}

	list := widget.NewList(
		func() int { return len(entries) },
		// Each row: an icon, with what happened above when it happened
		func() fyne.CanvasObject {
			what := widget.NewLabel("")
			what.Truncation = fyne.TextTruncateEllipsis
			when := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
			return container.NewBorder(nil, nil, widget.NewIcon(theme.HistoryIcon()), nil,
				container.New(layout.NewCustomPaddedVBoxLayout(0), what, when))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			e := entries[id]
			row := obj.(*fyne.Container)
			icon, text := describeActivity(e)
			// Border stores its centre object first, then the left one
			lines := row.Objects[0].(*fyne.Container)
			row.Objects[1].(*widget.Icon).SetResource(icon)
			lines.Objects[0].(*widget.Label).SetText(text)
			lines.Objects[1].(*widget.Label).SetText(e.Time.Local().Format("Mon 2 Jan 2006 at 15:04"))
		})

	g.showScreen("Activity", true, container.NewBorder(nil, footer, nil, nil, list))
}

// describeActivity returns an icon and a one-line description of a
// transaction, e.g. "Encrypted report.pdf for Alice" or "Encrypted
// report.pdf with a password".
func describeActivity(e core.ActivityEntry) (fyne.Resource, string) {
	key := e.KeyNickname
	if key == "" {
		key = trimExt(e.Key)
	}
	switch {
	case e.Type == core.ActivityEncrypt && e.Method == core.MethodPassword:
		return theme.ContentAddIcon(), fmt.Sprintf("Encrypted %s with a password  (%s)", filepath.Base(e.Source), filepath.Dir(e.Source))
	case e.Type == core.ActivityDecrypt && e.Method == core.MethodPassword:
		return theme.VisibilityIcon(), fmt.Sprintf("Decrypted %s with a password  (%s)", filepath.Base(e.Source), filepath.Dir(e.Source))
	}
	switch e.Type {
	case core.ActivityEncrypt:
		return theme.ContentAddIcon(), fmt.Sprintf("Encrypted %s for %s  (%s)", filepath.Base(e.Source), key, filepath.Dir(e.Source))
	case core.ActivityDecrypt:
		return theme.VisibilityIcon(), fmt.Sprintf("Decrypted %s with %s  (%s)", filepath.Base(e.Source), key, filepath.Dir(e.Source))
	default:
		return theme.AccountIcon(), "Created key " + e.KeyName
	}
}
