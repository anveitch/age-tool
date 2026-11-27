// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"age-tool/internal/desktop"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// desktopCommand runs --install-desktop (install true) or
// --remove-desktop from the command line, printing what happened.
// Returns the process exit code.
func desktopCommand(install bool) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Desktop integration is only available on Linux.")
		return 1
	}
	in, err := desktop.Default()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	var report desktop.Report
	if install {
		report, err = in.Install()
	} else {
		report, err = in.Uninstall()
	}
	for _, w := range report.Warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if install {
		fmt.Printf("age-tool is now in your app menu, and right-click Encrypt/Decrypt entries are installed.\n")
		fmt.Printf("Menus start: %s\n", in.Exe)
	} else {
		fmt.Printf("age-tool's menu entries have been removed (%d files changed).\n", len(report.Changed))
	}
	return 0
}

// showIntegration shows the Linux desktop integration screen: what it
// adds, whether it is installed, and buttons to install, update or remove
// it.
func (g *gui) showIntegration() {
	in, err := desktop.Default()
	if err != nil {
		g.problem("Desktop integration unavailable", err, g.showHome)
		return
	}

	intro := wrapped("Add age-tool to your desktop, for you only:\n\n" +
		"• age-tool in your app menu\n" +
		"• Double-click a .age file to decrypt it\n" +
		"• Right-click any file to encrypt it, or a .age file to decrypt it, " +
		"in the Files, Dolphin, Nemo and Thunar file managers. " +
		"(In Files, the entries are under Scripts.)")

	var status string
	installLabel := "Install"
	switch in.Status() {
	case desktop.Installed:
		status = "Installed."
		installLabel = "Reinstall"
	case desktop.Outdated:
		status = "Installed, but for a copy of age-tool in a different place. Choose Update so the menus open this copy."
		installLabel = "Update"
	default:
		status = "Not installed."
	}
	statusLabel := wrapped(status)
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	install := widget.NewButtonWithIcon(installLabel, theme.DownloadIcon(), func() {
		report, err := in.Install()
		g.integrationResult("Desktop integration installed",
			"age-tool is now in your app menu. The right-click entries appear the next time the file manager opens a window.",
			report, err)
	})
	install.Importance = widget.HighImportance
	remove := widget.NewButtonWithIcon("Remove", theme.DeleteIcon(), func() {
		report, err := in.Uninstall()
		g.integrationResult("Desktop integration removed",
			"age-tool's menu entries have been removed. Your keys and files are not affected.", report, err)
	})
	setEnabled(remove, in.Status() != desktop.NotInstalled)

	g.showScreen("Desktop integration", true, textScreen(
		intro,
		widget.NewSeparator(),
		statusLabel,
		container.NewHBox(install, remove),
	))
}

// integrationResult reports the outcome of installing or removing the
// integration, including any warnings, then shows the screen again.
func (g *gui) integrationResult(title, success string, report desktop.Report, err error) {
	if err != nil {
		g.tell("Something went wrong", "The desktop integration couldn't be fully changed.\n\n"+err.Error(), g.showIntegration)
		return
	}
	msg := success
	if len(report.Warnings) > 0 {
		msg += "\n\nNote:\n• " + strings.Join(report.Warnings, "\n• ")
	}
	g.tell(title, msg, g.showIntegration)
}

// declinedPref stores the program path for which the user chose "Not now"
// in offerIntegration, so they are only asked once per copy of the app.
const declinedPref = "desktopIntegrationDeclinedFor"

// offerIntegration runs when the app starts from an AppImage (the download
// users double-click). If age-tool isn't in the app menu yet, or the menus
// open a different copy (an older download, or one since moved), it offers
// to set that up, so users never need the Desktop integration screen or a
// terminal. Saying "Not now" is remembered for this copy.
func (g *gui) offerIntegration() {
	if runtime.GOOS != "linux" || os.Getenv("APPIMAGE") == "" {
		return
	}
	in, err := desktop.Default()
	if err != nil {
		return
	}
	status := in.Status()
	prefs := g.fy.Preferences()
	if status == desktop.Installed || prefs.String(declinedPref) == in.Exe {
		return
	}

	title, text, accept := "Add age-tool to your desktop?",
		"This puts age-tool in your app menu, lets you double-click .age files to decrypt them, "+
			"and adds Encrypt and Decrypt to the right-click menu of your files.", "Add to desktop"
	if status == desktop.Outdated {
		title, text, accept = "Update age-tool's menus?",
			"age-tool's menu entries open a copy of age-tool in a different place. "+
				"Update them so they open this copy?", "Update"
	}
	text += "\n\nYou can change this later with Desktop integration on the home screen."

	d := dialog.NewConfirm(title, text, func(ok bool) {
		if !ok {
			prefs.SetString(declinedPref, in.Exe)
			return
		}
		report, err := in.Install()
		if err != nil {
			g.tell("Something went wrong", "age-tool couldn't be added to your desktop.\n\n"+err.Error(), g.showHome)
			return
		}
		msg := "age-tool is now in your app menu. The right-click entries appear the next time the file manager opens a window."
		if len(report.Warnings) > 0 {
			msg += "\n\nNote:\n• " + strings.Join(report.Warnings, "\n• ")
		}
		g.tell("Added to your desktop", msg, g.showHome)
	}, g.win)
	d.SetConfirmText(accept)
	d.SetDismissText("Not now")
	d.Show()
}
