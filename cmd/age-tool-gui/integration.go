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
