// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Command age-tool-gui is the desktop front end for age-tool, aimed at
// non-technical users. It only gathers choices and shows results: every
// workflow (and every security rule) lives in internal/app and
// internal/core, shared with the CLI.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"age-tool/internal/app"
	"age-tool/internal/core"
	"age-tool/internal/desktop"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// gui holds the window and the shared workflow service. Nothing secret is
// stored here.
type gui struct {
	fy      fyne.App
	win     fyne.Window
	svc     *app.Service
	busy    bool   // An encrypt/decrypt/key operation is running
	lastDir string // Folder of the last file chosen, where file dialogs open next
}

func main() {
	// Command-line arguments choose the starting screen (Milestone 4's
	// right-click and double-click entries use these)
	launch, err := app.ParseLaunch(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-tool-gui: %v\n\n%s", err, app.Usage)
		os.Exit(2)
	}
	switch launch.Action {
	case app.ActionHelp:
		fmt.Print(app.Usage)
		return
	case app.ActionVersion:
		fmt.Printf("age-tool-gui %s\n", core.Version)
		return
	case app.ActionInstallDesktop, app.ActionRemoveDesktop:
		os.Exit(desktopCommand(launch.Action == app.ActionInstallDesktop))
	}

	g := &gui{fy: fyneapp.NewWithID(desktop.AppID)}
	g.fy.SetIcon(fyne.NewStaticResource(desktop.AppID+".svg", desktop.AppIcon()))
	g.win = g.fy.NewWindow("age-tool")
	g.win.Resize(fyne.NewSize(620, 520))

	// Files given on the command line are converted to absolute paths, so
	// dialogs and messages refer to them unambiguously
	files := make([]string, 0, len(launch.Files))
	for _, f := range launch.Files {
		if abs, err := filepath.Abs(f); err == nil {
			f = abs
		}
		files = append(files, f)
	}
	if len(files) > 0 {
		g.lastDir = filepath.Dir(files[0])
	}

	svc, err := app.New()
	if err != nil {
		// Without a key store nothing else works, so explain and stop
		g.win.SetContent(widget.NewLabel("age-tool could not set up its key folder.\n\n" + app.Message(err)))
		g.win.ShowAndRun()
		return
	}
	g.svc = svc
	g.tightenKeyPermissions()
	g.installCleanup()

	// Dropping files on the window starts the matching workflow
	g.win.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) { g.openDropped(uris) })

	switch launch.Action {
	case app.ActionEncrypt:
		g.showEncrypt(files)
	case app.ActionDecrypt:
		g.showDecrypt(files)
	default:
		g.showHome()
		g.offerIntegration()
	}
	if devHook != nil {
		devHook(g)
	}
	g.win.ShowAndRun()
}

// devHook, when set by a development build, runs once the window is ready.
var devHook func(*gui)

// tightenKeyPermissions makes sure private keys are owner-only (0600),
// fixing any that were loosened. The CLI asks first; the GUI's users
// can't be expected to know the answer, and the key store is age-tool's
// own folder, so it just fixes them.
func (g *gui) tightenKeyPermissions() {
	loose, err := core.PermissiveKeyFiles(g.svc.KeysDir)
	if err != nil {
		return
	}
	for _, f := range loose {
		_ = core.FixKeyPermissions(filepath.Join(g.svc.KeysDir, f))
	}
}

// installCleanup removes any half-written output if the app is closed or
// killed mid-operation, so no partial plaintext is left behind.
func (g *gui) installCleanup() {
	// Ctrl+C in a terminal, or a logout/shutdown signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		core.RemoveInProgressOutput()
		os.Exit(1)
	}()

	// Closing the window while working asks first, then cleans up
	g.win.SetCloseIntercept(func() {
		if !g.busy {
			g.fy.Quit()
			return
		}
		dialog.ShowConfirm("Stop and quit?",
			"age-tool is still working. If you quit now, the file being written will be removed.",
			func(quit bool) {
				if quit {
					core.RemoveInProgressOutput()
					g.fy.Quit()
				}
			}, g.win)
	})
}

// openDropped starts the right workflow for files dropped on the window:
// decrypt for .age files, encrypt for anything else. While busy, drops
// are ignored.
func (g *gui) openDropped(uris []fyne.URI) {
	if g.busy {
		return
	}
	var paths []string
	for _, u := range uris {
		if u.Scheme() == "file" {
			paths = append(paths, u.Path())
		}
	}
	launch, err := app.ParseLaunch(append([]string{"--"}, paths...))
	if err != nil || len(paths) == 0 {
		dialog.ShowInformation("Can't open these files",
			"Drop either encrypted (.age) files to decrypt, or other files to encrypt, but not both at once.", g.win)
		return
	}
	g.lastDir = filepath.Dir(paths[0])
	if launch.Action == app.ActionDecrypt {
		g.showDecrypt(paths)
	} else {
		g.showEncrypt(paths)
	}
}

// ─── Screens and navigation ─────────────────────────────────────────────────

// showScreen replaces the window's content with a screen: a heading, a
// Back button (except on the home screen) and the screen's body.
func (g *gui) showScreen(title string, back bool, body fyne.CanvasObject) {
	heading := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	heading.SizeName = theme.SizeNameSubHeadingText
	var top fyne.CanvasObject = heading
	if back {
		backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), g.showHome)
		top = container.NewBorder(nil, nil, backBtn, nil, heading)
	}
	g.win.SetContent(container.NewBorder(
		container.NewVBox(top, widget.NewSeparator()), nil, nil, nil,
		container.NewPadded(body)))
}

// textScreen lays out a screen that is mostly text: the objects stacked
// at the top, with the rest of the window empty. Placing them in a Border's
// top edge lets Fyne size wrapping labels correctly.
func textScreen(objects ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewBorder(container.NewVBox(objects...), nil, nil, nil)
}

// ─── Background work ────────────────────────────────────────────────────────

// runBusy runs work in the background while showing a busy dialog titled
// title, then calls done with the result on the UI thread. Encrypting a
// large file or unlocking a key (deliberately slow, to resist guessing)
// would otherwise freeze the window.
func runBusy[T any](g *gui, title string, work func() (T, error), done func(T, error)) {
	g.busy = true
	bar := widget.NewProgressBarInfinite()
	busy := dialog.NewCustomWithoutButtons(title, container.NewPadded(bar), g.win)
	busy.Show()
	go func() {
		result, err := work()
		fyne.Do(func() {
			busy.Hide()
			g.busy = false
			done(result, err)
		})
	}()
}

// ─── Messages ───────────────────────────────────────────────────────────────

// tell shows an information dialog and calls then (if not nil) once it
// is dismissed, so several files can be handled one after another.
func (g *gui) tell(title, message string, then func()) {
	d := dialog.NewInformation(title, message, g.win)
	if then != nil {
		d.SetOnClosed(then)
	}
	d.Show()
}

// problem reports err in plain language, then calls then (if not nil).
func (g *gui) problem(title string, err error, then func()) {
	g.tell(title, app.Message(err), then)
}

// warn shows any non-fatal warnings from a finished operation (e.g. an
// audit log that couldn't be written), then calls then.
func (g *gui) warn(warnings []error, then func()) {
	if len(warnings) == 0 {
		if then != nil {
			then()
		}
		return
	}
	msg := "The file was saved, but the activity log couldn't be fully updated:\n"
	for _, w := range warnings {
		msg += "\n• " + w.Error()
	}
	g.tell("Activity log not updated", msg, then)
}
