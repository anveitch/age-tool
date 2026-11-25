// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

// Command appdir lays out the AppImage's contents (its "AppDir") for the
// desktop app. It is run by packaging/linux/build-gui.sh inside the Linux
// build container; the result is packed into a SquashFS image and joined
// to the AppImage runtime.
//
// Usage: go run ./packaging/linux/appdir <appdir> <age-tool-gui binary>
//
// The desktop entry and icons come from internal/desktop, so the AppImage
// and the menus installed by --install-desktop always match.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"age-tool/internal/desktop"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: appdir <appdir> <age-tool-gui binary>")
		os.Exit(2)
	}
	if err := build(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "appdir: %v\n", err)
		os.Exit(1)
	}
}

// build creates the AppDir at dir, which must not exist yet:
//
//	AppRun                       -> usr/bin/age-tool-gui (started by the runtime)
//	usr/bin/age-tool-gui         the program
//	<AppID>.desktop              name, icon and file types
//	<AppID>.svg, .DirIcon        the icon (.DirIcon is what file managers show)
//	usr/share/icons/.../<AppID>.svg   the icon again, where desktop tools look
//
// Both paths come from the build script's command line, so they are only
// cleaned, not restricted; this tool never runs on user input.
func build(dir, binary string) error {
	dir, binary = filepath.Clean(dir), filepath.Clean(binary)
	if _, err := os.Lstat(dir); err == nil { // #nosec G703 -- build script's own path
		return fmt.Errorf("%s already exists", dir)
	}
	program, err := os.ReadFile(binary) // #nosec G304 G703 -- path given by the build script
	if err != nil {
		return err
	}

	iconName := desktop.AppID + ".svg"
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join("usr", "bin", desktop.ExeName), program, 0o755},
		{desktop.AppID + ".desktop", desktop.AppImageEntry(), 0o644},
		{iconName, desktop.AppIcon(), 0o644},
		{filepath.Join("usr", "share", "icons", "hicolor", "scalable", "apps", iconName), desktop.AppIcon(), 0o644},
	}
	for _, f := range files {
		path := filepath.Join(dir, f.path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 G703 -- AppDir contents are public, under the build script's path
			return err
		}
		if err := os.WriteFile(path, f.data, f.mode); err != nil { // #nosec G306 G703 -- AppDir contents are public, under the build script's path
			return err
		}
	}

	// Relative symlinks, so they still resolve once the image is mounted
	links := map[string]string{
		"AppRun":   filepath.Join("usr", "bin", desktop.ExeName),
		".DirIcon": iconName,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}
