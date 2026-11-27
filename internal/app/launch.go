// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package app

import (
	"fmt"
	"strings"

	"age-tool/internal/core"
)

// Action is the screen the GUI opens on.
type Action int

// Screens the GUI can be launched into.
const (
	ActionHome           Action = iota // The home screen
	ActionEncrypt                      // Encrypt the given files
	ActionDecrypt                      // Decrypt the given files
	ActionHelp                         // Print usage and exit
	ActionVersion                      // Print the version and exit
	ActionInstallDesktop               // Install the Linux desktop integration and exit
	ActionRemoveDesktop                // Remove the Linux desktop integration and exit
)

// Launch is what the GUI was asked to do on the command line.
type Launch struct {
	Action Action
	Files  []string // Files to encrypt or decrypt, in the order given
}

// ParseLaunch interprets the GUI's command-line arguments (excluding the
// program name). The desktop integration in Milestone 4 relies on these:
//
//	age-tool-gui                      open the home screen
//	age-tool-gui encrypt <file>...    encrypt files (right-click "Encrypt")
//	age-tool-gui decrypt <file>...    decrypt files (right-click "Decrypt")
//	age-tool-gui <file>...            decrypt .age files, encrypt others
//	                                  (double-clicking a .age file)
//	age-tool-gui --help | --version
//	age-tool-gui --install-desktop | --remove-desktop   (Linux menus)
//
// File managers can pass several selected files at once. With bare files
// they must be all .age files or all other files, so it's clear which
// action is meant. A "--" ends the options, for file names starting "-".
func ParseLaunch(args []string) (Launch, error) {
	// Options come before any files
	if len(args) > 0 {
		switch args[0] {
		case "--help", "-help", "-h":
			return Launch{Action: ActionHelp}, nil
		case "--version", "-version":
			return Launch{Action: ActionVersion}, nil
		case "--install-desktop":
			return Launch{Action: ActionInstallDesktop}, nil
		case "--remove-desktop":
			return Launch{Action: ActionRemoveDesktop}, nil
		case "--":
			args = args[1:]
		default:
			if strings.HasPrefix(args[0], "-") {
				return Launch{}, fmt.Errorf("unknown option %q", args[0])
			}
		}
	}
	if len(args) == 0 {
		return Launch{Action: ActionHome}, nil
	}

	// An explicit action word followed by at least one file
	switch args[0] {
	case "encrypt", "decrypt":
		files := args[1:]
		if len(files) > 0 && files[0] == "--" {
			files = files[1:]
		}
		if len(files) == 0 {
			return Launch{}, fmt.Errorf("%s needs at least one file", args[0])
		}
		action := ActionEncrypt
		if args[0] == "decrypt" {
			action = ActionDecrypt
		}
		return Launch{Action: action, Files: files}, nil
	}

	// Bare files: decide by extension, refusing a mixture
	encrypted := 0
	for _, f := range args {
		if strings.HasSuffix(f, core.AgeExt) {
			encrypted++
		}
	}
	switch encrypted {
	case len(args):
		return Launch{Action: ActionDecrypt, Files: args}, nil
	case 0:
		return Launch{Action: ActionEncrypt, Files: args}, nil
	default:
		return Launch{}, fmt.Errorf("choose either encrypted (.age) files to decrypt or other files to encrypt, not both")
	}
}

// Usage is the GUI's command-line help.
const Usage = `Usage:
  age-tool-gui                     Open age-tool
  age-tool-gui encrypt <file>...   Encrypt files
  age-tool-gui decrypt <file>...   Decrypt .age files
  age-tool-gui <file>...           Decrypt .age files, or encrypt other files
  age-tool-gui --install-desktop   Add age-tool to the Linux app menu and
                                   right-click menus (for this user only)
  age-tool-gui --remove-desktop    Remove them again
  age-tool-gui --version           Show the version
  age-tool-gui --help              Show this help
`
