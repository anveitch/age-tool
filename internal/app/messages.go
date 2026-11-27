// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package app

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"age-tool/internal/core"
)

// message pairs an error kind with the plain-language text shown for it.
type message struct {
	kind error
	text string
}

// messages are checked in order, so more specific kinds come first. The
// text is written for non-technical users: what happened and what to do,
// never Go error text.
var messages = []message{
	// Encrypting and decrypting
	{ErrOutputExists, "A file with that name already exists."},
	{ErrAlreadyEncrypted, "This file is already encrypted."},
	{ErrNotAgeFile, "This isn't an encrypted file. Encrypted files end in .age."},
	{ErrIsFolder, "That's a folder. Please choose a single file."},
	{ErrWrongKey, "This file wasn't encrypted for the key you chose. Try another of your keys, or ask the sender which key they used."},
	{core.ErrWrongPassphrase, "That passphrase is incorrect. Please try again."},
	{ErrTooManyAttempts, "The passphrase was incorrect too many times. Please start again."},
	{ErrFinished, "This decryption has already finished. Please start again."},
	{ErrDecryptFailed, "The file couldn't be decrypted. It may be damaged or incomplete, or there may not be enough disk space. Nothing was saved."},
	{ErrEncryptFailed, "The file couldn't be encrypted. There may not be enough disk space, or the folder may be read-only. Nothing was saved."},
	{core.ErrWrongPassword, "That password is incorrect. Please try again."},
	{ErrTooManyPasswordAttempts, "The password was incorrect too many times. Please start again."},
	{ErrNotPasswordFile, "This file was encrypted for a key, not with a password. Choose one of your keys to decrypt it."},
	{ErrPasswordMismatch, "The two passwords don't match. Please type them again."},
	{core.ErrFileTooLarge, fmt.Sprintf("This file is too large. The limit is %d GB.", core.MaxFileSize/(1024*1024*1024))},

	// Keys
	{core.ErrKeyNotProtected, "This private key isn't protected by a passphrase, so it can't be used yet. Protect it in My keys first."},
	{core.ErrKeyExists, "You already have a key with that name. Please choose a different name."},
	{core.ErrIsPrivateKey, "That's a private key. Never share it or import it as a contact. Ask the person for their public key instead (it starts with \"age1\")."},
	{core.ErrNotPublicKey, "That isn't a valid public key. A public key is a single line starting with \"age1\"."},
	{ErrPassphraseMismatch, "The two passphrases don't match. Please type them again."},
	{core.ErrPassphraseTooShort, fmt.Sprintf("The passphrase must be at least %d characters long.", core.MinPassphraseLen)},
	{core.ErrInvalidName, fmt.Sprintf("Please use a simple name, up to %d characters, without slashes or \"..\".", core.MaxInputLength)},

	// Saved passwords
	{core.ErrNoOwnKey, "You need a key of your own to save a record of a password. Create one in My keys."},
	{core.ErrRecordNotForKey, "This saved password wasn't protected with that key. Try another of your keys."},
	{core.ErrRecordNotFound, "That saved password couldn't be found. It may have been deleted."},
	{core.ErrRecordDamaged, "That saved password is damaged and can't be read."},

	// File system problems
	{core.ErrFileUnavailable, "The file couldn't be opened. It may have been moved or deleted."},
	{os.ErrNotExist, "The file couldn't be found. It may have been moved or deleted."},
	{os.ErrPermission, "You don't have permission to use this file or folder."},
	{syscall.ENOSPC, "There isn't enough disk space."},
}

// Message returns a plain-language description of err for the GUI to
// show. Unrecognised errors get a general message rather than their text,
// which may be technical.
func Message(err error) string {
	if err == nil {
		return ""
	}
	for _, m := range messages {
		if errors.Is(err, m.kind) {
			return m.text
		}
	}
	return "Something went wrong. Please try again."
}

// AttemptsMessage describes a wrong passphrase with attempts remaining,
// e.g. "That passphrase is incorrect. 2 attempts left."
func AttemptsMessage(left int) string {
	if left == 1 {
		return "That passphrase is incorrect. 1 attempt left."
	}
	return fmt.Sprintf("That passphrase is incorrect. %d attempts left.", left)
}

// PasswordAttemptsMessage describes a wrong file password with attempts
// remaining, e.g. "That password is incorrect. 2 attempts left."
func PasswordAttemptsMessage(left int) string {
	if left == 1 {
		return "That password is incorrect. 1 attempt left."
	}
	return fmt.Sprintf("That password is incorrect. %d attempts left.", left)
}

// PasswordProblem describes why a new file password can't be used. A
// rule problem shows the rule check's own text (which says exactly what to
// change), with a capital letter; other errors get their usual Message.
func PasswordProblem(err error) string {
	if errors.Is(err, core.ErrPasswordTooWeak) {
		text := err.Error()
		return strings.ToUpper(text[:1]) + text[1:] + "."
	}
	return Message(err)
}

// StrengthLabel describes a passphrase strength rating for a meter.
func StrengthLabel(s core.PassphraseStrength) string {
	switch s {
	case core.StrengthTooShort:
		return fmt.Sprintf("Too short: use at least %d characters", core.MinPassphraseLen)
	case core.StrengthWeak:
		return "Weak: easy to guess"
	case core.StrengthFair:
		return "Fair: longer is better"
	default:
		return "Strong"
	}
}
