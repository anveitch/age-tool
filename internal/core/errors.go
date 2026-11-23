// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import "errors"

// Error kinds that front ends can test for with errors.Is, so they can
// choose their own wording (the GUI shows plain-language messages rather
// than the error text). The errors core returns keep their own specific
// text, which the CLI prints as before; the kind only classifies them.
var (
	// ErrInvalidName: a key name or filename is empty, too long, or not a
	// simple filename (path separators, "..", absolute paths).
	ErrInvalidName = errors.New("invalid name")

	// ErrPassphraseTooShort: a new passphrase is shorter than MinPassphraseLen.
	ErrPassphraseTooShort = errors.New("passphrase too short")

	// ErrFileTooLarge: a file is bigger than MaxFileSize.
	ErrFileTooLarge = errors.New("file too large")

	// ErrFileUnavailable: a file doesn't exist or can't be accessed.
	ErrFileUnavailable = errors.New("file unavailable")

	// ErrKeyNotProtected: a private key is not passphrase-protected, so it
	// is refused for decryption until it is protected.
	ErrKeyNotProtected = errors.New("private key not passphrase-protected")

	// ErrNotPublicKey: text or a file doesn't contain a valid age public key.
	ErrNotPublicKey = errors.New("not a public key")

	// ErrIsPrivateKey: a private key was given where a public key was
	// expected (e.g. pasted in as a contact).
	ErrIsPrivateKey = errors.New("private key given as public key")
)

// kindError is an error with its own message that also matches one of the
// error kinds above with errors.Is.
type kindError struct {
	kind error  // One of the Err* kinds above
	msg  string // The specific message, shown by the CLI
}

// Error returns the specific message.
func (e *kindError) Error() string { return e.msg }

// Unwrap returns the kind, so errors.Is(err, kind) is true.
func (e *kindError) Unwrap() error { return e.kind }

// errorOfKind returns an error with message msg that matches kind.
func errorOfKind(kind error, msg string) error {
	return &kindError{kind: kind, msg: msg}
}
