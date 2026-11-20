// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
)

// AgeExt is the extension of encrypted files.
const AgeExt = ".age"

// EncryptedOutputPath returns the output path for encrypting inputPath:
// the same path with ".age" appended (document.txt -> document.txt.age).
func EncryptedOutputPath(inputPath string) string {
	return inputPath + AgeExt
}

// DecryptedOutputPath returns the output path for decrypting inputPath:
// the same path with ".age" removed (document.txt.age -> document.txt).
func DecryptedOutputPath(inputPath string) string {
	return strings.TrimSuffix(inputPath, AgeExt)
}

// ─── In-progress output tracking ────────────────────────────────────────────

// inProgressPath is the temp file currently being written by
// writeOutputAtomically, if any, so an interrupt handler can remove it.
// Guarded by a mutex because signal handlers run in their own goroutine.
var (
	inProgressMu   sync.Mutex
	inProgressPath string
)

// setInProgress records (or clears, with "") the in-progress temp file path.
func setInProgress(path string) {
	inProgressMu.Lock()
	defer inProgressMu.Unlock()
	inProgressPath = path
}

// RemoveInProgressOutput deletes the partial output file currently being
// written, if any. Front ends call this when interrupted (e.g. on Ctrl+C)
// so no partial plaintext is left behind.
func RemoveInProgressOutput() {
	inProgressMu.Lock()
	defer inProgressMu.Unlock()
	if inProgressPath != "" {
		_ = os.Remove(inProgressPath)
		inProgressPath = ""
	}
}

// ─── Encrypt / decrypt ──────────────────────────────────────────────────────

// writeOutputAtomically writes an output file so that it only ever appears
// complete. The write callback streams into a hidden temporary file in the
// same directory as outputPath (created owner-only, 0600); only after the
// callback succeeds and the data is flushed to disk is the temp file
// renamed over outputPath. On any failure the temp file is removed and
// outputPath is left untouched, so a failed or corrupted decryption never
// leaves a truncated plaintext file behind or destroys an existing file.
func writeOutputAtomically(outputPath string, write func(w io.Writer) error) error {
	// Same directory as the output, so the final rename is atomic.
	// os.CreateTemp creates the file with 0600 permissions and a random suffix.
	tmp, err := os.CreateTemp(filepath.Dir(outputPath), PartialFilePrefix+"*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Let an interrupt handler remove this file if interrupted mid-write
	setInProgress(tmpPath)
	defer setInProgress("")

	// Remove the temp file on every failure path below
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close() // best-effort cleanup; the write error is what gets reported
			_ = os.Remove(tmpPath)
		}
	}()

	if err := write(tmp); err != nil {
		return err
	}
	// Flush to disk before the rename so a crash can't leave an empty or
	// partial file under the final name
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Atomically replace (or create) the final output file
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return err
	}
	committed = true
	return nil
}

// EncryptFile encrypts the contents of inputPath to outputPath for the
// given age recipient (public key). Output is written atomically with
// owner-only permissions (0600).
func EncryptFile(inputPath, outputPath string, recipient age.Recipient) error {
	in, err := os.Open(filepath.Clean(inputPath))
	if err != nil {
		return err
	}
	defer in.Close()

	return writeOutputAtomically(outputPath, func(out io.Writer) error {
		w, err := age.Encrypt(out, recipient)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, in); err != nil {
			return err
		}
		// Close writes the final authenticated chunk; it must succeed
		return w.Close()
	})
}

// DecryptFile decrypts the contents of inputPath to outputPath using the
// given age identity (private key). Output is written atomically with
// owner-only permissions (0600): if the ciphertext is corrupted or
// truncated, age's per-chunk authentication fails part-way through and no
// output file is produced. A wrong key fails before any output is created.
func DecryptFile(inputPath, outputPath string, identity age.Identity) error {
	in, err := os.Open(filepath.Clean(inputPath))
	if err != nil {
		return err
	}
	defer in.Close()

	// Check the header and key before creating any output
	r, err := age.Decrypt(in, identity)
	if err != nil {
		return err
	}

	return writeOutputAtomically(outputPath, func(out io.Writer) error {
		_, err := io.Copy(out, r)
		return err
	})
}

// FindLeftoverTempFiles returns the names of temporary files in dir left
// by a session that was killed mid-operation:
//   - .tmpkey-*           decrypted private keys written by v1.2.0 and earlier
//   - .age-tool-partial-* incomplete encrypt/decrypt output (may be plaintext)
func FindLeftoverTempFiles(dir string) ([]string, error) {
	return ListFiles(dir, func(name string) bool {
		return strings.HasPrefix(name, LegacyTmpKeyPrefix) || strings.HasPrefix(name, PartialFilePrefix)
	})
}
