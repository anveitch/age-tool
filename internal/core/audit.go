// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"crypto/md5" // #nosec G501 -- MD5 is a convenience fingerprint in audit logs alongside SHA256, not used for security
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// AuditLog records encrypt, decrypt and key-creation transactions to two
// places: a running one-line-per-transaction log file, and an individual
// JSON receipt per transaction in a receipts directory. No passphrases or
// key material are ever logged — only filenames, hashes, timestamps and
// nicknames.
type AuditLog struct {
	LogFile     string // Path of the running human-readable log, e.g. age-tool.log
	ReceiptsDir string // Directory for JSON receipts, e.g. logs/
}

// Logging failures never stop an operation, so each Record method returns
// any problems as warnings for the front end to display. These are the
// possible warning messages.
var (
	errReceiptsDir   = errors.New("could not create logs directory")
	errReceiptsPerms = errors.New("could not restrict logs directory permissions to 0700")
	errMarshal       = errors.New("could not marshal receipt")
	errReceipt       = errors.New("could not write receipt")
	errLogFile       = errors.New("could not open log file")
)

// HashFile computes both the MD5 and SHA256 hex-encoded hashes of a file.
func HashFile(path string) (md5Hex, sha256Hex string, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	md5Hash := md5.New() // #nosec G401 -- see crypto/md5 import: audit fingerprint only
	sha256Hash := sha256.New()

	// Write file contents to both hashers simultaneously
	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), f); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(md5Hash.Sum(nil)), hex.EncodeToString(sha256Hash.Sum(nil)), nil
}

// ShortHash returns the first 16 characters of a hex hash for the one-line
// log. If hashing failed and the hash is empty or short, it returns
// "unavailable" instead of panicking on an out-of-range slice.
func ShortHash(h string) string {
	if len(h) < 16 {
		return "unavailable"
	}
	return h[:16]
}

// keyLabel formats a key filename with its nickname, if any.
func keyLabel(keyFile, nickname string) string {
	if nickname != "" {
		return fmt.Sprintf("%s (%s)", nickname, keyFile)
	}
	return keyFile
}

// RecordEncrypt logs an encryption of srcFile to outFile with the public
// key keyFile. Both files are hashed; a hash that can't be computed is
// recorded as empty. Returns any logging problems as warnings.
func (a AuditLog) RecordEncrypt(timestamp time.Time, srcFile, outFile, keyFile, keyNickname string) []error {
	srcMD5, srcSHA256, _ := HashFile(srcFile)
	outMD5, outSHA256, _ := HashFile(outFile)

	warnings := a.writeReceipt("encrypt", timestamp, map[string]string{
		"transaction":   "encrypt",
		"timestamp":     timestamp.Format(time.RFC3339),
		"source_file":   srcFile,
		"source_md5":    srcMD5,
		"source_sha256": srcSHA256,
		"output_file":   outFile,
		"output_md5":    outMD5,
		"output_sha256": outSHA256,
		"public_key":    keyFile,
		"key_nickname":  keyNickname,
	})

	line := fmt.Sprintf("[%s] ENCRYPT: %s -> %s | key: %s | src-sha256: %s | out-sha256: %s",
		timestamp.Format("2006-01-02 15:04:05"), srcFile, outFile, keyLabel(keyFile, keyNickname),
		ShortHash(srcSHA256), ShortHash(outSHA256))
	return append(warnings, a.appendLine(line)...)
}

// RecordDecrypt logs a decryption of srcFile to outFile with the private
// key keyFile. Returns any logging problems as warnings.
func (a AuditLog) RecordDecrypt(timestamp time.Time, srcFile, outFile, keyFile, keyNickname string) []error {
	srcMD5, srcSHA256, _ := HashFile(srcFile)
	outMD5, outSHA256, _ := HashFile(outFile)

	warnings := a.writeReceipt("decrypt", timestamp, map[string]string{
		"transaction":   "decrypt",
		"timestamp":     timestamp.Format(time.RFC3339),
		"source_file":   srcFile,
		"source_md5":    srcMD5,
		"source_sha256": srcSHA256,
		"output_file":   outFile,
		"output_md5":    outMD5,
		"output_sha256": outSHA256,
		"private_key":   keyFile,
		"key_nickname":  keyNickname,
	})

	line := fmt.Sprintf("[%s] DECRYPT: %s -> %s | key: %s | src-sha256: %s | out-sha256: %s",
		timestamp.Format("2006-01-02 15:04:05"), srcFile, outFile, keyLabel(keyFile, keyNickname),
		ShortHash(srcSHA256), ShortHash(outSHA256))
	return append(warnings, a.appendLine(line)...)
}

// RecordKeyCreation logs the creation of key pair keyName (pubFile and
// privFile). Returns any logging problems as warnings.
func (a AuditLog) RecordKeyCreation(timestamp time.Time, keyName, pubFile, privFile string) []error {
	pubMD5, pubSHA256, _ := HashFile(pubFile)
	privMD5, privSHA256, _ := HashFile(privFile)

	warnings := a.writeReceipt("key-creation", timestamp, map[string]string{
		"transaction":        "key-creation",
		"timestamp":          timestamp.Format(time.RFC3339),
		"key_pair_name":      keyName,
		"public_key_file":    pubFile,
		"public_key_md5":     pubMD5,
		"public_key_sha256":  pubSHA256,
		"private_key_file":   privFile,
		"private_key_md5":    privMD5,
		"private_key_sha256": privSHA256,
		"private_key_status": "passphrase-encrypted",
	})

	line := fmt.Sprintf("[%s] KEY-CREATION: %s | pub: %s (sha256: %s) | priv: %s [ENCRYPTED] (sha256: %s)",
		timestamp.Format("2006-01-02 15:04:05"), keyName, pubFile, ShortHash(pubSHA256), privFile, ShortHash(privSHA256))
	return append(warnings, a.appendLine(line)...)
}

// writeReceipt creates an individual JSON receipt in the receipts
// directory, named by transaction type and timestamp, e.g.
// encrypt-2026-04-09-143022.json. The directory is created owner-only
// (0700) if needed, and receipts are written owner-only (0600).
func (a AuditLog) writeReceipt(txType string, timestamp time.Time, receipt map[string]string) []error {
	if err := os.MkdirAll(a.ReceiptsDir, 0700); err != nil {
		return []error{errReceiptsDir}
	}

	var warnings []error
	// Tighten the directory if it already existed with looser permissions
	if info, err := os.Stat(a.ReceiptsDir); err == nil && info.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(a.ReceiptsDir, 0700); err != nil { // #nosec G302 -- directories need the execute bit; 0700 is owner-only
			warnings = append(warnings, errReceiptsPerms)
		}
	}

	filename := fmt.Sprintf("%s-%s.json", txType, timestamp.Format("2006-01-02-150405"))
	path := filepath.Join(a.ReceiptsDir, filename)

	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return append(warnings, errMarshal)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		warnings = append(warnings, errReceipt)
	}
	return warnings
}

// appendLine appends a single line to the running log file, creating it
// owner-only (0600) if it doesn't exist.
func (a AuditLog) appendLine(line string) []error {
	f, err := os.OpenFile(a.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return []error{errLogFile}
	}
	defer f.Close()
	fmt.Fprintln(f, line)
	return nil
}
