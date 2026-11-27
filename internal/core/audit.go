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
	"strings"
	"time"
)

// AuditLog records encrypt, decrypt and key-creation transactions to two
// places: a running one-line-per-transaction log file, and an individual
// JSON receipt per transaction in a receipts directory. No passphrases or
// key material are ever logged — only filenames, hashes, timestamps and
// nicknames.
//
// A log records file paths either in full (AbsolutePaths, used for the
// central log) or relative to the log's own folder (used for local logs,
// matching the 1.x format).
type AuditLog struct {
	LogFile       string // Path of the running human-readable log, e.g. age-tool.log
	ReceiptsDir   string // Directory for JSON receipts, e.g. logs/
	AbsolutePaths bool   // Record full paths rather than paths relative to the log
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

// displayPath returns how a file path is recorded in this log: the full
// path for a log with AbsolutePaths, otherwise the path relative to the
// log's folder (e.g. "report.pdf" for a file beside the log). A path that
// isn't inside the log's folder is recorded in full.
func (a AuditLog) displayPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if a.AbsolutePaths {
		return abs
	}
	logDir, err := filepath.Abs(filepath.Dir(a.LogFile))
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(logDir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return abs
	}
	return rel
}

// RecordEncrypt logs an encryption of srcFile to outFile with the public
// key keyFile. Both files are hashed; a hash that can't be computed is
// recorded as empty. Returns any logging problems as warnings.
func (a AuditLog) RecordEncrypt(timestamp time.Time, srcFile, outFile, keyFile, keyNickname string) []error {
	srcMD5, srcSHA256, _ := HashFile(srcFile)
	outMD5, outSHA256, _ := HashFile(outFile)
	srcFile, outFile = a.displayPath(srcFile), a.displayPath(outFile)

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
	srcFile, outFile = a.displayPath(srcFile), a.displayPath(outFile)

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

// RecordPasswordEncrypt logs an encryption of srcFile to outFile with a
// password. The receipt records the method ("password") in place of a key;
// the password itself is never logged. Returns any logging problems as
// warnings.
func (a AuditLog) RecordPasswordEncrypt(timestamp time.Time, srcFile, outFile string) []error {
	return a.recordPasswordTx(ActivityEncrypt, "ENCRYPT", timestamp, srcFile, outFile)
}

// RecordPasswordDecrypt logs a decryption of srcFile to outFile with a
// password. As for RecordPasswordEncrypt, the password is never logged.
func (a AuditLog) RecordPasswordDecrypt(timestamp time.Time, srcFile, outFile string) []error {
	return a.recordPasswordTx(ActivityDecrypt, "DECRYPT", timestamp, srcFile, outFile)
}

// recordPasswordTx writes the receipt and log line for a password
// encryption or decryption (txType "encrypt" or "decrypt").
func (a AuditLog) recordPasswordTx(txType, label string, timestamp time.Time, srcFile, outFile string) []error {
	srcMD5, srcSHA256, _ := HashFile(srcFile)
	outMD5, outSHA256, _ := HashFile(outFile)
	srcFile, outFile = a.displayPath(srcFile), a.displayPath(outFile)

	warnings := a.writeReceipt(txType, timestamp, map[string]string{
		"transaction":   txType,
		"timestamp":     timestamp.Format(time.RFC3339),
		"method":        MethodPassword,
		"source_file":   srcFile,
		"source_md5":    srcMD5,
		"source_sha256": srcSHA256,
		"output_file":   outFile,
		"output_md5":    outMD5,
		"output_sha256": outSHA256,
	})

	line := fmt.Sprintf("[%s] %s: %s -> %s | password | src-sha256: %s | out-sha256: %s",
		timestamp.Format("2006-01-02 15:04:05"), label, srcFile, outFile,
		ShortHash(srcSHA256), ShortHash(outSHA256))
	return append(warnings, a.appendLine(line)...)
}

// RecordKeyCreation logs the creation of key pair keyName (pubFile and
// privFile). Returns any logging problems as warnings.
func (a AuditLog) RecordKeyCreation(timestamp time.Time, keyName, pubFile, privFile string) []error {
	pubMD5, pubSHA256, _ := HashFile(pubFile)
	privMD5, privSHA256, _ := HashFile(privFile)
	pubFile, privFile = a.displayPath(pubFile), a.displayPath(privFile)

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

	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return append(warnings, errMarshal)
	}

	// Receipts are named to the second; if several transactions share a
	// second, number the later ones (-2, -3, ...) rather than overwrite.
	base := fmt.Sprintf("%s-%s", txType, timestamp.Format("2006-01-02-150405"))
	for n := 1; n <= 1000; n++ {
		name := base + ".json"
		if n > 1 {
			name = fmt.Sprintf("%s-%d.json", base, n)
		}
		err := writeNewFile(filepath.Join(a.ReceiptsDir, name), append(data, '\n'))
		if err == nil {
			return warnings
		}
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	return append(warnings, errReceipt)
}

// appendLine appends a single line to the running log file, creating it
// owner-only (0600) if it doesn't exist. A missing parent folder is created
// owner-only (0700); an existing folder's permissions are left alone, since
// a local log may sit in the user's own documents folder.
func (a AuditLog) appendLine(line string) []error {
	if err := os.MkdirAll(filepath.Dir(a.LogFile), 0700); err != nil {
		return []error{errLogFile}
	}
	f, err := os.OpenFile(filepath.Clean(a.LogFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return []error{errLogFile}
	}
	defer f.Close()
	fmt.Fprintln(f, line)
	return nil
}

// AuditLogs records each transaction to several audit logs, e.g. the
// central log and the local log beside the file.
type AuditLogs []AuditLog

// NewAuditLogs combines logs, dropping any that write to the same log file
// as an earlier one (e.g. when the local folder is the central folder).
func NewAuditLogs(logs ...AuditLog) AuditLogs {
	var result AuditLogs
	seen := map[string]bool{}
	for _, l := range logs {
		key, err := filepath.Abs(l.LogFile)
		if err != nil {
			key = l.LogFile
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, l)
		}
	}
	return result
}

// each runs record against every log and collects the warnings. When
// there is more than one log, each warning names the log it came from.
func (ls AuditLogs) each(record func(AuditLog) []error) []error {
	var warnings []error
	for _, l := range ls {
		for _, w := range record(l) {
			if len(ls) > 1 {
				w = fmt.Errorf("%w (%s)", w, filepath.Dir(l.LogFile))
			}
			warnings = append(warnings, w)
		}
	}
	return warnings
}

// RecordEncrypt logs an encryption to every log. See AuditLog.RecordEncrypt.
func (ls AuditLogs) RecordEncrypt(timestamp time.Time, srcFile, outFile, keyFile, keyNickname string) []error {
	return ls.each(func(l AuditLog) []error { return l.RecordEncrypt(timestamp, srcFile, outFile, keyFile, keyNickname) })
}

// RecordDecrypt logs a decryption to every log. See AuditLog.RecordDecrypt.
func (ls AuditLogs) RecordDecrypt(timestamp time.Time, srcFile, outFile, keyFile, keyNickname string) []error {
	return ls.each(func(l AuditLog) []error { return l.RecordDecrypt(timestamp, srcFile, outFile, keyFile, keyNickname) })
}

// RecordPasswordEncrypt logs a password encryption to every log. See
// AuditLog.RecordPasswordEncrypt.
func (ls AuditLogs) RecordPasswordEncrypt(timestamp time.Time, srcFile, outFile string) []error {
	return ls.each(func(l AuditLog) []error { return l.RecordPasswordEncrypt(timestamp, srcFile, outFile) })
}

// RecordPasswordDecrypt logs a password decryption to every log. See
// AuditLog.RecordPasswordDecrypt.
func (ls AuditLogs) RecordPasswordDecrypt(timestamp time.Time, srcFile, outFile string) []error {
	return ls.each(func(l AuditLog) []error { return l.RecordPasswordDecrypt(timestamp, srcFile, outFile) })
}

// RecordKeyCreation logs a key creation to every log. See
// AuditLog.RecordKeyCreation.
func (ls AuditLogs) RecordKeyCreation(timestamp time.Time, keyName, pubFile, privFile string) []error {
	return ls.each(func(l AuditLog) []error { return l.RecordKeyCreation(timestamp, keyName, pubFile, privFile) })
}
