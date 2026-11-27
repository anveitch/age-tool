// Copyright (c) 2026 Andy Veitch
// Licensed under the MIT License. See LICENSE file for details.

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxReceiptSize bounds how much of a receipt file is read; real receipts
// are well under 1 KB.
const maxReceiptSize = 64 * 1024

// Activity types, as recorded in each receipt's "transaction" field.
const (
	ActivityEncrypt     = "encrypt"
	ActivityDecrypt     = "decrypt"
	ActivityKeyCreation = "key-creation"
)

// How an encrypt or decrypt transaction was done (ActivityEntry.Method).
const (
	MethodKey      = "key"      // With a key (receipts from before 2.1 have no method, and mean this)
	MethodPassword = "password" // With a password; no key is involved
)

// ActivityEntry is one transaction read back from an audit log's receipts,
// for display in an activity view. Which fields are set depends on Type.
type ActivityEntry struct {
	Type        string    // ActivityEncrypt, ActivityDecrypt or ActivityKeyCreation
	Time        time.Time // When the transaction happened
	Method      string    // Encrypt/decrypt: MethodKey or MethodPassword
	Source      string    // Encrypt/decrypt: the file that was read
	Output      string    // Encrypt/decrypt: the file that was written
	Key         string    // Encrypt/decrypt: the key file used
	KeyNickname string    // Encrypt/decrypt: the key's nickname at the time, if any
	KeyName     string    // Key creation: the new key pair's name
	PublicKey   string    // Key creation: the public key file
	PrivateKey  string    // Key creation: the private key file
}

// receipt is the JSON layout of a receipt file written by AuditLog.
type receipt struct {
	Transaction    string `json:"transaction"`
	Timestamp      string `json:"timestamp"`
	Method         string `json:"method"`
	SourceFile     string `json:"source_file"`
	OutputFile     string `json:"output_file"`
	PublicKey      string `json:"public_key"`
	PrivateKey     string `json:"private_key"`
	KeyNickname    string `json:"key_nickname"`
	KeyPairName    string `json:"key_pair_name"`
	PublicKeyFile  string `json:"public_key_file"`
	PrivateKeyFile string `json:"private_key_file"`
}

// ReadActivity reads the receipts in receiptsDir (e.g. the central log's
// receipts folder) and returns up to limit of the most recent
// transactions, newest first. A limit of 0 or less returns them all.
//
// A missing folder means no activity yet and is not an error. Receipts
// that can't be read or parsed are skipped and counted in skipped, so one
// damaged file doesn't hide the rest.
func ReadActivity(receiptsDir string, limit int) (entries []ActivityEntry, skipped int, err error) {
	files, err := ListFiles(receiptsDir, func(name string) bool { return strings.HasSuffix(name, ".json") })
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// Receipt timestamps are to the second, so also remember when each
	// receipt file was written, to order transactions within a second
	type dated struct {
		entry   ActivityEntry
		written time.Time
	}
	var all []dated
	for _, name := range files {
		path := filepath.Join(receiptsDir, name)
		entry, ok := readReceipt(path)
		if !ok {
			skipped++
			continue
		}
		var written time.Time
		if info, err := os.Stat(path); err == nil {
			written = info.ModTime()
		}
		all = append(all, dated{entry, written})
	}

	// Newest first, by recorded time and then by when the receipt was written
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].entry.Time.Equal(all[j].entry.Time) {
			return all[i].entry.Time.After(all[j].entry.Time)
		}
		return all[i].written.After(all[j].written)
	})

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	entries = make([]ActivityEntry, len(all))
	for i, d := range all {
		entries[i] = d.entry
	}
	return entries, skipped, nil
}

// readReceipt parses one receipt file. Returns false if it can't be read,
// isn't a receipt, or has an unknown transaction type or a bad timestamp.
func readReceipt(path string) (ActivityEntry, bool) {
	data, err := readLimited(path, maxReceiptSize)
	if err != nil {
		return ActivityEntry{}, false
	}
	var r receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return ActivityEntry{}, false
	}
	t, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return ActivityEntry{}, false
	}

	entry := ActivityEntry{Type: r.Transaction, Time: t}
	if r.Transaction == ActivityEncrypt || r.Transaction == ActivityDecrypt {
		entry.Method = MethodKey
		if r.Method == MethodPassword {
			entry.Method = MethodPassword
		}
	}
	switch r.Transaction {
	case ActivityEncrypt:
		entry.Source, entry.Output, entry.Key, entry.KeyNickname = r.SourceFile, r.OutputFile, r.PublicKey, r.KeyNickname
	case ActivityDecrypt:
		entry.Source, entry.Output, entry.Key, entry.KeyNickname = r.SourceFile, r.OutputFile, r.PrivateKey, r.KeyNickname
	case ActivityKeyCreation:
		entry.KeyName, entry.PublicKey, entry.PrivateKey = r.KeyPairName, r.PublicKeyFile, r.PrivateKeyFile
	default:
		return ActivityEntry{}, false
	}
	return entry, true
}
