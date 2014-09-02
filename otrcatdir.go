// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// The code here manages the otrcat directory (~/.otrcat by default), which
// contains the private key (id.priv by default) and the contacts list
// (contacts by default).

package main

import (
	"code.google.com/p/go.crypto/otr"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// Establishes that the otrcat directory exists.  If it doesn't, then either
// fix it or complain about it.
func establishDir(fix bool) {
	if _, err := os.Lstat(dir); err == nil {
		return
	}
	if !fix {
		exitPrintf("The otrcat directory (%s) does not exist.\n", dir)
	}
	fmt.Fprintf(os.Stderr, "Creating the otrcat directory: %s\n", dir)
	if err := os.Mkdir(dir, 0700); err != nil {
		exitError(err)
	}
}

// Loads and parses a private key.
func loadKey(path string) *otr.PrivateKey {
	establishDir(false)
	base64Key, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		exitPrintf("The private key (%s) does not exist.  Please use genkey.\n",
			path)
	}
	if err != nil {
		exitError(err)
	}

	rawKey := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(rawKey, base64Key)
	if err != nil {
		exitError(err)
	}

	key := new(otr.PrivateKey)
	if _, ok := key.Parse(rawKey[:n]); !ok {
		exitPrintf("Invalid or corrupted private key (%s).\n", path)
	}

	return key
}

func saveKey(path string, key *otr.PrivateKey) {
	var rawKey []byte

	establishDir(true)
	rawKey = key.Serialize(rawKey)
	base64Key := make([]byte, base64.StdEncoding.EncodedLen(len(rawKey)))
	base64.StdEncoding.Encode(base64Key, rawKey)
	if err := ioutil.WriteFile(path, base64Key, 0600); err != nil {
		exitError(err)
	}
}

// Saves the contact list, i.e. known contacts' names and fingerprints
func saveContacts(path string) {
	establishDir(true)
	file, err := os.Create(path)
	if err != nil {
		exitError(err)
	}
	for name, fingerprint := range contacts {
		if name == "me" {
			continue
		}
		if _, err := fmt.Fprintf(file, "%-20s %x\n", name, fingerprint); err != nil {
			exitError(err)
		}
	}
	if err = file.Close(); err != nil {
		exitError(err)
	}
}

// Loads the contact list, i.e. known contacts' names and fingerprints
func loadContacts(path string) {
	establishDir(false)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr,
			"Creating a new contacts file (%s).\n", path)
		saveContacts(path)
		return
	}
	for {
		var name, fingerprint string

		n, err := fmt.Fscanf(file, "%s %x", &name, &fingerprint)
		if err == io.EOF {
			break
		}
		if err != nil {
			exitError(err)
		}
		if n < 2 {
			break
		}
		contacts[name] = string(fingerprint)
		contactsReverse[string(fingerprint)] = name
	}
	if err := file.Close(); err != nil {
		exitError(err)
	}
}
