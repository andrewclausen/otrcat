// "otrcat" is a general purpose communication tool using the Off-The-Record
// protocol.
//
// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.

package main

import (
	"code.google.com/p/go.crypto/otr"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

// TODO: figure out a good default port
const OTRPort = ":2147"

type Command struct {
	call  func()
	name  string
	desc  string
	args  []string
	flags *flag.FlagSet
}

var (
	// Communication state that changes throughout the course of the conversation
	conv             otr.Conversation
	theirFingerprint string = ""

	// Contacts, loaded by default from ~/.otrcat/contacts
	contacts        map[string]string = make(map[string]string) // name -> fingerprint
	contactsReverse map[string]string = make(map[string]string) // fingerprint -> name

	// Things parsed from command-line arguments
	cmd            *Command
	args           []string // Non-flag arguments
	dir            string
	privateKeyPath string
	contactsPath   string
	address        string = OTRPort
	anyone         bool
	remember       string
	expect         string
	execCommand    string

	cmds []Command // Commands (effectively a constant)
)

// Command-line flags
func dirFlag(f *flag.FlagSet) {
	f.StringVar(&dir, "dir", "$HOME/.otrcat",
		"where keys and contacts are stored")
}

func keyFileFlag(f *flag.FlagSet) {
	f.StringVar(&privateKeyPath, "key", "", "the private key file")
}

func contactsFileFlag(f *flag.FlagSet) {
	f.StringVar(&contactsPath, "contacts", "", "the contacts file")
}

func anyoneFlag(f *flag.FlagSet) {
	f.BoolVar(&anyone, "anyone", false, "converse with anyone, not just known contacts")
}

func rememberFlag(f *flag.FlagSet) {
	f.StringVar(&remember, "remember", "", "name to remember the contact by; implies -anyone")
}

func expectFlag(f *flag.FlagSet) {
	f.StringVar(&expect, "expect", "", "contact to expect; abort if it's someone else")
}

func execFlag(f *flag.FlagSet) {
	f.StringVar(&execCommand, "exec", "", "shell command to execute with sh(1); the contact is $1")
}

// A flag.FlagSet constructor.
func flags(cmd string, flags ...func(*flag.FlagSet)) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	for _, flag := range flags {
		flag(fs)
	}
	return fs
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	os.Exit(1)
}

func exitPrintf(errFormat string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, errFormat, args...)
	os.Exit(1)
}

// Generates a new private key
func genkey() {
	// Key generation takes a long time, so it's polite to check the user's
	// request makes sense first.
	establishDir(true)
	if _, err := os.Lstat(privateKeyPath); err == nil {
		exitPrintf("Error: The private key file (%s) already exists.\n",
			privateKeyPath)
	}

	fmt.Fprintf(os.Stderr, "Generating a new private key (%s)...", privateKeyPath)
	privateKey := new(otr.PrivateKey)
	privateKey.Generate(rand.Reader)
	conv.PrivateKey = privateKey
	fmt.Fprintf(os.Stderr, "\n")

	saveKey(privateKeyPath, privateKey)
}

// Parses and checks the flags that are relevant for listen/connect/proxy.
// This uses the contacts information from ~/.otrcat
func parseConversationFlags() {
	if remember != "" {
		anyone = true
	}
	if expect != "" && remember != "" {
		exitPrintf("The -expect and -remember options are mutually exclusive.\n")
	}
	if anyone && expect != "" {
		exitPrintf("The -expect and -anyone options are mutually exclusive.\n")
	}
	if expect != "" {
		if _, known := contacts[expect]; !known {
			exitPrintf("Can't expect unknown contact '%s'.\n", expect)
		}
	}
	if remember != "" {
		if _, known := contacts[remember]; known {
			exitPrintf("Can't re-remember an already known contact '%s'.\n",
				remember)
		}
	}

	if cmd.name == "proxy" {
		return
	}

	if len(args) == 1 {
		address = args[0]
		if cmd.name == "listen" {
			if !strings.HasPrefix(address, ":") {
				exitPrintf("Can't listen on a remote address (%s).  "+
					"Specify a local port with ':port'.\n", address)
			}
		}
		if !strings.Contains(address, ":") {
			address += OTRPort
		}
	}
}

// Selects a private key for use in the conversation
func useKey(key *otr.PrivateKey) {
	conv.PrivateKey = key
	fingerprint := string(key.PublicKey.Fingerprint())
	if _, ok := contacts[fingerprint]; !ok {
		contacts["me"] = fingerprint
		contactsReverse[fingerprint] = "me"
	}
}

func connect() {
	useKey(loadKey(privateKeyPath))
	loadContacts(contactsPath)
	parseConversationFlags()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		exitError(err)
	}
	mainLoop(conn)
	conn.Close()
}

func listen() {
	useKey(loadKey(privateKeyPath))
	loadContacts(contactsPath)
	parseConversationFlags()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		exitError(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		exitError(err)
	}
	mainLoop(conn)
	conn.Close()
}

func proxy() {
	useKey(loadKey(privateKeyPath))
	loadContacts(contactsPath)
	parseConversationFlags()
	cmd, conn, err := startProxy(args)
	if err != nil {
		exitError(err)
	}
	mainLoop(conn)
	closeProxy(cmd, conn)
}

// Lists all known contacts (including "me")
func fingerprints() {
	useKey(loadKey(privateKeyPath))
	loadContacts(contactsPath)
	for name, fingerprint := range contacts {
		fmt.Printf("%-20s %x\n", name, fingerprint)
	}
}

func matchCommand(name string) *Command {
	for _, cmd := range cmds {
		if cmd.name == name {
			return &cmd
		}
	}
	return nil
}

func help() {
	if cmd != nil && cmd.name == "help" {
		if len(args) > 0 {
			cmd = matchCommand(args[0])
			if cmd != nil {
				helpCommand(cmd)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Usage:\n")
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "otrcat %-15s %s\n", cmd.name, cmd.desc)
	}
	os.Exit(1)
}

func helpCommand(cmd *Command) {
	fmt.Fprintf(os.Stderr, "Usage: otrcat %s", cmd.name)
	for _, arg := range cmd.args {
		fmt.Fprintf(os.Stderr, " %s", arg)
	}
	fmt.Fprintf(os.Stderr, " [options]\n")
	cmd.flags.PrintDefaults()
	os.Exit(1)
}

func main() {
	cmds = []Command{
		Command{connect, "connect", "start a conversation", []string{"[host][:port]"},
			flags("connect", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag, execFlag)},
		Command{fingerprints, "fingerprints", "show contacts' fingerprints", []string{},
			flags("fingerprints", dirFlag, keyFileFlag, contactsFileFlag)},
		Command{genkey, "genkey", "create a new private key", []string{},
			flags("genkey", dirFlag, keyFileFlag)},
		Command{help, "help", "help on each command", []string{"[command]"}, flags("help")},
		Command{listen, "listen", "wait for someone to start a conversation", []string{"[:port]"},
			flags("listen", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag, execFlag)},
		Command{proxy, "proxy", "connect with a proxy command", []string{"command", "[args]"},
			flags("proxy", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag, execFlag)},
	}
	if len(os.Args) < 2 {
		help()
	}
	cmd = matchCommand(os.Args[1])
	if cmd == nil {
		help()
	}
	cmd.flags.Parse(os.Args[2:])
	args = cmd.flags.Args()
	if cmd.name == "proxy" {
		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "'proxy' needs a command to be specified.\n")
			helpCommand(cmd)
		}
	} else {
		if len(args) > len(cmd.args) {
			fmt.Fprintf(os.Stderr, "%s only takes up to %d parameters.\n",
				cmd.name, len(cmd.name))
			helpCommand(cmd)
		}
	}
	dir = os.ExpandEnv(dir)
	if privateKeyPath == "" {
		privateKeyPath = dir + "/id.priv"
	}
	if contactsPath == "" {
		contactsPath = dir + "/contacts"
	}
	cmd.call()
}
