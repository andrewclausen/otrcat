// "otrcat" is a general purpose communication tool using the Off-The-Record
// protocol.
//
// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.

package main

import (
	"bytes"
	"code.google.com/p/go.crypto/otr"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
)

// TODO: figure out a good default port
const OTRPort = ":2147"

type Command struct {
	name  string
	desc  string
	flags *flag.FlagSet
	args  []string
	call  func()
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

// Checks if the contact is authorised, and remembers the contact if
// appropriate.  This is the only place these tasks are done, with the
// following exceptions:
// * "me" is included in the contact list
// * the main loop checks if the contact changed mid-conversation (which we
// forbid)
func authoriseRemember(fingerprint string) {
	name, known := contactsReverse[fingerprint]
	if expect != "" {
		if !known {
			exitPrintf("Expected contact '%s', but the contact is unknown.\n",
				expect)
		}
		if name != expect {
			exitPrintf("Expected contact '%s', but the contact is '%s'.\n",
				expect, name)
		}
		return // authorised
	}

	if !anyone && !known {
		exitPrintf("The contact is unknown.  " +
			"Use -anyone or -remember to talk to unknown contacts.\n")
	}

	if remember != "" && known {
		fmt.Fprintf(os.Stderr,
			"Warning: Expected an unknown contact, but the contact is known "+
				"as '%s'.\n",
			name)
	}

	if remember != "" && !known {
		fmt.Fprintf(os.Stderr, "Remembering contact '%s'.\n", remember)
		contacts[remember] = fingerprint
		contactsReverse[fingerprint] = remember
		saveContacts(contactsPath)
	}

	if remember == "" && known {
		fmt.Fprintf(os.Stderr, "The contact is '%s'.\n", name)
	}
}

// Turns a Reader into a channel of buffers
func readLoop(r io.Reader, ch chan []byte) {
	for {
		buf := make([]byte, 4096) // TODO: what's a good buffer size?
		n, err := r.Read(buf)
		if err == io.EOF {
			close(ch)
			return
		}
		if err != nil {
			exitError(err)
		}
		ch <- buf[:n]
	}
}

func writeLoop(w io.Writer, ch chan []byte) {
	for {
		buf, open := <-ch
		if !open {
			return
		}
		_, err := w.Write(buf)
		if err != nil {
			exitError(err)
		}
	}
}

// Listen for SIGTERM signals
func sigLoop(ch chan os.Signal) {
	listener := make(chan os.Signal)
	signal.Notify(listener, os.Interrupt)
	for {
		select {
		case sig := <-listener:
			ch <- sig
		}
	}
}

// The main loop.
// * The main job is to pass messages between standard input/output, the OTR
// library, the TCP socket, and the JSON encoder.
// * It starts goroutines that listen on standard input and the TCP socket.
// Note: it only starts listening on standard input when an encrypted
// connection has been established, to prevent any data being sent in plain
// text.
// * When an encrypted session has been established, it checks if the contact
// is authentication and authorised (according to -remember and -expect).
func mainLoop(upstream io.ReadWriter) {
	netOutChan := make(chan []byte, 100)
	netInChan := make(chan []byte, 100)
	stdOutChan := make(chan []byte, 100)
	stdInChan := make(chan []byte, 100)
	sigTermChan := make(chan os.Signal)

	// Encode everything (with JSON) before sending
	var nl = []byte("\n")
	msgSender, msgReceiver := NewDelimitedSender(upstream, nl), NewDelimitedReceiver(upstream, nl)

	go SendForever(msgSender, netOutChan)
	go ReceiveForever(msgReceiver, netInChan)
	go writeLoop(os.Stdout, stdOutChan)
	// Don't touch secret text until we are sure everything is encrypted and
	// authorised.
	// go readLoop(os.Stdin, stdInChan)
	go sigLoop(sigTermChan)

	send := func(toSend [][]byte) {
		for _, msg := range toSend {
			netOutChan <- msg
		}
	}

	stdInChan <- []byte(otr.QueryMessage) // Queue a handshake message to be sent

	authorised := false // conversation ready to send secret data?
Loop:
	for {
		select {
		case _ = <-sigTermChan:
			break Loop

		case plaintext, alive := <-stdInChan:
			if !alive {
				break Loop
			}
			if bytes.Index(plaintext, []byte{0}) != -1 {
				fmt.Fprintf(os.Stderr,
					"The OTR protocol only supports UTF8-encoded text.\n"+
						"Please use base64 or another suitable encoding for binary data.\n")
				break Loop
			}
			toSend, err := conv.Send(plaintext)
			if err != nil {
				exitError(err)
			}
			send(toSend)

		case otrText, alive := <-netInChan:
			if !alive {
				if authorised {
					exitPrintf("Connection dropped!  Recent messages might not be deniable.\n")
				}
				exitPrintf("Connection dropped!\n")
			}
			plaintext, encrypted, state, toSend, err := conv.Receive(otrText)
			if err != nil {
				exitError(err)
			}
			if state == otr.ConversationEnded {
				return
			}
			send(toSend)
			if conv.IsEncrypted() {
				fingerprint := string(conv.TheirPublicKey.Fingerprint())
				if authorised && theirFingerprint != fingerprint {
					exitPrintf("The contact changed mid-conversation.\n")
				}
				if !authorised {
					theirFingerprint = fingerprint
					authoriseRemember(fingerprint)
					authorised = true
					go readLoop(os.Stdin, stdInChan)
				}
			}
			if len(plaintext) > 0 {
				if !encrypted || !authorised {
					exitPrintf("Received unencrypted or unauthenticated text.\n")
				}
				stdOutChan <- plaintext
			}
		}
	}

	// We want to terminate the conversation.  To do this, we send the
	// termination messages, and wait for the other side to close the
	// connection.  It's important that these messages get through, for
	// deniability.
	toSend := conv.End()
	send(toSend)
	netOutChan <- nil
ShutdownLoop:
	for {
		select {
		case _, alive := <-netInChan:
			if !alive {
				break ShutdownLoop
			}
		}
	}
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
		Command{"connect", "start a conversation",
			flags("connect", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag),
			[]string{"[host][:port]"}, connect},
		Command{"fingerprints", "show contacts' fingerprints",
			flags("fingerprints", dirFlag, keyFileFlag, contactsFileFlag), []string{}, fingerprints},
		Command{"genkey", "create a new private key",
			flags("genkey", dirFlag, keyFileFlag), []string{}, genkey},
		Command{"help", "help on each command", flags("help"), []string{"[command]"}, help},
		Command{"listen", "wait for someone to start a conversation",
			flags("listen", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag),
			[]string{"[:port]"}, listen},
		Command{"proxy", "connect with a proxy command",
			flags("proxy", dirFlag, keyFileFlag, anyoneFlag, rememberFlag, contactsFileFlag, expectFlag),
			[]string{"command", "[args]"}, proxy},
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
