// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This file contains mainLoop(), which forwards, encrypts and decrypts
// messages.  All authentication and authorisation logic is in here.

package main

import (
	"bytes"
	"code.google.com/p/go.crypto/otr"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
)

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

// Implements the -exec option, which runs a given command using /bin/sh, and
// connects the processes stdin/stdout to this side of the conversation
func StartCommand(theirFingerprint string) (io.Reader, io.Writer) {
	cmd := exec.Command("/bin/sh", "-c", execCommand, "--", contactsReverse[theirFingerprint])
	stdIn, err := cmd.StdinPipe()
	if err != nil {
		exitError(err)
	}
	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		exitError(err)
	}
	if err := cmd.Start(); err != nil {
		exitError(err)
	}
	return stdOut, stdIn
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
func mainLoop(privateKey otr.PrivateKey, upstream io.ReadWriter) {
	var conv otr.Conversation
	var theirFingerprint string = ""

	conv.PrivateKey = &privateKey

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
	// Don't touch secret input or output anything until we are sure everything
	// is encrypted and authorised.
	// go readLoop(os.Stdin, stdInChan)
	// go writeLoop(os.Stdout, stdOutChan)
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

					var w io.Writer
					var r io.Reader

					r, w = os.Stdout, os.Stdin
					if execCommand != "" {
						r, w = StartCommand(fingerprint)
					}
					go readLoop(r, stdInChan)
					go writeLoop(w, stdOutChan)
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
