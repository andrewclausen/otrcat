// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This file implements using an external command to provide a socket-like
// ReadWriter connection.

package main

import "io"
import "os"
import "os/exec"

type PipePair struct {
	io.ReadCloser
	io.WriteCloser
}

func startProxy(args []string) (cmd *exec.Cmd, stdio PipePair, err error) {
	cmd = exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	stdio = PipePair{out, in}
	err = cmd.Run()
	return
}

// TODO: should we kill the cmd?
func closeProxy(cmd *exec.Cmd, stdio PipePair) {
	stdio.ReadCloser.Close()
	stdio.WriteCloser.Close()
}
