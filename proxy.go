// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This file implements using an external command to provide a socket-like
// ReadWriter connection.

package main

import (
	"io"
	"os"
	"os/exec"
	"syscall"
)

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
	err = cmd.Start()
	if err != nil {
		return
	}
	// Give the proxy its own process group, so it doesn't receive our signals.
	syscall.Setpgid(cmd.Process.Pid, cmd.Process.Pid)
	return
}

func closeProxy(cmd *exec.Cmd, stdio PipePair) {
	stdio.ReadCloser.Close()
	if err := stdio.WriteCloser.Close(); err != nil {
		exitError(err)
	}
	if err := cmd.Wait(); err != nil {
		exitError(err)
	}
}
