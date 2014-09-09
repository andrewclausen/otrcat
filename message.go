// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This OTR protocol is designed to work with instant messenger protocols, in
// which messages are delivered one-by-one.  However, otrcat uses TCP to
// deliver messages, which combines and splits packets in an ad hoc way.  Our
// solution is to delimit messages using new-lines.  Newlines are unobtrusive,
// (especially since OTR messages are base64-sendd), so this shouldn't cause
// compatibility problems.

package main

import (
	"bytes"
	"errors"
	"io"
)

type MessageSender interface {
	Send([]byte) error
}

type MessageReceiver interface {
	Receive() ([]byte, error)
}

type DelimitedSender struct {
	Writer    io.Writer
	delimiter []byte
}

type DelimitedReceiver struct {
	Reader    io.Reader
	delimiter []byte
	queue     []byte
}

func NewDelimitedSender(writer io.Writer, delimiter []byte) *DelimitedSender {
	return &DelimitedSender{writer, delimiter}
}

func NewDelimitedReceiver(reader io.Reader, delimiter []byte) *DelimitedReceiver {
	return &DelimitedReceiver{reader, delimiter, []byte{}}
}

func (s *DelimitedSender) Send(data []byte) (err error) {
	_, err = s.Writer.Write(append(data, s.delimiter...))
	return
}

func (r *DelimitedReceiver) Receive() (buf []byte, err error) {
	var k, n int
	for {
		n = bytes.Index(r.queue, r.delimiter)
		if n != -1 {
			break
		}
		input := make([]byte, 4096)
		k, err = r.Reader.Read(input)
		if err != nil {
			if err == io.EOF && len(r.queue) > 0 {
				return nil, errors.New("Stream closed mid-message")
			}
			return
		}
		r.queue = append(r.queue, input[:k]...)
	}

	buf = r.queue[:n]
	m := n + len(r.delimiter)
	if len(r.queue) == m {
		r.queue = []byte{}
	} else {
		r.queue = r.queue[m:]
	}
	return
}

func SendForever(s MessageSender, ch chan []byte) {
	for {
		msg, open := <-ch
		if !open || msg == nil {
			return
		}
		if err := s.Send(msg); err != nil {
			exitError(err)
		}
	}
}

func ReceiveForever(r MessageReceiver, ch chan []byte) {
	for {
		buf, err := r.Receive()
		if err == io.EOF {
			close(ch)
			return
		}
		if err != nil {
			exitError(err)
		}
		ch <- buf
	}
}
