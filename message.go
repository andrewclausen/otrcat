// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This OTR protocol is designed to work with instant messenger protocols, in
// which messages are delivered one-by-one.  However, otrcat uses TCP to
// deliver messages, which combines and splits packets in an ad hoc way.
// This file uses JSON to encode each OTR fragment, so that the TCP stream of
// bytes can be reassembled at the other end into a stream of OTR fragments.

package main

import (
	"encoding/json"
	"io"
)

type MessageEncoder struct {
	json.Encoder
}

type MessageDecoder struct {
	json.Decoder
}

func NewMessageEncoder(w io.Writer) *MessageEncoder {
	return &MessageEncoder{*json.NewEncoder(w)}
}

func NewMessageDecoder(r io.Reader) *MessageDecoder {
	return &MessageDecoder{*json.NewDecoder(r)}
}

func (e *MessageEncoder) EncodeMessages(msgs [][]byte) {
	for _, msg := range msgs {
		if err := e.Encode(msg); err != nil {
			exitError(err)
		}
	}
}

func (d *MessageDecoder) DecodeForever(ch chan []byte) {
	var buf []byte
	for {
		err := d.Decode(&buf)
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
