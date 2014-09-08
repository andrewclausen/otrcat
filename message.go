// Copyright (C) 2014 Andrew Clausen
// This program may be distributed under the BSD-style licence that Go is
// released under; see https://golang.org/LICENSE.
//
// This OTR protocol is designed to work with instant messenger protocols, in
// which messages are delivered one-by-one.  However, otrcat uses TCP to
// deliver messages, which combines and splits packets in an ad hoc way.  Our
// solution is to delimit messages using new-lines, which works because OTR
// encodes messages using Base64.  Newlines are unobtrusive, so this shouldn't
// cause compatibility problems.

package main

import (
	"bytes"
	"errors"
	"io"
)

type MessageEncoder interface {
	Encode([]byte) error
}

type MessageDecoder interface {
	Decode() ([]byte, error)
}

type VanillaEncoder struct {
	Writer io.Writer
}

type VanillaDecoder struct {
	Reader io.Reader
}

type DelimitedEncoder struct {
	Writer    io.Writer
	delimiter []byte
}

type DelimitedDecoder struct {
	Reader    io.Reader
	delimiter []byte
	queue     []byte
}

func NewVanillaEncoder(writer io.Writer) *VanillaEncoder {
	return &VanillaEncoder{writer}
}

func NewVanillaDecoder(reader io.Reader) *VanillaDecoder {
	return &VanillaDecoder{reader}
}

func NewDelimitedEncoder(writer io.Writer, delimiter []byte) *DelimitedEncoder {
	return &DelimitedEncoder{writer, delimiter}
}

func NewDelimitedDecoder(reader io.Reader, delimiter []byte) *DelimitedDecoder {
	return &DelimitedDecoder{reader, delimiter, []byte{}}
}

func (e *VanillaEncoder) Encode(data []byte) (err error) {
	_, err = e.Writer.Write(data)
	return
}

func (e *VanillaDecoder) Decode() ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := e.Reader.Read(buf)
	return buf[:n], err
}

func (e *DelimitedEncoder) Encode(data []byte) (err error) {
	_, err = e.Writer.Write(append(data, e.delimiter...))
	return
}

func (d *DelimitedDecoder) Decode() (buf []byte, err error) {
	var n int
	for {
		n = bytes.Index(d.queue, d.delimiter)
		if n != -1 {
			break
		}
		input := make([]byte, 4096)
		n, err = d.Reader.Read(input)
		if err != nil {
			if err == io.EOF && len(d.queue) > 0 {
				return nil, errors.New("Stream closed mid-message")
			}
			return
		}
		d.queue = append(d.queue, input[:n]...)
	}

	buf = d.queue[:n]
	m := n + len(d.delimiter)
	if len(d.queue) == m {
		d.queue = []byte{}
	} else {
		d.queue = d.queue[m:]
	}
	return
}

func EncodeForever(e MessageEncoder, ch chan []byte) {
	for {
		msg, open := <-ch
		if !open {
			return
		}
		if msg == nil {
			return
		}
		if err := e.Encode(msg); err != nil {
			exitError(err)
		}
	}
}

func DecodeForever(d MessageDecoder, ch chan []byte) {
	for {
		buf, err := d.Decode()
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
