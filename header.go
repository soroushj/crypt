package crypt

import (
	"encoding/binary"
	"fmt"
)

const (
	magic      = "crypt"
	version    = 1
	saltSize   = 16 // 128 bits, as recommended by RFC 9106, Section 4
	headerSize = 31
)

// header is the header of an encrypted stream. Its fields are laid out in
// wire order, so it can be encoded and decoded by [encoding/binary].
type header struct {
	Magic   [len(magic)]byte
	Version uint8
	Params  Params
	Salt    [saltSize]byte
}

// newHeader returns the header of a new stream with params and salt.
func newHeader(params Params, salt [saltSize]byte) *header {
	return &header{
		Magic:   [len(magic)]byte([]byte(magic)),
		Version: version,
		Params:  params,
		Salt:    salt,
	}
}

// marshal returns the wire encoding of h.
func (h *header) marshal() []byte {
	b, err := binary.Append(make([]byte, 0, headerSize), binary.BigEndian, h)
	if err != nil {
		panic(err) // header has a fixed size
	}
	return b
}

// parseHeader parses and validates the header at the start of b.
func parseHeader(b []byte) (*header, error) {
	if len(b) < headerSize {
		return nil, ErrFormat
	}
	var h header
	if _, err := binary.Decode(b, binary.BigEndian, &h); err != nil {
		panic(err) // header has a fixed size, and b is large enough
	}
	if string(h.Magic[:]) != magic {
		return nil, ErrFormat
	}
	if h.Version != version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	if err := h.Params.validate(); err != nil {
		return nil, err
	}
	return &h, nil
}
