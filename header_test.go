package crypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestHeaderSize(t *testing.T) {
	if got := binary.Size(header{}); got != headerSize {
		t.Errorf("binary.Size(header{}) = %d, want %d", got, headerSize)
	}
}

func TestHeaderMarshal(t *testing.T) {
	salt := [saltSize]byte{0: 0xaa, saltSize - 1: 0xbb}
	got := newHeader(Params{Time: 0x01020304, Memory: 0x05060708, Threads: 0x09}, salt).marshal()
	want := []byte("crypt\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbb")
	if !bytes.Equal(got, want) {
		t.Errorf("marshal() = %q, want %q", got, want)
	}
}

func FuzzHeader(f *testing.F) {
	f.Add(newHeader(DefaultParams, [saltSize]byte{}).marshal())
	f.Add(newHeader(LowMemoryParams, [saltSize]byte{1}).marshal())
	f.Add([]byte("crypt"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := parseHeader(b)
		if err != nil {
			if !errors.Is(err, ErrFormat) && !errors.Is(err, ErrVersion) && !errors.Is(err, ErrParams) {
				t.Fatalf("parseHeader() error = %v, want ErrFormat, ErrVersion, or ErrParams", err)
			}
			return
		}
		if got := h.marshal(); !bytes.Equal(got, b[:headerSize]) {
			t.Errorf("marshal(parseHeader(b)) = %x, want %x", got, b[:headerSize])
		}
	})
}
