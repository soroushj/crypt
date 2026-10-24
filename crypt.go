package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"runtime/debug"

	"golang.org/x/crypto/argon2"
)

// keySize is the size of both the Argon2 tag and the AES key: 256 bits, as
// recommended by RFC 9106, Section 4.
const keySize = 32

var (
	// ErrFormat is returned when the input is not an encrypted stream.
	ErrFormat = errors.New("not an encrypted stream")

	// ErrVersion is returned when the input is an encrypted stream of an
	// unsupported version.
	ErrVersion = errors.New("unsupported format version")

	// ErrParams is returned when the Argon2 parameters are out of bounds.
	ErrParams = errors.New("invalid parameters")

	// ErrAuthentication is returned when a chunk fails authentication,
	// meaning that either the password is wrong, or the stream is corrupt.
	// The two cases are indistinguishable by design.
	ErrAuthentication = errors.New("wrong password or corrupt data")
)

// NewWriter writes a header to w and returns a [Writer] that encrypts data
// with a key derived from password with params. The caller must call
// [Writer.Close] when done writing.
//
// Key derivation allocates params.Memory KiB, and calls
// [debug.FreeOSMemory] to release it. Callers may clear password once
// NewWriter returns.
func NewWriter(w io.Writer, password []byte, params Params) (*Writer, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	var salt [saltSize]byte
	rand.Read(salt[:]) // never fails
	raw := newHeader(params, salt).marshal()
	aead, err := newAEAD(password, params, salt[:], raw)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	return newWriter(w, aead, chunkSize), nil
}

// NewReader reads a header from r and returns a [Reader] that decrypts data
// with a key derived from password with the parameters in the header.
//
// Key derivation allocates as much memory as the header specifies, up to
// [MaxMemory] KiB, and calls [debug.FreeOSMemory] to release it. Callers may
// clear password once NewReader returns.
func NewReader(r io.Reader, password []byte) (*Reader, error) {
	raw := make([]byte, headerSize)
	if _, err := io.ReadFull(r, raw); err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, ErrFormat
	} else if err != nil {
		return nil, err
	}
	h, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(password, h.Params, h.Salt[:], raw)
	if err != nil {
		return nil, err
	}
	return newReader(r, aead, chunkSize), nil
}

// newAEAD derives the key of a stream with the given raw header, and returns
// an AES-256-GCM AEAD with that key.
func newAEAD(password []byte, params Params, salt, header []byte) (cipher.AEAD, error) {
	tag := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, keySize)
	// Argon2's memory is garbage now, but the GC sized its next cycle after
	// it, so it would stay resident for as long as the stream is processed.
	// Release it now. On Linux, this also wipes the Argon2 state, which is
	// otherwise out of reach.
	debug.FreeOSMemory()
	defer clear(tag)
	key, err := hkdf.Expand(sha256.New, tag, string(header), keySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
