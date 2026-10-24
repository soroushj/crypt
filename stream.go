package crypt

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

const chunkSize = 64 << 10

var errClosed = errors.New("write to closed Writer")

// nonce is a STREAM nonce: an 11-byte big-endian chunk counter followed by a
// last-chunk flag.
type nonce [12]byte

// next advances n to the next chunk.
func (n *nonce) next() {
	for i := len(n) - 2; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
	panic("crypt: chunk counter overflow") // after 2^88 chunks
}

// first reports whether n is the nonce of the first chunk.
func (n *nonce) first() bool {
	return [11]byte(n[:11]) == [11]byte{}
}

// setLast marks n as the nonce of the last chunk.
func (n *nonce) setLast() {
	n[len(n)-1] = 1
}

// Writer is an [io.WriteCloser] that encrypts data written to it.
type Writer struct {
	w         io.Writer
	aead      cipher.AEAD
	nonce     nonce
	chunkSize int
	buf       []byte // plaintext of the pending chunk, with room for its tag
	err       error  // sticky
}

var _ io.WriteCloser = (*Writer)(nil)

func newWriter(w io.Writer, aead cipher.AEAD, chunkSize int) *Writer {
	return &Writer{
		w:         w,
		aead:      aead,
		chunkSize: chunkSize,
		buf:       make([]byte, 0, chunkSize+aead.Overhead()),
	}
}

// Write encrypts p and writes it to the underlying writer, one chunk at a
// time. Data is buffered until a full chunk is available, and more data
// shows that it is not the last chunk, so callers must call [Writer.Close]
// to flush the last chunk.
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	for len(p) > 0 {
		if len(w.buf) == w.chunkSize {
			if err := w.seal(false); err != nil {
				return n, err
			}
		}
		m := copy(w.buf[len(w.buf):w.chunkSize], p)
		w.buf = w.buf[:len(w.buf)+m]
		n += m
		p = p[m:]
	}
	return n, nil
}

// Close encrypts and writes the last chunk. It does not close the underlying
// writer. Closing a closed Writer has no effect.
func (w *Writer) Close() error {
	if w.err == errClosed {
		return nil
	}
	if w.err != nil {
		return w.err
	}
	if err := w.seal(true); err != nil {
		return err
	}
	w.err = errClosed
	return nil
}

// seal encrypts the pending chunk in place and writes it out.
func (w *Writer) seal(last bool) error {
	if last {
		w.nonce.setLast()
	}
	chunk := w.aead.Seal(w.buf[:0], w.nonce[:], w.buf, nil)
	w.nonce.next()
	if _, err := w.w.Write(chunk); err != nil {
		w.err = err
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

// Reader is an [io.Reader] that decrypts data read from an underlying reader.
type Reader struct {
	r         io.Reader
	aead      cipher.AEAD
	nonce     nonce
	chunkSize int
	buf       []byte // ciphertext of a full chunk, plus one byte of lookahead
	ahead     bool   // whether the lookahead byte is at the end of buf
	plain     []byte // unread plaintext, which aliases buf
	err       error  // sticky; io.EOF after the last chunk
}

var _ io.Reader = (*Reader)(nil)

func newReader(r io.Reader, aead cipher.AEAD, chunkSize int) *Reader {
	return &Reader{
		r:         r,
		aead:      aead,
		chunkSize: chunkSize,
		buf:       make([]byte, chunkSize+aead.Overhead()+1),
	}
}

// Read reads and decrypts data from the underlying reader. Data is returned
// only after its chunk is authenticated, but the stream is known to be
// complete only once Read returns [io.EOF].
func (r *Reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.plain, r.err = r.open()
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// open reads, authenticates, and decrypts the next chunk in place. It returns
// io.EOF along with the plaintext of the last chunk.
func (r *Reader) open() ([]byte, error) {
	// A chunk is the last one if no data follows it, so read one byte past
	// a full chunk to find out.
	full := len(r.buf) - 1
	start := 0
	if r.ahead {
		r.buf[0] = r.buf[full]
		start = 1
	}
	n, err := io.ReadFull(r.r, r.buf[start:])
	n += start
	last := false
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		last = true
	case err != nil:
		return nil, err
	}
	r.ahead = !last
	chunk := r.buf[:min(n, full)]
	if len(chunk) < r.aead.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	if last {
		r.nonce.setLast()
	}
	plain, err := r.aead.Open(chunk[:0], r.nonce[:], chunk, nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	if last && len(plain) == 0 && !r.nonce.first() {
		return nil, fmt.Errorf("%w: empty last chunk", ErrFormat)
	}
	r.nonce.next()
	if last {
		return plain, io.EOF
	}
	return plain, nil
}
