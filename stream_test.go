package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"
)

func testAEAD(tb testing.TB) cipher.AEAD {
	tb.Helper()
	block, err := aes.NewCipher(make([]byte, keySize))
	if err != nil {
		tb.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		tb.Fatal(err)
	}
	return aead
}

func encryptStream(tb testing.TB, plain []byte, chunkSize int) []byte {
	tb.Helper()
	var b bytes.Buffer
	w := newWriter(&b, testAEAD(tb), chunkSize)
	if _, err := w.Write(plain); err != nil {
		tb.Fatal(err)
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	return b.Bytes()
}

func TestNonce(t *testing.T) {
	var n nonce
	if !n.first() {
		t.Error("zero nonce is not first")
	}
	for range 256 {
		n.next()
	}
	if want := (nonce{9: 1}); n != want {
		t.Errorf("nonce after 256 chunks = %x, want %x", n, want)
	}
	if n.first() {
		t.Error("nonce after 256 chunks is first")
	}
	n.setLast()
	if want := (nonce{9: 1, 11: 1}); n != want {
		t.Errorf("last nonce after 256 chunks = %x, want %x", n, want)
	}
}

func TestNonceOverflow(t *testing.T) {
	var n nonce
	for i := range 11 {
		n[i] = 0xff
	}
	defer func() {
		if recover() == nil {
			t.Error("next() did not panic on counter overflow")
		}
	}()
	n.next()
}

func TestEmptyLastChunk(t *testing.T) {
	// A full chunk followed by an empty last chunk is authentic but not
	// canonical, and Writer never produces it.
	const chunkSize = 16
	aead := testAEAD(t)
	var n nonce
	ct := aead.Seal(nil, n[:], make([]byte, chunkSize), nil)
	n.next()
	n.setLast()
	ct = aead.Seal(ct, n[:], nil, nil)
	_, err := io.ReadAll(newReader(bytes.NewReader(ct), aead, chunkSize))
	if !errors.Is(err, ErrFormat) {
		t.Errorf("ReadAll() error = %v, want ErrFormat", err)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte(nil), uint8(16), uint8(1), uint8(1))
	f.Add([]byte("hello, world"), uint8(4), uint8(3), uint8(5))
	f.Add(bytes.Repeat([]byte{0xa5}, 100), uint8(16), uint8(16), uint8(16))
	f.Fuzz(func(t *testing.T, plain []byte, chunkSize, writeSize, readSize uint8) {
		cs := int(chunkSize%64) + 1
		ws, rs := int(writeSize)+1, int(readSize)+1
		aead := testAEAD(t)

		var ct bytes.Buffer
		w := newWriter(&ct, aead, cs)
		for p := plain; len(p) > 0; {
			n, err := w.Write(p[:min(ws, len(p))])
			if err != nil {
				t.Fatal(err)
			}
			p = p[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		chunks := max(1, (len(plain)+cs-1)/cs)
		if want := len(plain) + chunks*aead.Overhead(); ct.Len() != want {
			t.Fatalf("ciphertext size = %d, want %d", ct.Len(), want)
		}

		r := newReader(&ct, aead, cs)
		var got []byte
		buf := make([]byte, rs)
		for {
			n, err := r.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("decrypted %x, want %x", got, plain)
		}
	})
}

func FuzzReader(f *testing.F) {
	const chunkSize = 16
	for _, n := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize} {
		f.Add(encryptStream(f, make([]byte, n), chunkSize))
	}
	f.Fuzz(func(t *testing.T, ct []byte) {
		plain, err := io.ReadAll(newReader(bytes.NewReader(ct), testAEAD(t), chunkSize))
		if err != nil {
			return
		}
		// The encoding is canonical: there is only one ciphertext for each
		// plaintext under a given key.
		if got := encryptStream(t, plain, chunkSize); !bytes.Equal(got, ct) {
			t.Errorf("accepted non-canonical ciphertext %x, want %x", ct, got)
		}
	})
}
