package crypt

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkKeyDerivation(b *testing.B) {
	for _, bc := range []struct {
		name   string
		params Params
	}{
		{"Default", DefaultParams},
		{"LowMemory", LowMemoryParams},
	} {
		b.Run(bc.name, func(b *testing.B) {
			var salt [saltSize]byte
			rawHeader := newHeader(bc.params, salt).marshal()
			for b.Loop() {
				if _, err := newAEAD([]byte("password"), bc.params, salt[:], rawHeader); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWriter(b *testing.B) {
	plain := make([]byte, 1<<20)
	aead := testAEAD(b)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	for b.Loop() {
		w := newWriter(io.Discard, aead, chunkSize)
		if _, err := w.Write(plain); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReader(b *testing.B) {
	plain := make([]byte, 1<<20)
	ct := encryptStream(b, plain, chunkSize)
	aead := testAEAD(b)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	for b.Loop() {
		r := newReader(bytes.NewReader(ct), aead, chunkSize)
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
	}
}
