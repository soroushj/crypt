package crypt_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/cryptotest"
	"testing/iotest"

	"github.com/soroushj/crypt"
)

var update = flag.Bool("update", false, "update golden files")

const (
	tagSize       = 16
	encChunkSize  = crypt.ChunkSize + tagSize
	multiChunkLen = 2*crypt.ChunkSize + 100
)

// testParams are the cheapest valid parameters.
var testParams = crypt.Params{Time: 1, Memory: 8, Threads: 1}

var password = []byte("correct horse battery staple")

// randomBytes returns n deterministic pseudorandom bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.NewChaCha8([32]byte{}).Read(b)
	return b
}

func encrypt(t *testing.T, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := crypt.NewWriter(&b, password, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// decrypt returns the data decrypted before an error, if any.
func decrypt(enc, password []byte) ([]byte, error) {
	r, err := crypt.NewReader(bytes.NewReader(enc), password)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, crypt.ChunkSize - 1, crypt.ChunkSize, crypt.ChunkSize + 1, 3*crypt.ChunkSize + 7} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			plain := randomBytes(n)
			enc := encrypt(t, plain)
			chunks := max(1, (n+crypt.ChunkSize-1)/crypt.ChunkSize)
			if want := crypt.HeaderSize + n + chunks*tagSize; len(enc) != want {
				t.Errorf("encrypted size = %d, want %d", len(enc), want)
			}
			got, err := decrypt(enc, password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Error("decrypted data differs from plaintext")
			}
		})
	}
}

// TestGolden guards the format against accidental changes.
func TestGolden(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plain []byte
	}{
		{"empty", nil},
		{"short", []byte("Hello, world!\n")},
		{"chunks", randomBytes(crypt.ChunkSize + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cryptotest.SetGlobalRandom(t, 1)
			enc := encrypt(t, tc.plain)
			path := filepath.Join("testdata", tc.name+".crypt")
			if *update {
				if err := os.WriteFile(path, enc, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			golden, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(enc, golden) {
				t.Errorf("encrypted data differs from %s", path)
			}
			got, err := decrypt(golden, password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.plain) {
				t.Errorf("decrypted data of %s differs from plaintext", path)
			}
		})
	}
}

func TestDecryptErrors(t *testing.T) {
	plain := randomBytes(multiChunkLen)
	enc := encrypt(t, plain)
	header := enc[:crypt.HeaderSize]
	chunk := func(i int) []byte {
		start := crypt.HeaderSize + i*encChunkSize
		return enc[start:min(start+encChunkSize, len(enc))]
	}
	flip := func(i int) []byte {
		b := bytes.Clone(enc)
		b[i] ^= 1
		return b
	}
	for _, tc := range []struct {
		name     string
		enc      []byte
		password []byte
		want     error
	}{
		{"wrong password", enc, []byte("Tr0ub4dor&3"), crypt.ErrAuthentication},
		{"empty", nil, password, crypt.ErrFormat},
		{"truncated header", header[:crypt.HeaderSize-1], password, crypt.ErrFormat},
		{"magic", flip(0), password, crypt.ErrFormat},
		{"version", flip(5), password, crypt.ErrVersion},
		{"params out of bounds", flip(6), password, crypt.ErrParams},
		{"params in bounds", flip(13), password, crypt.ErrAuthentication},
		{"salt", flip(crypt.HeaderSize - 1), password, crypt.ErrAuthentication},
		{"first chunk", flip(crypt.HeaderSize), password, crypt.ErrAuthentication},
		{"last tag", flip(len(enc) - 1), password, crypt.ErrAuthentication},
		{"no chunks", header, password, io.ErrUnexpectedEOF},
		{"truncated tag", enc[:crypt.HeaderSize+tagSize-1], password, io.ErrUnexpectedEOF},
		{"truncated at chunk boundary", enc[:crypt.HeaderSize+encChunkSize], password, crypt.ErrAuthentication},
		{"truncated in chunk", enc[:crypt.HeaderSize+encChunkSize+100], password, crypt.ErrAuthentication},
		{"dropped chunk", slices.Concat(header, chunk(0), chunk(2)), password, crypt.ErrAuthentication},
		{"swapped chunks", slices.Concat(header, chunk(1), chunk(0), chunk(2)), password, crypt.ErrAuthentication},
		{"appended byte", slices.Concat(enc, []byte{0}), password, crypt.ErrAuthentication},
		{"appended chunk", slices.Concat(enc, chunk(1)), password, crypt.ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decrypt(tc.enc, tc.password)
			if !errors.Is(err, tc.want) {
				t.Errorf("decrypt() error = %v, want %v", err, tc.want)
			}
			if !bytes.HasPrefix(plain, got) {
				t.Error("decrypt() released data that is not a prefix of the plaintext")
			}
		})
	}
}

func TestReader(t *testing.T) {
	plain := randomBytes(multiChunkLen)
	enc := encrypt(t, plain)
	r, err := crypt.NewReader(bytes.NewReader(enc), password)
	if err != nil {
		t.Fatal(err)
	}
	if err := iotest.TestReader(r, plain); err != nil {
		t.Error(err)
	}
}

func TestReaderShortReads(t *testing.T) {
	plain := randomBytes(multiChunkLen)
	enc := encrypt(t, plain)
	for name, src := range map[string]io.Reader{
		"OneByteReader": iotest.OneByteReader(bytes.NewReader(enc)),
		"HalfReader":    iotest.HalfReader(bytes.NewReader(enc)),
		"DataErrReader": iotest.DataErrReader(bytes.NewReader(enc)),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := crypt.NewReader(src, password)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Error("decrypted data differs from plaintext")
			}
		})
	}
}

func TestReaderErrors(t *testing.T) {
	errTest := errors.New("test")
	enc := encrypt(t, randomBytes(multiChunkLen))
	if _, err := crypt.NewReader(iotest.ErrReader(errTest), password); !errors.Is(err, errTest) {
		t.Errorf("NewReader() error = %v, want %v", err, errTest)
	}
	// TimeoutReader fails on its second read, after the header.
	r, err := crypt.NewReader(iotest.TimeoutReader(bytes.NewReader(enc)), password)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // the error is sticky
		if _, err := r.Read(make([]byte, 1)); !errors.Is(err, iotest.ErrTimeout) {
			t.Errorf("Read() error = %v, want %v", err, iotest.ErrTimeout)
		}
	}
}

// TestWriterSplits checks that the output does not depend on how the input
// is split into writes.
func TestWriterSplits(t *testing.T) {
	plain := randomBytes(multiChunkLen)
	cryptotest.SetGlobalRandom(t, 1)
	want := encrypt(t, plain)
	for name, write := range map[string]func(io.Writer) error{
		"bytes": func(w io.Writer) error {
			for i := range plain {
				if _, err := w.Write(plain[i : i+1]); err != nil {
					return err
				}
			}
			return nil
		},
		"chunks": func(w io.Writer) error {
			for c := range slices.Chunk(plain, crypt.ChunkSize) {
				if _, err := w.Write(c); err != nil {
					return err
				}
			}
			return nil
		},
		"HalfReader": func(w io.Writer) error {
			_, err := io.Copy(w, iotest.HalfReader(bytes.NewReader(plain)))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			cryptotest.SetGlobalRandom(t, 1)
			var b bytes.Buffer
			w, err := crypt.NewWriter(&b, password, testParams)
			if err != nil {
				t.Fatal(err)
			}
			if err := write(w); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b.Bytes(), want) {
				t.Error("encrypted data differs from that of a single write")
			}
		})
	}
}

// failWriter fails after n bytes are written to it.
type failWriter struct {
	n   int
	err error
}

func (w *failWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, w.err
	}
	w.n -= len(p)
	return len(p), nil
}

func TestWriterErrors(t *testing.T) {
	errTest := errors.New("test")

	if _, err := crypt.NewWriter(&failWriter{0, errTest}, password, testParams); !errors.Is(err, errTest) {
		t.Errorf("NewWriter() error = %v, want %v", err, errTest)
	}

	w, err := crypt.NewWriter(&failWriter{crypt.HeaderSize, errTest}, password, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, crypt.ChunkSize+1)); !errors.Is(err, errTest) {
		t.Errorf("Write() error = %v, want %v", err, errTest)
	}
	if _, err := w.Write([]byte{0}); !errors.Is(err, errTest) {
		t.Errorf("Write() after error: error = %v, want %v", err, errTest)
	}
	if err := w.Close(); !errors.Is(err, errTest) {
		t.Errorf("Close() after error: error = %v, want %v", err, errTest)
	}

	w, err = crypt.NewWriter(&failWriter{crypt.HeaderSize, errTest}, password, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, errTest) {
		t.Errorf("Close() error = %v, want %v", err, errTest)
	}

	w, err = crypt.NewWriter(io.Discard, password, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
	if _, err := w.Write([]byte{0}); err == nil {
		t.Error("Write() after Close() succeeded")
	}
}

func TestParams(t *testing.T) {
	for _, p := range []crypt.Params{
		{Time: 0, Memory: 8, Threads: 1},
		{Time: crypt.MaxTime + 1, Memory: 8, Threads: 1},
		{Time: 1, Memory: 8, Threads: 0},
		{Time: 1, Memory: 7, Threads: 1},
		{Time: 1, Memory: 31, Threads: 4},
		{Time: 1, Memory: crypt.MaxMemory + 1, Threads: 1},
	} {
		if _, err := crypt.NewWriter(io.Discard, password, p); !errors.Is(err, crypt.ErrParams) {
			t.Errorf("NewWriter(%+v) error = %v, want ErrParams", p, err)
		}
	}
}

// TestPresets checks the presets against RFC 9106, Section 4.
func TestPresets(t *testing.T) {
	if want := (crypt.Params{Time: 1, Memory: 2 << 20, Threads: 4}); crypt.DefaultParams != want {
		t.Errorf("DefaultParams = %+v, want %+v", crypt.DefaultParams, want)
	}
	if want := (crypt.Params{Time: 3, Memory: 64 << 10, Threads: 4}); crypt.LowMemoryParams != want {
		t.Errorf("LowMemoryParams = %+v, want %+v", crypt.LowMemoryParams, want)
	}
}
