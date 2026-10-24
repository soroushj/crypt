package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/soroushj/crypt"
)

var plain = []byte("Hello, world!\n")

func password(s string) func(bool) ([]byte, error) {
	return func(bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func checkFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s = %q, want %q", path, got, want)
	}
}

// checkDir checks that dir contains exactly the named files, so no temporary
// files are left behind.
func checkDir(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("files in %s = %q, want %q", dir, got, want)
	}
}

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		want    options
		wantErr bool
	}{
		{args: nil, want: options{}},
		{args: []string{"-d", "in"}, want: options{decrypt: true, input: "in"}},
		{args: []string{"-l", "-o", "out", "-"}, want: options{lowMemory: true, output: "out", input: "-"}},
		{args: []string{"--", "-d"}, want: options{input: "-d"}},
		{args: []string{"-V"}, want: options{version: true}},
		{args: []string{"in", "-d"}, wantErr: true},
		{args: []string{"-d", "-l"}, wantErr: true},
		{args: []string{"-x"}, wantErr: true},
		{args: []string{"-o"}, wantErr: true},
	} {
		got, err := parseArgs(tc.args, io.Discard)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseArgs(%q) succeeded, want error", tc.args)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseArgs(%q) = %+v, %v, want %+v, nil", tc.args, got, err, tc.want)
		}
	}
	if _, err := parseArgs([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("parseArgs(-h) error = %v, want flag.ErrHelp", err)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in, enc, dec := filepath.Join(dir, "in"), filepath.Join(dir, "enc"), filepath.Join(dir, "dec")
	writeFile(t, in, plain)
	if err := run(options{lowMemory: true, input: in, output: enc}, nil, nil, password("pw")); err != nil {
		t.Fatal(err)
	}
	if err := run(options{decrypt: true, input: enc, output: dec}, nil, nil, password("pw")); err != nil {
		t.Fatal(err)
	}
	checkFile(t, dec, plain)
	for _, path := range []string{enc, dec} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("mode of %s = %v, want %v", path, got, os.FileMode(0o600))
		}
	}
	checkDir(t, dir, "in", "enc", "dec")
}

func TestInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	writeFile(t, path, plain)
	if err := run(options{lowMemory: true, input: path, output: path}, nil, nil, password("pw")); err != nil {
		t.Fatal(err)
	}
	if err := run(options{decrypt: true, input: path, output: path}, nil, nil, password("pw")); err != nil {
		t.Fatal(err)
	}
	checkFile(t, path, plain)
	checkDir(t, dir, "file")
}

func TestStdio(t *testing.T) {
	dir := t.TempDir()
	in, enc, dec := filepath.Join(dir, "in"), filepath.Join(dir, "enc"), filepath.Join(dir, "dec")
	writeFile(t, in, plain)
	pipe := func(opts options, in, out string) {
		t.Helper()
		stdin, err := os.Open(in)
		if err != nil {
			t.Fatal(err)
		}
		defer stdin.Close()
		stdout, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		if err := run(opts, stdin, stdout, password("pw")); err != nil {
			t.Fatal(err)
		}
	}
	pipe(options{lowMemory: true}, in, enc)
	pipe(options{decrypt: true, input: "-"}, enc, dec)
	checkFile(t, dec, plain)
}

func TestFailure(t *testing.T) {
	dir := t.TempDir()
	enc, out := filepath.Join(dir, "enc"), filepath.Join(dir, "out")
	if err := run(options{lowMemory: true, input: os.DevNull, output: enc}, nil, nil, password("pw")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, out, plain)
	err := run(options{decrypt: true, input: enc, output: out}, nil, nil, password("wrong"))
	if !errors.Is(err, crypt.ErrAuthentication) {
		t.Errorf("run() error = %v, want %v", err, crypt.ErrAuthentication)
	}
	checkFile(t, out, plain)
	checkDir(t, dir, "enc", "out")
}

func TestEmptyPassword(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	if err := run(options{input: os.DevNull, output: out}, nil, nil, password("")); err == nil {
		t.Error("run() with empty password succeeded")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%s) error = %v, want %v", out, err, os.ErrNotExist)
	}
}

func TestIrregularOutput(t *testing.T) {
	if err := run(options{input: os.DevNull, output: os.DevNull}, nil, nil, password("pw")); err == nil {
		t.Errorf("run() with output %s succeeded", os.DevNull)
	}
}
