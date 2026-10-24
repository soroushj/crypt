// Crypt encrypts and decrypts files with a password.
//
// Usage:
//
//	crypt [-d] [-l] [-o output] [input]
//
// Crypt reads input, or the standard input if input is absent or "-", and
// writes the result to output, or the standard output if -o is absent. The
// password is read from the terminal, so that the standard input remains
// available for data. When encrypting, the password is read twice.
//
// The flags are:
//
//	-d
//		Decrypt instead of encrypting.
//	-l
//		Encrypt with the low-memory parameters of RFC 9106, which need
//		64 MiB of memory, instead of the default ones, which need 2 GiB.
//		Decryption needs as much memory as encryption did, so use -l for
//		files that may be decrypted on machines with less memory. When
//		decrypting, the parameters are read from input, so -l is invalid.
//	-o output
//		Write to output instead of the standard output. Output must be a
//		regular file, if it exists. It is created with mode 0600, and is
//		replaced atomically, only if crypt succeeds, so it may be the same
//		file as input. If output is a symbolic link, the link is replaced.
//	-V
//		Print the version and exit.
//
// Crypt refuses to write encrypted data to a terminal. When decrypting to
// the standard output, data is written as soon as it is authenticated, so
// the output is complete only if crypt succeeds.
//
// The exit status is 0 on success, 1 on error, and 2 on invalid usage. If
// crypt receives SIGHUP, SIGINT, or SIGTERM, it removes its temporary file,
// restores the terminal, and terminates by the same signal.
//
// See [github.com/soroushj/crypt] for the cryptographic design and the file
// format.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/soroushj/crypt"
	"golang.org/x/term"
)

const usageLine = "usage: crypt [-d] [-l] [-o output] [input]"

type options struct {
	decrypt   bool
	lowMemory bool
	output    string
	version   bool
	input     string
}

func main() {
	opts, err := parseArgs(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	} else if err != nil {
		os.Exit(2)
	}
	if opts.version {
		fmt.Println("crypt", version())
		return
	}
	go handleSignals()
	if err := run(opts, os.Stdin, os.Stdout, readPassword); err != nil {
		fmt.Fprintln(os.Stderr, "crypt:", err)
		os.Exit(1)
	}
}

// parseArgs parses the command-line arguments, and reports invalid usage to
// stderr.
func parseArgs(args []string, stderr io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("crypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), usageLine)
		fs.PrintDefaults()
	}
	fs.BoolVar(&opts.decrypt, "d", false, "decrypt instead of encrypting")
	fs.BoolVar(&opts.lowMemory, "l", false, "encrypt with 64 MiB of memory instead of 2 GiB")
	fs.StringVar(&opts.output, "o", "", "write to `output` instead of the standard output")
	fs.BoolVar(&opts.version, "V", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	var err error
	switch {
	case fs.NArg() > 1:
		err = errors.New("too many operands")
	case opts.decrypt && opts.lowMemory:
		err = errors.New("-l is invalid with -d")
	}
	if err != nil {
		fmt.Fprintln(stderr, "crypt:", err)
		fs.Usage()
		return opts, err
	}
	opts.input = fs.Arg(0)
	return opts, nil
}

// run encrypts or decrypts as specified by opts. It calls getPassword to read
// the password, asking for confirmation if confirm is set.
func run(opts options, stdin, stdout *os.File, getPassword func(confirm bool) ([]byte, error)) (err error) {
	in := stdin
	if opts.input != "" && opts.input != "-" {
		f, err := os.Open(opts.input)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	if opts.output == "" {
		if !opts.decrypt && term.IsTerminal(int(stdout.Fd())) {
			return errors.New("refusing to write encrypted data to a terminal")
		}
	} else if fi, err := os.Stat(opts.output); err == nil && !fi.Mode().IsRegular() {
		// Only regular files can be replaced atomically. Redirect the
		// standard output to write to anything else.
		return fmt.Errorf("%s is not a regular file", opts.output)
	}

	password, err := getPassword(!opts.decrypt)
	if err != nil {
		return err
	}
	defer clear(password)
	if len(password) == 0 {
		return errors.New("empty password")
	}

	out := stdout
	if opts.output != "" {
		var f *os.File
		f, err = createTemp(opts.output) // not :=, which would shadow err
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				discard(f)
			}
		}()
		out = f
	}

	if opts.decrypt {
		err = decrypt(out, in, password)
	} else {
		params := crypt.DefaultParams
		if opts.lowMemory {
			params = crypt.LowMemoryParams
		}
		err = encrypt(out, in, password, params)
	}
	if err != nil {
		return err
	}
	if out != stdout {
		return commit(out, opts.output)
	}
	return nil
}

func encrypt(dst io.Writer, src io.Reader, password []byte, params crypt.Params) error {
	w, err := crypt.NewWriter(dst, password, params)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return w.Close()
}

func decrypt(dst io.Writer, src io.Reader, password []byte) error {
	r, err := crypt.NewReader(src, password)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}

// readPassword reads a password from the terminal. If confirm is set, it
// reads the password twice, and checks that both match.
func readPassword(confirm bool) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot read password: %w", err)
	}
	defer tty.Close()
	password, err := prompt(tty, "Password: ")
	if err != nil || !confirm {
		return password, err
	}
	again, err := prompt(tty, "Confirm password: ")
	defer clear(again)
	if err == nil && !bytes.Equal(password, again) {
		err = errors.New("passwords do not match")
	}
	if err != nil {
		clear(password)
		return nil, err
	}
	return password, nil
}

// prompt writes s to tty, and reads a line from it with echo disabled.
func prompt(tty *os.File, s string) ([]byte, error) {
	fd := int(tty.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	undo.Lock()
	undo.tty, undo.ttyState = fd, state
	undo.Unlock()
	defer func() {
		undo.Lock()
		undo.ttyState = nil
		undo.Unlock()
	}()
	fmt.Fprint(tty, s)
	defer fmt.Fprintln(tty) // the newline is not echoed either
	return term.ReadPassword(fd)
}

// createTemp creates a temporary file in the directory of path, so that it
// can be renamed to path atomically.
func createTemp(path string) (*os.File, error) {
	undo.Lock()
	defer undo.Unlock()
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	undo.temp = f.Name()
	return f, nil
}

// commit flushes the temporary file f to stable storage, and renames it to
// path.
func commit(f *os.File, path string) error {
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	undo.Lock()
	defer undo.Unlock()
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	undo.temp = ""
	return nil
}

// discard closes and removes the temporary file f.
func discard(f *os.File) {
	f.Close()
	undo.Lock()
	defer undo.Unlock()
	os.Remove(f.Name())
	undo.temp = ""
}

// undo is the state to restore if crypt is terminated by a signal.
var undo struct {
	sync.Mutex
	tty      int         // file descriptor of the terminal
	ttyState *term.State // state of the terminal to restore, if not nil
	temp     string      // name of the temporary file to remove, if not empty
}

// handleSignals waits for a terminating signal, undoes the side effects of
// crypt, and re-raises the signal.
func handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c
	undo.Lock() // never unlocked: the process is about to terminate
	if undo.ttyState != nil {
		term.Restore(undo.tty, undo.ttyState)
	}
	if undo.temp != "" {
		os.Remove(undo.temp)
	}
	// Terminate by the default action of the signal, rather than exiting,
	// so that the parent process can tell how crypt terminated.
	signal.Reset(sig)
	syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
}

// version returns the version of the main module, which go build derives
// from version control.
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}
