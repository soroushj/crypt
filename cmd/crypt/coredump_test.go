package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestDisableCoreDumps checks the effect of disableCoreDumps on the test
// process itself, which cannot be undone, but is harmless to the tests.
func TestDisableCoreDumps(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Errorf("RLIMIT_CORE = %+v, want {Cur:0 Max:0}", lim)
	}
	checkDumpable(t)
}
