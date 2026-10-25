package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func checkDumpable(t *testing.T) {
	t.Helper()
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if dumpable != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, want 0", dumpable)
	}
}
