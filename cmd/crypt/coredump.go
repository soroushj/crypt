package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDumps prevents the operating system from saving a core dump of
// crypt.
//
// A core dump is a copy of a process's memory that the operating system can
// save when the process crashes, for later debugging. A Go program dumps core
// on a fatal error or a signal such as SIGQUIT if GOTRACEBACK=crash is set in
// its environment, which a user or a system may do for debugging. The memory
// of crypt may hold the password, the derived key, and decrypted data, so a
// core dump would leave them on disk, or in a crash reporting system, long
// after crypt exits. Clearing secrets once they are no longer needed does not
// prevent this, since a crash can happen while they are in use.
//
// Setting the RLIMIT_CORE resource limit to zero is the POSIX way to disable
// core dumps. Both the soft and the hard limits are set, so that the limit
// cannot be raised again. However, Linux does not enforce RLIMIT_CORE for
// core dumps piped to a crash handler, such as systemd-coredump or apport,
// which many distributions do by default (see core(5)). So on Linux, crypt is
// also marked as not dumpable; see disableDumpable.
func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("cannot disable core dumps: %w", err)
	}
	if err := disableDumpable(); err != nil {
		return fmt.Errorf("cannot disable core dumps: %w", err)
	}
	return nil
}
