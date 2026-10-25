package main

import "golang.org/x/sys/unix"

// disableDumpable marks the process as not dumpable, so that the kernel
// produces no core dump of it at all, including one piped to a crash
// handler, which RLIMIT_CORE does not prevent. As a side benefit, it also
// prevents unprivileged processes, even of the same user, from attaching to
// crypt with a debugger (ptrace) or reading its memory through /proc, which
// would otherwise expose secrets while crypt runs. OpenSSH's ssh-agent does
// the same. See PR_SET_DUMPABLE in prctl(2).
func disableDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
