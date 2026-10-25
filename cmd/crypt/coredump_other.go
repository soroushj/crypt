//go:build !linux

package main

// disableDumpable does nothing, since outside Linux, RLIMIT_CORE applies to
// all core dumps.
func disableDumpable() error {
	return nil
}
