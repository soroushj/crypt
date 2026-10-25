package crypt

import "fmt"

// Params are the Argon2id parameters used to derive a key from a password.
// RFC 9106, Section 3.1, requires Time and Threads to be at least 1, and
// Memory to be at least 8*Threads KiB.
type Params struct {
	Time    uint32 // number of passes over the memory, t
	Memory  uint32 // memory size in KiB, m
	Threads uint8  // degree of parallelism, p
}

var (
	// DefaultParams are the first recommended parameters of RFC 9106,
	// Section 4: t=1, m=2 GiB, and p=4.
	DefaultParams = Params{Time: 1, Memory: 2 << 20, Threads: 4}

	// LowMemoryParams are the second recommended parameters of RFC 9106,
	// Section 4, for memory-constrained environments: t=3, m=64 MiB, and p=4.
	// They make password guessing considerably cheaper than DefaultParams, so
	// use them only when 2 GiB of memory is not available.
	LowMemoryParams = Params{Time: 3, Memory: 64 << 10, Threads: 4}
)

// Upper bounds of [Params], which limit the resources a stream can demand
// of a decrypting process.
const (
	MaxTime   = 16
	MaxMemory = 4 << 20 // 4 GiB, twice that of DefaultParams
)

// validate returns an error wrapping [ErrParams] unless p is within the
// bounds set by RFC 9106, Section 3.1, and by [MaxTime] and [MaxMemory].
func (p Params) validate() error {
	switch {
	case p.Time < 1 || p.Time > MaxTime:
		return fmt.Errorf("%w: time %d is not in [1, %d]", ErrParams, p.Time, MaxTime)
	case p.Threads < 1:
		return fmt.Errorf("%w: zero threads", ErrParams)
	case p.Memory < 8*uint32(p.Threads) || p.Memory > MaxMemory:
		return fmt.Errorf("%w: memory %d KiB is not in [8*threads, %d]", ErrParams, p.Memory, MaxMemory)
	}
	return nil
}
