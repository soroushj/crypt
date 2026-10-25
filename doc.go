// Package crypt implements password-based authenticated encryption of
// arbitrarily large streams.
//
// A key is derived from the password with Argon2id, as recommended by
// [RFC 9106], and bound to the header with HKDF ([RFC 5869]). The data is
// encrypted with AES-256-GCM in fixed-size chunks using the STREAM
// construction of [HRRV15]. Encryption and decryption work online (i.e., in a
// single pass, as the data arrives) and in constant memory, and every chunk is
// authenticated before it is released. Reordering, truncation, and extension
// of the stream are detected.
//
// [NewWriter] encrypts and [NewReader] decrypts:
//
//	w, err := crypt.NewWriter(dst, password, crypt.DefaultParams)
//	if err != nil {
//		return err
//	}
//	if _, err := io.Copy(w, src); err != nil {
//		return err
//	}
//	return w.Close()
//
// # Parameters
//
// [DefaultParams] and [LowMemoryParams] are the two recommendations of
// RFC 9106, Section 4. Decryption must derive the same key with the same
// parameters, so it needs as much memory as encryption did: 2 GiB for
// DefaultParams, and 64 MiB for LowMemoryParams. The parameters are stored in
// the header, so this is decided when the stream is encrypted, and
// [NewReader] needs no parameters. The memory used for key derivation is
// returned to the operating system before any data is processed, so the peak
// memory usage of encryption and decryption is that of key derivation, plus a
// few MiB, regardless of the size of the data.
//
// # Format
//
// An encrypted stream is a 31-byte header followed by a payload. Integers are
// big-endian.
//
//	offset  size  field
//	     0     5  magic, "crypt"
//	     5     1  version, 1
//	     6     4  Argon2 time, t (number of passes)
//	    10     4  Argon2 memory, m (KiB)
//	    14     1  Argon2 parallelism, p
//	    15    16  salt (random)
//
// The salt and the password are passed to Argon2id with the parameters in the
// header, producing a 32-byte key. Since this key is uniformly random, it is
// used as the pseudorandom key of HKDF-Expand with SHA-256, skipping the
// extract step as permitted by [RFC 5869], Section 3.3. The info parameter is
// the entire header, which binds every header field to the resulting 32-byte
// AES key: changing any of them results in a different key, and thus an
// authentication failure.
//
// The payload is a sequence of chunks. Each chunk is 64 KiB of plaintext
// encrypted with AES-256-GCM and followed by its 16-byte GCM tag, except the
// last chunk, which may be shorter. The last chunk is empty only if the whole
// plaintext is empty. The 12-byte nonce of the chunk with index i (counting
// from 0) is the 11-byte big-endian encoding of i followed by a byte that is 1
// for the last chunk and 0 otherwise. Every stream has a fresh random salt,
// and thus a fresh key, so nonces never repeat under the same key.
//
// [RFC 9106]: https://www.rfc-editor.org/rfc/rfc9106.html
// [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869.html
// [HRRV15]: https://eprint.iacr.org/2015/189
package crypt
