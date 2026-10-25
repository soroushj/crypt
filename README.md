# crypt

[![Go Reference](https://pkg.go.dev/badge/github.com/soroushj/crypt.svg)](https://pkg.go.dev/github.com/soroushj/crypt)
[![CI](https://github.com/soroushj/crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/soroushj/crypt/actions/workflows/ci.yml)

`crypt` encrypts files with a password. It is a small command-line tool and a
Go package that follow published recommendations closely:

- Keys are derived with **Argon2id**, using the parameters recommended by
  [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
- Data is encrypted with **AES-256-GCM** in 64 KiB chunks, using the
  **STREAM** construction of
  [Hoang, Reyhanitabar, Rogaway, and Vizár](https://eprint.iacr.org/2015/189).
  Files of any size are processed in constant memory, and truncated,
  reordered, or tampered files are rejected.
- The whole header is bound to the key with **HKDF**, as described in
  [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.3).

The only dependencies are the Go standard library, plus `golang.org/x/crypto`
for Argon2 and `golang.org/x/term` for reading passwords.

## Install

```sh
go install github.com/soroushj/crypt/cmd/crypt@latest
```

Or download a binary for Linux or macOS from the
[releases](https://github.com/soroushj/crypt/releases) page. Release archives
come with build provenance attestations, which you can verify with:

```sh
gh attestation verify crypt_1.0.0_linux_amd64.tar.gz --repo soroushj/crypt
```

## Usage

```
crypt [-d] [-l] [-o output] [input]
```

`crypt` reads `input`, or the standard input if `input` is absent or `-`, and
writes to `output`, or the standard output if `-o` is absent. The password is
read from the terminal, so the standard input stays free for data.

| Flag        | Description |
| ----------- | ----------- |
| `-d`        | Decrypt instead of encrypting. |
| `-l`        | Encrypt with 64 MiB of memory instead of 2 GiB (see [Parameters](#parameters)). |
| `-o output` | Write to `output`, which is replaced atomically, only on success. It may be the same file as `input`. |
| `-V`        | Print the version. |

```sh
crypt -o notes.txt.crypt notes.txt       # encrypt a file
crypt -d -o notes.txt notes.txt.crypt    # decrypt it
crypt -o notes.txt notes.txt             # encrypt in place
tar -c photos | crypt -o photos.tar.crypt
crypt -d photos.tar.crypt | tar -x
```

The exit status is 0 on success, 1 on error, and 2 on invalid usage. When
decrypting to the standard output, data is written as soon as it is
authenticated, so the output is complete only if the exit status is 0. With
`-o`, nothing is written unless decryption succeeds.

On `SIGHUP`, `SIGINT`, or `SIGTERM`, `crypt` removes its temporary file,
restores the terminal if it was reading a password, and terminates by the same
signal.

## Package

```go
// Encrypt: plaintext written to w is encrypted and written to dst.
w, err := crypt.NewWriter(dst, password, crypt.DefaultParams)
if err != nil {
	return err
}
if _, err := io.Copy(w, src); err != nil {
	return err
}
return w.Close() // writes the last chunk
```

```go
// Decrypt: ciphertext is read from src, and plaintext is read from r.
r, err := crypt.NewReader(src, password)
if err != nil {
	return err
}
_, err = io.Copy(dst, r) // errors.Is(err, crypt.ErrAuthentication) on a wrong password
return err
```

See the [package documentation](https://pkg.go.dev/github.com/soroushj/crypt).

## Design

### Parameters

RFC 9106 recommends two parameter sets for Argon2id, both with a 128-bit
salt and a 256-bit tag:

| Preset            | Flag | t | m      | p | Apple M2\* | Intel Core i9-13900\* |
| ----------------- | ---- | - | ------ | - | ---------- | --------------------- |
| `DefaultParams`   |      | 1 | 2 GiB  | 4 | 530 ms     | 700 ms                |
| `LowMemoryParams` | `-l` | 3 | 64 MiB | 4 | 38 ms      | 36 ms                 |

\* Key derivation time, median of 5 runs of `BenchmarkKeyDerivation`.

Decryption must derive the same key with the same parameters, so it needs as
much memory as encryption did. The parameters are stored in each file, so this
is decided when the file is encrypted: use `-l` for files that may be
decrypted on machines with less than 2 GiB of free memory.

Argon2 allocates all of its memory at once, and the Go garbage collector would
then keep that much memory resident for the rest of the run. So `crypt`
returns it to the operating system before processing any data. Peak memory
usage is therefore that of key derivation plus one 64 KiB chunk: encrypting
or decrypting a 1 GiB file with the default parameters peaks at 2.1 GB of RSS.

### Encryption

The 32-byte Argon2id output is expanded into an AES-256 key with HKDF-SHA-256.
The output is already uniformly random, so the extract step is skipped, as
RFC 5869 permits. The info parameter is the whole header, so any change to
the header yields a different key.

The data is split into 64 KiB chunks, and each chunk is encrypted with
AES-256-GCM. A chunk's nonce is its index followed by a flag marking the
last chunk. Every file has a random salt, and thus its own key, so counter
nonces never repeat under the same key. This also means that the limits that
apply to random GCM nonces don't apply here. The last-chunk flag is what
detects truncation at a chunk boundary.

Each chunk adds a 16-byte tag, which is 0.02% overhead. Larger chunks would
not speed things up: AES-GCM throughput levels off well below 64 KiB. They
would also make decryption hold back more data before it can be
authenticated.

### File format

All integers are big-endian.

| Offset | Size | Field |
| -----: | ---: | ----- |
| 0      | 5    | Magic, `crypt` |
| 5      | 1    | Version, 1 |
| 6      | 4    | Argon2 time, t |
| 10     | 4    | Argon2 memory in KiB, m |
| 14     | 1    | Argon2 parallelism, p |
| 15     | 16   | Salt |
| 31     |      | Chunks: up to 64 KiB of ciphertext followed by a 16-byte tag |

The 12-byte nonce of chunk *i* is *i* as an 11-byte integer, followed by `01`
for the last chunk and `00` otherwise. Only the last chunk may be shorter than
64 KiB, and it is empty only if the plaintext is empty.

To let `file(1)` recognize encrypted files, add this to `~/.magic` or
`/etc/magic`:

```
0	string	crypt\001	crypt encrypted data, version 1
>6	belong	x	\b, t=%u
>10	belong	x	\b, m=%u KiB
>14	byte	x	\b, p=%u
```

## Security considerations

- This project has not been audited.
- Encryption is only as strong as the password. Argon2id makes guessing
  expensive, not impossible.
- Encryption hides the content of a file, not its approximate size.
- Key material is cleared from memory where possible, but Go gives no
  guarantee about copies made by the runtime.

## Development

```sh
go test ./...                              # unit, golden-file, and example tests
go test -run TestGolden -update            # regenerate testdata after a format change
go test -fuzz FuzzReader                   # also FuzzRoundTrip and FuzzHeader
go test -run '^$' -bench .                 # key derivation and throughput
```

`crypt` supports Linux and macOS, and the two latest Go releases.

## License

[MIT](LICENSE)
