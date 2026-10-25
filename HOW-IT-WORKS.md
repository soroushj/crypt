# How crypt works

This is a walkthrough of how `crypt` encrypts and decrypts data, and why each
part of the design is needed. It is written for software engineers rather
than cryptographers: It describes what each building block does and
guarantees, not how the algorithms work inside. For the exact file format,
see the [README](README.md#file-format).

## The big picture

```
password ─┐
salt ─────┼─► Argon2id ─► 32-byte secret ─┐
params ───┘                               ├─► HKDF ─► key
header ───────────────────────────────────┘

plaintext ─► 64 KiB chunks ─► AES-256-GCM (key, nonce) ─► encrypted chunks

file = header | encrypted chunk 0 | encrypted chunk 1 | ... | encrypted chunk n
```

There are two halves:

1. Turning a human password into a strong key.
2. Using that key to encrypt a stream so that it cannot be read, modified,
   reordered, or cut short without detection.

## Part 1: From password to key

### Salt

The salt is 16 random bytes, generated for every file and stored in its
header. It is mixed into key derivation.

**Why:** Without a salt, the same password would always produce the same key.
An attacker could precompute the keys of millions of common passwords once
and reuse that work against every file, and two files encrypted with the
same password would share a key. With a salt, every guess must be redone for
every file, and every file gets its own key, even if passwords are reused.
The salt is not secret; it only has to be unique.

### Argon2id

[Argon2id](https://www.rfc-editor.org/rfc/rfc9106.html) is a password-hashing
function. It takes the password, the salt, and three parameters (time t,
memory m, and parallelism p), and produces 32 random-looking bytes.

**Why:** Passwords are weak secrets. Anyone with an encrypted file can guess
passwords offline, as fast as their hardware allows, with no lockout after
failed attempts. Argon2id is deliberately slow and memory-hungry: With the
default parameters, each guess takes about half a second and 2 GiB of memory.
The memory requirement matters most. GPUs and custom chips are fast because
they run thousands of cores in parallel, but they don't have 2 GiB of memory
per core, so requiring it per guess takes away most of their advantage.

This makes guessing expensive, not impossible. Argon2id multiplies the cost
of each guess, but the number of guesses needed depends only on the password:
A password from a list of a million leaked passwords is still found in hours
on rented servers, while a long random passphrase is out of reach.

Argon2id is deterministic: The same password, salt, and parameters always
produce the same output. This is why the parameters are stored in the
header, and why decryption needs as much memory as encryption did.

### HKDF

[HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) is a key derivation
function. It turns the Argon2id output into the AES key, mixing in the raw
bytes of the header.

**Why:** This binds the header to the key. The salt and the parameters
already affect the key through Argon2id, but the format's magic and version
bytes don't. Mixing in the whole header means that changing any byte of it
results in a different key, so decryption fails at the first chunk. Thus, the
header cannot be tampered with, for example to relabel a file as a different
version, without detection, and no extra field is needed to protect it.

## Part 2: Encrypting the data

### AES-256-GCM

AES-256-GCM is an *AEAD* (authenticated encryption with associated data)
cipher. Given a key, a nonce, and a message, it produces:

- **Ciphertext:** The message, made unreadable without the key. This provides
  confidentiality.
- **A tag:** 16 bytes that act as a keyed checksum. On decryption, GCM
  recomputes the tag, and refuses to return anything if it doesn't match.
  This provides integrity.

**Why authentication matters:** Encryption alone does not prevent
modification. With many ciphers, including the one inside GCM, flipping a bit
of the ciphertext flips the same bit of the plaintext, so an attacker could
change "pay $100" into "pay $900" without knowing the key. The tag makes any
change, even of a single bit, detectable.

A wrong password produces a wrong key, which also fails the tag check. This
is why `crypt` reports a wrong password and corrupt data as the same error:
The two are indistinguishable by design.

### Nonce

A nonce, short for "number used once," is a 12-byte value that GCM takes
along with the key for each message.

**Why it must be unique:** GCM has one hard rule: Never encrypt two messages
with the same key and nonce. Breaking it is catastrophic. It reveals the XOR
of the two plaintexts, which often reveals both, and it allows an attacker to
forge tags. How `crypt` chooses nonces is described below.

## Part 3: Chunking and STREAM

### Why chunks

The simplest approach is to encrypt the whole file as a single GCM message.
That has two problems:

1. **Memory:** The whole file must fit in memory.
2. **Unverified output:** GCM can only check the tag after processing the
   whole message. A decryptor that streams its output would have to either
   hold everything back until the end, or release plaintext that hasn't been
   verified yet. Acting on unverified data is a classic source of attacks.

So `crypt` splits the plaintext into 64 KiB chunks, and encrypts each chunk
as a separate GCM message with its own tag. An encrypted chunk is the
ciphertext of a chunk, followed by its tag. Each chunk is verified before its
plaintext is released, and memory usage does not depend on file size.

### Why naive chunking is insecure

Suppose each chunk were encrypted independently, say with a random nonce
stored next to it. Every chunk would pass its own tag check, but an attacker
could still rearrange whole chunks without breaking any tags:

- **Reorder:** Swap chunks 3 and 7.
- **Drop:** Delete chunk 5.
- **Duplicate:** Repeat chunk 2.
- **Truncate:** Cut the file after chunk 10.

Each chunk would be authentic, but the stream as a whole would not.
Truncation is especially dangerous: A truncated configuration file or
transaction log may still look valid.

### STREAM: Put the position in the nonce

[STREAM](https://eprint.iacr.org/2015/189) is a construction by Hoang,
Reyhanitabar, Rogaway, and Vizár, also used by
[age](https://age-encryption.org) and Google's
[Tink](https://developers.google.com/tink). Its idea is simple: The nonce is
not random, but encodes where the chunk belongs.

```
nonce = [ chunk index: 11 bytes ][ last-chunk flag: 1 byte ]
```

The index starts at zero in every file. This is safe because every file has
its own key, derived with its random salt, so a nonce never repeats under the
same key, and nonces don't need to be stored. For the same reason, chunks
taken from another file fail verification.

The tag depends on the nonce, so a chunk is only verified at its own
position:

- **Reordered or duplicated:** Chunk 7 moved to position 3 is checked with
  index 3, and fails.
- **Dropped:** Once chunk 5 is removed, chunk 6 is at position 5, and fails.

The index alone doesn't detect truncation at a chunk boundary: If the file is
cut after chunk 10, chunks 0 to 10 are all still verified. That is the job of
the last-chunk flag:

- **Truncated:** Chunk 10 was encrypted with the flag set to "not last."
  Once it is the last chunk, it is checked with the flag set to "last," and
  fails.
- **Extended:** If anything is appended after the real last chunk, that chunk,
  which was encrypted as "last," is checked as "not last," and fails.

In short, the index protects the order, and the flag protects the
completeness. The only stream that decrypts successfully is exactly the one
that was written.

### Consequences for the implementation

- **The writer can't encrypt a full chunk right away.** It doesn't know yet
  whether the chunk is the last one, and the flag is part of the encryption.
  So it buffers 64 KiB, and encrypts the chunk as "not last" only once more
  data arrives. This is why calling `Close` is mandatory: It encrypts the last
  chunk with the flag set.
- **The reader reads one byte ahead.** To know whether a chunk is the last
  one, it must know whether any data follows it, so it reads a full chunk
  plus one byte. If that byte exists, the chunk is not the last one.

### Canonical encoding

One more rule: The last chunk is empty only if the whole plaintext is empty.
Without it, the same plaintext could be encoded in two ways, for example as a
full chunk followed by an empty last chunk, or as a full last chunk. The
writer never produces the former, and the reader rejects it, so every
plaintext has exactly one valid encoding under a given key. This is checked
by a fuzz test.

## Putting it together

Encryption:

1. Generate a random salt, and build the header: magic, version, parameters,
   and salt.
2. Derive the key with Argon2id and HKDF, and free Argon2id's memory.
3. Write the header.
4. Encrypt each 64 KiB of plaintext with the nonce of its index and flag, and
   write it, followed by its tag. The last chunk has the flag set.

Decryption:

1. Read the header, and check its magic, version, and parameter bounds.
2. Derive the same key from the password and the header.
3. Read each chunk, plus one byte to learn whether it is the last one. Verify
   and decrypt it with the nonce of its index and flag, and release its
   plaintext only once it is verified.
4. Report success only once the last chunk is verified.

## What this does and doesn't protect

`crypt` guarantees:

- **Confidentiality:** The content can't be read without the password.
- **Integrity:** Any change to the header or to any chunk is detected.
- **Stream integrity:** Reordering, dropping, duplicating, truncating, or
  appending chunks is detected.
- **No unverified output:** Any data released has been verified. However,
  the data is known to be complete only once decryption reaches the end
  successfully. This is why the exit status of `crypt` matters when
  decrypting to the standard output.

`crypt` does not protect against:

- **Weak passwords:** Argon2id slows guessing down, but can't prevent it.
- **Size leaks:** The size of an encrypted file reveals the approximate size
  of its content.
- **A compromised machine:** If an attacker can read your memory or log your
  keystrokes, no encryption helps.
