# Security policy

## Supported versions

Only the latest release of `crypt` receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately, not in public issues. Use
[GitHub's private vulnerability reporting](https://github.com/soroushj/crypt/security/advisories/new):
on the repository's **Security** tab, select **Report a vulnerability**.

Please include:

- A description of the vulnerability, and what an attacker could do with it.
- The affected versions, if known.
- Steps or code to reproduce it, such as a crafted encrypted file.

This is a personal project maintained on a best-effort basis. I will
acknowledge your report as soon as I can, keep you updated on the fix, and
credit you in the advisory unless you prefer otherwise.

## Scope

In scope are the `crypt` package and command, including their cryptographic
design, the file format, and the handling of passwords and keys. Note that the
project has not been audited.

Vulnerabilities in Go itself or in `golang.org/x` modules should be reported to
the Go project, as described in the
[Go security policy](https://go.dev/doc/security/policy).
