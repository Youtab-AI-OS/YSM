name: Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's [private vulnerability
reporting](https://github.com/Youtab-AI-OS/YSM/security/advisories/new), or
email the maintainer listed in `CODEOWNERS`.

Please include:

- the version (Settings → About in the app, or the commit SHA),
- the operating system,
- what you expected, what happened, and the smallest reproduction you have,
- whether you have already disclosed it anywhere.

You will get an acknowledgement, an assessment of severity, and a fix timeline.
Credit is given in the advisory unless you ask otherwise.

## Scope

In scope:

- cryptographic weaknesses (key derivation, envelope format, nonce handling)
- authentication bypass (password, TOTP, recovery codes, lockout)
- plaintext disclosure at rest or on the wire
- IPC boundary violations, renderer sandbox escape
- unauthorised file read/write through the app
- failure to reject tampered or forged messages
- any network egress from the application

Out of scope, and already documented as limitations in
[`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md):

- absence of forward secrecy (long-term identity key, known and stated)
- an attacker who has the password **and** the TOTP secret
- a compromised operating system or malware reading process memory while unlocked
- metadata visible from the transport you choose (e.g. an email provider)
- the unsigned installer triggering a SmartScreen warning

## Supported versions

Only the latest release receives fixes.
