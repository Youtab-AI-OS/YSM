# YSM — Youtab Security Message

## Architecture and threat model

This document states what YSM protects against, what it does not, and where every
decision lives. If a claim here is not backed by code and a test, it should not
be here.

---

## 1. What YSM is

YSM is a **local-first, end-to-end encrypted messenger**. Two people who have
exchanged public keys can send each other text, photos, video, audio and arbitrary
files. Everything is encrypted on the sender's device and decrypted only on the
recipient's device.

It runs as a Windows desktop application (Electron), with a **responsive
mobile-first UI** that renders correctly down to 360 px wide. The same UI layer is
platform-neutral, which is what makes a future iOS/Android/macOS shell possible —
but see §9 for what that does and does not mean today.

---

## 2. Threat model

### In scope — YSM defends against these

| Threat | Defence |
| --- | --- |
| Network eavesdropper reading messages | Nothing plaintext ever leaves the device; ciphertext only |
| Server / relay operator reading messages | There is no server. Transport is an encrypted file or a paired channel; the relay only ever sees ciphertext |
| Attacker with the database file | Database is encrypted at the application layer; key never stored on disk |
| Attacker with a stolen backup | Same — ciphertext only, and the Argon2id-wrapped key needs the password |
| Attacker modifying ciphertext in transit | AES-256-GCM + Ed25519 signatures; tampering fails closed |
| Impersonation / key substitution | Contact verification by safety number (fingerprint comparison, out of band) |
| Phishing the account password | Password alone is insufficient: TOTP authenticator required at every unlock |
| Credential stuffing | Argon2id with per-account salt; rate limiting; no remote login endpoint exists at all |
| Malicious attachment (extension spoofing, path traversal) | Filename sanitisation, MIME sniffing, no auto-execution, no auto-open |
| UI injection via message content | All rendering via text nodes / `textContent`; no `innerHTML` for user data; strict CSP |
| Screen scraping at rest | Optional auto-lock, DB key held in memory only while unlocked |
| Telemetry / data exfiltration | **None.** No analytics, no crash reporting, no update pings, no DNS beaconing beyond nothing at all |
| Prompt injection into an AI feature | No AI features in the app. Zero LLM surface (see §8) |

### Out of scope — YSM does **not** defend against these

Stated plainly so nobody assumes protection that is not delivered:

- **A compromised operating system.** Malware with the ability to read process
  memory or inject into Electron can read messages while the app is unlocked. No
  user-space application can prevent this.
- **A coerced user.** YSM cannot stop someone being forced to reveal a password.
- **Metadata analysis across the transport you choose.** If you send `.ysm`
  files by email, the mail provider learns who talked to whom and when, and the
  file size reveals approximate message size.
- **Forward secrecy across a full device compromise.** See §4 — this is a real
  limitation of the current design.
- **Hardware attacks** (cold boot, DMA, evil maid) on an unencrypted disk.
- **An attacker who has your password *and* your TOTP secret.** At that point
  they are you.

---

## 3. Cryptographic design

### Primitives

| Purpose | Primitive | Source |
| --- | --- | --- |
| Key agreement | X25519 (Curve25519 ECDH) | `@noble/curves` |
| Signatures | Ed25519 | `@noble/curves` |
| Key derivation | HKDF-SHA256 | `@noble/hashes` |
| Message encryption | AES-256-GCM (AEAD, 96-bit nonce) | `@noble/ciphers` |
| Password hashing | Argon2id (64 MiB, t=3, p=1) | `@noble/hashes` |
| Hashing | SHA-256 / SHA-512 | `@noble/hashes` |
| Randomness | `crypto.getRandomValues` / `randomBytes` | platform CSPRNG |

No custom cryptographic constructions. Every primitive is a well-reviewed
audited library, and YSM composes them in standard ways only.

### Identity

Each account has two long-term keypairs, generated on-device:

- **X25519 identity keypair** — for key agreement.
- **Ed25519 signing keypair** — for authenticating messages and contact cards.

A user's shareable **Contact Card** contains: display name, X25519 public key,
Ed25519 public key, and is self-signed by the Ed25519 key. The **safety number**
is `SHA-256(x25519_pub || ed25519_pub)` rendered as 8 groups of 5 digits. Two
users compare it out of band (in person, on a call) to rule out a
man-in-the-middle. That comparison is the only defence against MITM and it
depends on the users actually doing it — the UI says so.

### Message encryption

For a message from A to B:

```
shared   = X25519(A_identity_priv, B_identity_pub)          // 32 bytes
                                          == X25519(B_identity_priv, A_identity_pub)
msg_key  = HKDF-SHA256(ikm = shared, salt = random_32, info = "ysm/v1/msg" || A_pub || B_pub, len = 32)
nonce    = random 12 bytes
cipher   = AES-256-GCM(key = msg_key, nonce, aad = canonical_header)
```

The AAD binds the header (sender pub, recipient pub, message id, timestamp,
content type) so nothing in it can be altered without breaking the AEAD tag.

Then the envelope is **signed** by the sender's Ed25519 key, and the signature
covers the whole envelope plus the salt and nonce. Signature verification is what
lets the recipient distinguish "from A" from "from anyone who knows A's public
key" — with a shared ECDH secret alone, either party could have produced the
message.

The long-term ECDH shared secret is **never used directly** as a message key; it
is only HKDF input, with a fresh per-message salt. That means one message key
compromise does not reveal others.

### Why a random salt per message, not a counter

A counter needs synchronised state between two offline devices, and desync
produces catastrophic key reuse with GCM. A fresh 32-byte random salt per message
costs 32 bytes and removes the entire class of key-reuse bugs.

### Attachments

Attachments are encrypted the same way but **chunked**, because a 500 MB video
cannot be loaded into memory:

- Split into 1 MiB chunks.
- Each chunk encrypted with AES-256-GCM under a **per-chunk subkey** derived as
  `HKDF(file_key, info = "ysm/v1/chunk" || chunk_index)`, with `chunk_index` also
  in the AAD.
- `file_key` is random per file, and travels inside the encrypted message body.
- Chunk index in the subkey derivation means chunks cannot be reordered,
  duplicated, or dropped without detection. The chunk count is bound in the
  message envelope, so truncation is detected.

This is why a 1 GiB upload works without OOM and why a partially-downloaded file
cannot be silently truncated.

### Database encryption

SQLite stores **only ciphertext** for user data:

- Every message body, attachment chunk, contact record and room record is
  encrypted at the application layer before being handed to SQLite.
- The **DB key** is random 32 bytes, generated at account creation.
- It is stored **wrapped**: `Argon2id(password, salt) -> KEK`, then
  `AES-256-GCM(KEK, db_key)`. The KEK exists only in memory while unlocked.
- The TOTP secret is stored inside the same encrypted bundle, not in plaintext.
- The database file never contains a plaintext password, plaintext message, or
  the DB key.

Note: this is application-layer encryption, **not** SQLCipher. Queries operate on
ciphertext, so no server-side-style search is possible — which is correct for a
messenger, and is stated rather than glossed over.

### Password and 2FA

1. Account creation: password (min 12 chars, checked against a common-password
   list), Argon2id-salted KEK derivation, random DB key, TOTP secret generated.
2. The TOTP secret is shown once as `otpauth://` URI + QR for an authenticator
   app, plus 10 single-use recovery codes (each Argon2id-hashed).
3. Login: password → KEK → unwrap DB key → then **TOTP code required before the
   database is opened**. The DB key is only released after both factors succeed.
4. Failed attempts are rate-limited with exponential backoff persisted per
   account. There is no unlock bypass and no "remember me" that skips TOTP.
5. Recovery codes are the only fallback, and each works once.

---

## 4. Honest limitations

- **No forward secrecy.** The X25519 identity key is long-term, so a device
  compromise that exposes it decrypts previously captured messages. A future
  version should move to a Double Ratchet (X3DH + ratchet) for per-message
  forward secrecy. This is the single biggest gap versus Signal, and it is a
  design choice for v1 scope, not an oversight.
- **No multi-device.** One account = one device identity. Adding a second device
  means exporting/importing the identity, which is not implemented.
- **No group rekeying.** Group rooms derive keys per member; removing a member
  does not retroactively rekey past messages and does not rotate future ones
  automatically.
- **Transport is your problem.** YSM produces and consumes `.ysm` envelopes.
  Delivering them (file copy, USB, email, your own relay) is outside the app.
  A relay sees only ciphertext and timing.
- **Safety numbers require user action.** If users never compare them, MITM is
  undetectable. The UI surfaces them prominently and explains why.

---

## 5. What "no telemetry" means concretely

- No analytics SDK, no crash reporter, no error upload.
- No network requests at all during normal operation. The app works fully
  offline; there is no account server, no sync, no update checker.
- Electron's `session` is configured with a request blocker that denies every
  outbound request not served from `app://` — enforced in code and covered by a
  test.
- `webPreferences`: `nodeIntegration: false`, `contextIsolation: true`,
  `sandbox: true`, no remote module, a strict allowlist on IPC channel names and
  shapes.
- A test asserts that the built app contains no telemetry endpoints and that the
  network guard denies unknown origins.

---

## 6. OWASP analysis

See `docs/OWASP.md` for the full mapping of OWASP Top 10 (2021), OWASP ASVS
areas, the OWASP Top 10 for LLM Applications, and the OWASP Agentic AI threats —
with, for each item, what YSM does and what residual risk remains. Items that do
not apply are marked N/A **with a reason**, not silently omitted.

---

## 7. Platform strategy

| Platform | Status |
| --- | --- |
| Windows | **Built and tested here.** Electron app + Inno Setup installer. |
| Mobile browsers / any browser | The UI is a responsive web app; it runs at mobile widths. |
| iOS | Requires macOS + Xcode + Apple signing. **Codebase prepared, not built.** |
| Android | Requires Android SDK + Gradle. **Codebase prepared, not built.** |
| macOS | Requires macOS to build/sign/notarise. **Codebase prepared, not built.** |

The UI and crypto core are platform-neutral ES modules with no Node-specific
dependencies except a thin storage adapter, so wrapping them for Capacitor
(iOS/Android) or a macOS Electron build is a packaging task, not a rewrite. I will
not claim those builds work until they are actually built and tested.

---

## 8. Deliberately absent: AI/LLM features

YSM contains **no LLM, no agent, no AI assistant**. This is a security decision,
not an oversight:

- A messenger that pipes message content into a model has a prompt-injection
  surface where an attacker's message can instruct the model to leak other
  messages.
- Model providers are third parties; using one would break the no-telemetry
  guarantee by definition.

Because there is no LLM surface, the OWASP LLM Top 10 and Agentic threats are
documented as N/A with reasoning, rather than pretended to be "handled".
