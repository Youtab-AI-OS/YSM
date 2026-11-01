# YSM — Youtab Security Message

A local-first, end-to-end encrypted messenger for Windows, with a responsive
mobile-first interface. Built on the crypto work recovered from
aesencryption.net (see [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)),
but with a completely different and far stronger security model.

---

## Status — read this first

| Platform | State |
| --- | --- |
| **Windows 10/11 x64** | **Built, tested, packaged, installer verified.** This is what exists. |
| Responsive web UI | Works from 360 px up. Verified by automated layout tests at 360/390/768/1280 px. |
| iOS | **Not built.** Requires macOS + Xcode + an Apple signing identity. |
| Android | **Not built.** Requires the Android SDK + Gradle. |
| macOS | **Not built.** Requires macOS to build, sign and notarise. |

The UI and crypto core are platform-neutral ES modules with a single storage
adapter, and the UI is a plain responsive web app — so wrapping it for
Capacitor (iOS/Android) or a macOS Electron build is a packaging task, not a
rewrite. But "prepared" is not "working", and I am not claiming those builds
work until they are actually built and tested on those platforms.

---

## Install (Windows)

```
release/installer/YSM-Setup-1.0.0-x64.exe
```

- Per-user install to `%LOCALAPPDATA%\Programs\YSM` — **no administrator rights**.
- Silent install supported: `YSM-Setup-1.0.0-x64.exe /VERYSILENT /SUPPRESSMSGBOXES`.
- Uninstaller asks before deleting your encrypted data, and defaults to keeping it.
- Installs no background service, no startup entry, no update checker.

Requirements: Windows 10 1809+ or Windows 11, 64-bit.

---

## Using it

### 1. Create an account

Click **Create a new account**. Choose a display name and a password of at
least 12 characters.

That password encrypts everything on the device. It is never stored anywhere —
not on disk, not in memory after unlock, not sent anywhere.

### 2. Set up two-factor authentication

You are shown a QR code and a Base32 key. Add them to any authenticator app
(Google Authenticator, Authy, Aegis, 1Password, …). Then type the 6-digit code
to prove enrolment worked.

The account does **not** unlock until you do this, so you cannot accidentally
create an account you can never open again.

You are then shown **10 recovery codes**. Save them offline, now. They are shown
exactly once, are stored only as hashes, and each works once.

### 3. Exchange contact cards

Each account has a **contact card** (`ysm-contact://…`). Send yours to the other
person however you like. They paste it in **Contacts → Add contact**.

A card is self-signed, and a card with an invalid signature is refused.

### 4. Compare safety numbers — this matters

Open a contact to see a **safety number**: 8 groups of 5 digits.

Compare it with the other person **in person or over a voice call**. If the
numbers match, nobody is in the middle of your conversation. If they do not,
stop.

This is the only defence against a man-in-the-middle. The app shows the number
prominently, but it cannot verify it for you.

### 5. Talk

Send text, or attach files: photos, video, audio (including `.wav` and `.mp3`),
ZIP archives, PDFs and office documents. Files are chunked at 1 MiB and each
chunk is separately encrypted and signed, so a large video works without loading
the whole thing into memory.

### 6. Deliver the messages

YSM has no server. To send a message, export it and hand the file to the
recipient by whatever means you like:

- **Export encrypted file** writes a `.ysm` file containing the envelopes.
- The recipient uses **Import encrypted file**.

Whoever carries the file sees only ciphertext — but they do see that a file was
sent, roughly how big it is, and when. If you route it through email, the email
provider learns the same.

---

## Languages

English, Nederlands and فارسی. Switch in **Settings → Language**; the interface
flips to right-to-left for Farsi.

---

## Security design

### Crypto

| Purpose | Primitive |
| --- | --- |
| Key agreement | X25519 |
| Signatures | Ed25519 |
| Message encryption | AES-256-GCM (fresh random nonce per message) |
| Key derivation | HKDF-SHA256 |
| Password hashing | Argon2id, 64 MiB / t=3 / p=1 |
| Hashing | SHA-256 / SHA-512 |

No custom constructions. Every primitive comes from the audited `@noble/*`
libraries.

**Per message:** a fresh 32-byte salt and 12-byte nonce. The long-term ECDH
secret is only ever HKDF *input*, never a key. Encryption and MAC keys are
derived with distinct labels. The header is authenticated as AAD, so it cannot
be altered. The whole envelope is then signed with Ed25519, and **the signature
is verified before decryption**.

**Identity:** two long-term keypairs (X25519 for agreement, Ed25519 for
signatures). Both are needed: a shared ECDH secret proves two parties can derive
the same key, but only a signature proves *who* sent a message.

### Storage

- SQLite via `node:sqlite` — **no native module to compile**, which removes the
  usual Electron ABI breakage.
- Every user-data column is encrypted at the application layer with AES-256-GCM,
  under a subkey bound to that column's context. A ciphertext moved into another
  column fails to decrypt.
- The database key is random 32 bytes, generated at account creation and stored
  **wrapped** under an Argon2id-derived KEK. The KEK exists only in memory while
  unlocked.
- Not SQLCipher. Queries operate on ciphertext, so there is no full-text search
  over message bodies. That is a deliberate trade.

### Unlock

```
password + salt ──Argon2id──▶ KEK ──AES-GCM──▶ vault key ──▶ database
                                    ▲
                        TOTP code checked BEFORE the key is released
```

Five failed attempts trigger exponential backoff (30 s, doubling, capped at
15 min), checked *before* Argon2 runs so it cannot be used as a CPU oracle. A
TOTP code that was already used is refused — the counter is persisted.

---

## No telemetry — concretely

- No analytics SDK. No crash reporter. No update checker. No network calls.
- The renderer's request filter denies **every** origin that is not the app's own
  files. Even a hypothetical beacon could not connect.
- `connect-src 'none'` in the CSP, on top of that.
- Every permission request (camera, microphone, geolocation, notifications)
  returns deny.
- The app works fully offline. There is no account server, because there is no
  server at all.

You can verify this yourself: disable your network adapter and use the app
normally.

---

## Known limitations (stated, not hidden)

1. **No forward secrecy.** The X25519 identity key is long-term, so compromise of
   a device key decrypts previously captured messages. This is the main gap
   versus Signal, and it needs a Double Ratchet to fix.
2. **Safety numbers require user action.** If two people never compare them, a
   MITM is undetectable.
3. **No multi-device.** One account = one device identity. Device linking is not
   implemented.
4. **No group rekeying.** Removing a member does not rotate keys or prevent them
   from reading old messages.
5. **No auto-update.** Security fixes require running a new installer. That is a
   deliberate trade: no update channel means no update channel to compromise.
6. **Transport is yours.** Delivering `.ysm` files is outside the app.
7. **`node:sqlite` is flagged experimental** by Node. It is stable in Electron 45
   in practice and pinned by `engines`, but a future runtime upgrade is a real
   risk.
8. **Attachments are capped at 2 GiB** per file and messages at 64 KiB of text.

---

## Development

```bash
npm ci
npm run build      # i18n + icons + TypeScript
npm test           # 212 unit/integration tests + Electron e2e
npm start          # run the app from source
npm run dist       # package with electron-builder
```

Then build the installer:

```bash
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\ysm.iss
# or, on this machine:
"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\ysm.iss
```

### Test suites

| Suite | What it proves |
| --- | --- |
| `test/*.test.mjs` | AES vs FIPS-197 and OpenSSL; aesencryption.net compatibility; the CMSG1 envelope format |
| `scripts/test-crypto.mjs` | Identity, envelopes, tamper/impersonation rejection, all six file types |
| `scripts/test-auth.mjs` | RFC 6238 TOTP vectors, Argon2id, vault wrapping, password policy, recovery codes |
| `scripts/test-vault.mjs` | Account lifecycle, wrong password, wrong TOTP, replay, lockout, data-at-rest |
| `scripts/test-messaging.mjs` | Two accounts: text + files, impersonation, tampering, dropped chunks |
| `scripts/test-service.mjs` | The IPC-equivalent service surface, recovery codes, locking |
| `scripts/e2e-electron.cjs` | The **real app**: account creation, 2FA, IPC validation, locked-state protection |
| `scripts/e2e-two-users.cjs` | The **real app**: a full Alice↔Bob conversation with text and a photo, plus Eve unable to read it |
| `scripts/test-responsive.cjs` | Layout at 360/390/768/1280 px, touch targets, RTL, composer visibility |
| `scripts/test-qr-decode.cjs` | QR codes decode with an independent decoder (jsQR) |
| `scripts/test-urlguard.cjs` | File-URL guard blocks traversal and remote requests |
| `scripts/smoke-electron.cjs` | Electron hardening assertions at runtime |

### Layout

```
src/ysm/
  crypto/       identity, envelope, attachment, auth (TOTP/Argon2)
  storage/      db (node:sqlite), vault, contacts, messaging
  app/          service — the IPC-equivalent API, Electron-free and testable
  ipc/          the closed IPC contract and per-channel validators
  i18n/         translations (source of truth)
electron/       main process (hardened), preload bridge, QR encoder
renderer/       index.html, styles.css, app.js, i18n.js (generated)
installer/      Inno Setup script
docs/           architecture, OWASP analysis, spec, reverse-engineering notes
```

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — threat model, what is and is not defended
- [docs/OWASP.md](docs/OWASP.md) — OWASP Top 10, LLM Top 10 and Agentic threats, item by item
- [docs/SPEC.md](docs/SPEC.md) — the CMSG1 envelope format
- [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md) — how the aesencryption.net scheme was recovered
- [docs/DECISIONS.md](docs/DECISIONS.md) — design choices and the traps that cost time
