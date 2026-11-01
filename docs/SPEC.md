# CMSG1 — the v2 message envelope

A self-describing, authenticated, versioned container for messages. This is the
format `cmsg encrypt` produces and `cmsg decrypt` consumes. The
aesencryption.net-compatible scheme is documented separately in
[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and is **not** this format.

## Wire format

```
CMSG1.<header>.<ciphertext>.<tag>
```

- `CMSG1` — literal magic and format generation.
- `<header>` — base64url (no padding) of the canonical header JSON.
- `<ciphertext>` — base64url of the raw AES-CBC ciphertext, PKCS#7 padded.
- `<tag>` — base64url of the 32-byte HMAC-SHA256 tag.

All four fields are separated by `.`. Whitespace around the whole envelope is
ignored; whitespace *inside* the base64 fields is rejected so corruption fails
loudly rather than decrypting to something wrong.

### Header

Canonical JSON: fixed key order, no spaces, absent optional fields omitted
entirely (never `null`). The exact serialized bytes are the MAC input, so any
re-serialization must reproduce them byte for byte.

```jsonc
{
  "v": 2,                        // format version
  "alg": "AES-CBC-HMAC-SHA256",  // the composition, not a bare cipher name
  "cipher": "AES-256-CBC",       // AES-128-CBC | AES-192-CBC | AES-256-CBC
  "kdf": "HKDF-SHA256",          // or "PBKDF2-SHA256-HKDF-SHA256"
  "p2c": 600000,                 // PBKDF2 only: iteration count
  "salt": "...",                 // base64url, 16..64 bytes
  "iv": "...",                   // base64url, exactly 16 bytes
  "aad": "...",                  // base64url, may be empty (encodes as "")
  "kid": "alice",                // optional: key identifier
  "ts": 1730000000               // optional: creation time, unix seconds
}
```

## Key schedule

Two keys, never one:

```
encKey = HKDF-SHA256(ikm = masterKey, salt = salt, info = "cmsg v2 enc"   || cipher, L = keyBytes(cipher))
macKey = HKDF-SHA256(ikm = masterKey, salt = salt, info = "cmsg v2 mac"   || cipher, L = 32)
```

where `keyBytes` is 16/24/32 for AES-128/192/256.

The `masterKey` is either:

- a raw 16/24/32-byte key supplied by the caller (`kdf = HKDF-SHA256`), or
- `PBKDF2-HMAC-SHA256(passphrase, salt, p2c, 32)` (`kdf = PBKDF2-...`).

Separate `info` labels are mandatory: sharing one key between CBC and HMAC is a
known construction hazard, and distinct labels make the two outputs independent
even though both derive from the same secret.

## Tag

```
tag = HMAC-SHA256(macKey, headerBytes || ciphertext)
```

where `headerBytes` are the exact ASCII bytes of the canonical header JSON.
Truncation is not used: the full 32 bytes are stored.

## Encrypt

1. Validate the plaintext size and exactly one of key / passphrase.
2. `salt` ← 16 random bytes. `iv` ← 16 random bytes. Both fresh per message.
3. Derive `masterKey` (PBKDF2 if a passphrase was given).
4. Derive `encKey`, `macKey` with HKDF over the salt.
5. `ciphertext = AES-CBC(encKey, iv, PKCS7(plaintext))`.
6. Serialize the header, compute the tag over `header || ciphertext`.
7. Emit `CMSG1.header.ciphertext.tag`.

## Decrypt

1. Strict structural parse; reject an unknown magic, version, algorithm, cipher
   or KDF rather than guessing.
2. Bound every attacker-controlled parameter *before* doing work: salt length,
   IV length, `p2c` range, envelope length, ciphertext block alignment.
3. Derive `masterKey` and the two subkeys. Refuse a KDF/cipher mismatch (a key
   file against a passphrase-sealed message, or the reverse) with a specific
   error instead of a generic failure.
4. **Verify the tag first**, in constant time. On mismatch, stop: return
   `INTEGRITY_FAILURE`. Never touch the padding before this point, so a padding
   error can never be used as an oracle.
5. Decrypt, then unpad strictly (every padding byte checked).
6. Optionally enforce `expectAad` and `maxAgeSeconds`.

## Design rules and the reason for each

| Rule | Reason |
| --- | --- |
| Random IV per message | Fixes the site's biggest leak: equal plaintexts no longer produce equal ciphertext. |
| Encrypt-then-MAC | Detects any modification, including to the header. |
| MAC over the header bytes, not re-serialized fields | Rules out parser-differential attacks where two encodings of the same header disagree. |
| Separate enc and MAC keys | A CBC padding oracle cannot be pivoted into forgery. |
| Tag checked before unpadding | No padding oracle exists in the failure path. |
| Constant-time comparison | No timing side channel on the tag. |
| Per-message salt | PBKDF2 output is unique per message; precomputation is not reusable. |
| `p2c` bounded on read | A hostile header cannot make decrypt run for years (CPU-exhaustion DoS). |
| Cipher/length fields bounded on read | A hostile header cannot cause unbounded allocation. |
| AAD supported | A caller can bind context (sender, recipient, purpose, sequence number) that is authenticated but not encrypted. |
| `ts` optional and authenticated | Freshness checking is possible without making it mandatory; a forged timestamp breaks the tag. |
| Strict base64 | Corruption is an error, not silent garbage. |

## What this format does **not** do

Stated explicitly so nobody assumes more than is delivered:

- **No forward secrecy.** One long-term key compromise decrypts every message
  ever sent with it. There is no per-message ephemeral key exchange.
- **No sender authentication for groups.** HMAC proves possession of the shared
  key. Any holder can produce a valid message, so it cannot distinguish
  "alice sent this" from "someone with alice's key sent this". For that you need
  signatures or a separate asymmetric layer.
- **No metadata hiding.** Ciphertext length reveals approximate plaintext
  length. `kid` and `ts` are visible in the header (they are authenticated, not
  encrypted).
- **No key rotation or revocation.** The `kid` field lets you *label* keys; it
  does not implement a trust policy.
- **No compression, no chunking.** Messages are bounded at 64 MiB.
- **Not a substitute for a mature protocol.** For protecting traffic between
  parties over a network, use TLS/Noise/Signal — they solve freshness,
  identity and forward secrecy, which this deliberately does not.

## Versioning

`v` in the header and the `CMSG1` magic are separate knobs:

- A change that existing readers can still handle correctly (new optional
  header field that they already ignore-and-authenticate) keeps `v = 2`.
- A change that requires new logic (new cipher, new KDF, changed MAC scope) must
  bump `v` and the magic, so old readers reject it as `UNSUPPORTED_VERSION`
  rather than misinterpreting it.

Readers must fail closed on anything they do not understand. Guessing is how
formats become insecure over time.
