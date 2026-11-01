# Reverse-engineering report: aesencryption.net

Everything below was derived from the live site and then verified against it. Where a
claim is an observation it says so; where it is an inference it is labelled.

## 1. Where the behaviour lives

The site's tool form has two code paths:

| Path | Trigger | Implementation |
| --- | --- | --- |
| In-browser | "Run in my browser" checkbox (default once JS loads) | `/js/aes-browser.js`, exposes `window.BrowserAES` |
| Server | Checkbox unchecked (no-JS fallback) | PHP `openssl_encrypt` per the published `AES` class |

Observation: `aes-browser.js` is loaded as a plain script from
`https://aesencryption.net/js/aes-browser.js`. Its header comment states it is
byte-for-byte compatible with the server path, and that it avoids Web Crypto
because Chromium does not support AES-192 there. Both paths therefore agree, and
reproducing the browser path reproduces the server path.

The submitted form posts `taInpText`, `inpKey`, `sleBlockSize` and a button
named `direction` with value `Encrypt` or `Decrypt`. When the checkbox is
checked the click handler calls `ev.preventDefault()` and never contacts the
server — the key and plaintext stay in the browser.

## 2. The algorithm, exactly

```
cipher      AES-CBC
key sizes   128, 192, 256 bit
padding     PKCS#7 (always 1..16 bytes, full block when input is a multiple of 16)
IV          fixed, 16 bytes, ASCII "12345678b0z2345n"
key         UTF-8 bytes of the password, truncated to keysize/8,
            then right-padded with 0x00 when shorter
output      standard base64 of the ciphertext (padding included, no wrapping)
decrypt     PKCS#7 unpad -> UTF-8 decode -> PHP trim() over " \t\n\r\0\x0B"
```

Observations that pin each detail:

- **The IV is a constant.** `serverIV()` returns the literal
  `"12345678b0z2345n"`. The PHP class it mirrors has a dead
  `return '1234567890123456';` before the random-IV line, and the JS was built
  from the effective behaviour rather than the dead line. The
  string is 16 characters: `12345678` + `b0z2345n`.
- **The key is not derived.** `prepareKey()` allocates a zero-filled buffer of
  `keysize/8` and copies at most that many bytes of the UTF-8 password. It is
  truncation plus zero padding, not PBKDF2, not SHA, not hashing of any kind.
  Consequence: a password shorter than the key size has effectively fewer
  entropy bits than the nominal key size, and any two passwords sharing their
  first N bytes produce the same key.
- **Trailing whitespace is trimmed on decrypt only.** `phpTrim()` strips PHP's
  default trim set. So `decrypt(encrypt(" x "))` returns `"x"` — the scheme is
  not a byte-exact round trip for leading/trailing whitespace.
- **Empty input encrypts.** The site's `run()` rejects whitespace-only text with
  "Please enter some text first." That is a UI rule, not a crypto rule; the
  cipher produces a single padding block for empty input. Our engine performs
  the encryption and leaves the UI rule to the UI.
- **AES-192 is real AES-192.** The site implements all three key sizes in pure
  JS specifically so 192 works in browsers.

The published PHP, Python, Go, Rust, Kotlin and JavaScript examples on the page
all describe the same parameters. Note the *Java* example on that page does
**not** match — it uses `AES/ECB/PKCS5Padding` with a SHA-1 derived 16-byte key.
That example is incompatible with the tool and is a documentation bug on the
site, not part of the format.

## 3. Verification method

Three independent checks, because a self-consistent implementation can still be
wrong:

1. **Known-answer vectors from the site itself.** Ten plaintext/password/key-size
   triples were run through the live `BrowserAES` and recorded in
   `docs/vectors.json`. `legacyEncrypt` must reproduce them character for
   character. This is the primary contract.
2. **OpenSSL cross-check.** The same scheme rebuilt directly on Node's OpenSSL
   bindings (manual PKCS#7, fixed IV, zero-padded key, autopadding disabled)
   must produce identical ciphertext for all three key sizes. This proves the
   scheme is plain AES-CBC and not something bespoke that merely matches its own
   inverse.
3. **Live bidirectional interop.** Ciphertext produced by this engine was fed to
   the live site's `BrowserAES.decrypt` for 256/192/128-bit keys, including
   Persian text, a 200-byte message, a 30-byte password and trailing
   whitespace. All four decrypted correctly on the site.

A note on how check 2 caught a real bug: an early version passed every
round-trip test and every site vector while producing a **non-standard cipher**,
because Node's `Buffer.prototype.slice()` returns a *view*, not a copy. The AES
state aliased the caller's buffer, so `shiftRows` read partly-written data.
Round-trip and site-vector tests both passed; only the OpenSSL cross-check
failed. See `docs/DECISIONS.md`.

## 4. Weaknesses (why this is not a message system)

These are properties of the site's scheme, not implementation defects. They are
the reason this repository has a second, hardened format.

| Weakness | Consequence |
| --- | --- |
| Fixed IV | Identical plaintext under the same key always produces identical ciphertext. Anyone who sees the ciphertext can tell whether two messages are the same, and can spot repeated blocks inside a long message. |
| No key derivation | A short or guessable password gives far less than the nominal key strength. There is no per-message salt, so precomputation is reusable across every message ever sent with that password. |
| No integrity protection | CBC is malleable. Flipping bits in ciphertext block *i* flips corresponding bits in plaintext block *i+1* predictably, and the only feedback is whether the padding check passes. Anyone who can modify the ciphertext can corrupt or partially control the decrypted message undetected. |
| Padding-oracle exposure | Decryption reports success/failure based on padding. If an attacker can observe that distinction, they can recover plaintext. |
| Trims output | Leading/trailing whitespace and NUL bytes in the plaintext are silently lost. |
| Base64 not authenticated | The encoding can be altered (whitespace, padding) without detection. |

Recommendation encoded in this repo: use `cmsg encrypt` / `cmsg decrypt` (v2) for
real messages. Use `legacy-*` only to interoperate with the site, with code or
people still running that scheme, or to recover existing ciphertext.

## 5. Artifacts

- `src/engine/legacy.ts` — the compatible implementation.
- `docs/vectors.json` — the captured site vectors.
- `test/legacy.test.mjs` — vector, OpenSSL, UTF-8, determinism and failure tests.
- `docs/SPEC.md` — the v2 format that replaces this for real use.
