# Decisions and known hazards

Short records of choices that are not obvious from the code, and of traps that
cost real time. Future readers should not have to rediscover these.

## D1 — Write our own AES instead of using Web Crypto or OpenSSL cipher APIs

**Decision.** `src/aes/block.ts` is a from-scratch FIPS-197 implementation.

**Why.** AES-192 is not available through the Web Crypto API in several
Chromium builds, which is precisely the reason the reference site wrote its own
too. Beyond that, byte-exact compatibility with a *specific* scheme (fixed IV,
zero-padded key, CBC, PKCS#7) is easier to prove against a block cipher we
control than to configure correctly on a platform API whose defaults differ per
version. Node's `aes-*-cbc` would have worked here, but the browser-parity
argument is the deciding one, and the block-level primitives are needed anyway.

**Cost.** We own the correctness. Mitigated by FIPS-197 known-answer tests plus
a 200-case random cross-check against OpenSSL in `test/aes.test.mjs`.

## D2 — Node's `crypto` module is used for SHA-256/HMAC/HKDF/PBKDF2

**Decision.** Hash primitives come from `node:crypto`. Everything with a design
decision (key derivation layout, envelope structure, MAC scope, masking) is
ours.

**Why.** SHA-256 has no practical weakness and is not the thing being reverse
engineered. Reimplementing it would add risk, not confidence. The boundary is
deliberate: primitives from the platform, construction from this repository.

## D3 — Two formats, not one

**Decision.** Ship the aesencryption.net-compatible scheme *and* a hardened v2
envelope, as separate entry points.

**Why.** Compatibility and safety are different requirements. Silently
"improving" the compatible path would break the only reason to have it. Silently
using it for real messages would be unsafe. Making them explicit and separately
named means the caller makes an informed choice.

**Cost.** Two code paths to maintain. Bounded: the legacy path is a thin wrapper
over the same CBC core, and the tests pin its exact output.

## D4 — Authenticate before unpad

**Decision.** `openEnvelope` verifies the HMAC over `header || ciphertext` before
the ciphertext is unpadded, and returns a distinct code for a padding failure
that can only occur on an already-authentic message.

**Why.** Checking padding first creates a padding oracle. Ordering the checks
here means the only observable failure for an attacker who does not hold the key
is `INTEGRITY_FAILURE`, with no information about plaintext.

## D5 — Fail closed on unknown format features

**Decision.** An unknown magic, `v`, `alg`, `cipher` or `kdf` is a hard error.
Optional fields we do not recognise are still authenticated (they are inside the
MAC'd header bytes) but a *new required* semantic must bump `v`.

**Why.** Lenient parsing is how crypto formats rot. A reader that guesses turns
a future downgrade into a vulnerability.

## D6 — Reject rather than repair malformed input

**Decision.** Bad base64, bad padding, wrong parameter lengths and
AES-CBC-incompatible key sizes all raise errors. The legacy decoder tolerates
whitespace in base64 (because humans paste it) but the v2 decoder does not.

**Why.** Silent repair hides corruption. For a message system, "this did not
decrypt" is a strictly better outcome than "this decrypted to something".

## H1 — `Buffer.prototype.slice()` returns a view, not a copy

**Symptom.** The AES implementation passed every round-trip test and reproduced
all seven site vectors, while producing ciphertext no other AES implementation
agrees with.

**Cause.** `const t = s.slice()` was intended to snapshot the state before a
mutating pass. For a plain `Uint8Array`, `slice()` copies. For a Node `Buffer`
(which the tests and the legacy path pass in), `slice()` returns a **view over
the same memory**, so `shiftRows` was reading bytes it had already overwritten.
The result was still a deterministic permutation, so it round-tripped perfectly
against its own inverse.

**Fix.** `copyBytes()` in `src/aes/block.ts` — an explicit `new Uint8Array` +
`set`. Used for the state, the key schedule seed and the CBC chaining block.
Callers are normalised on entry so a `Buffer` cannot smuggle aliasing into the
cipher.

**Detection lesson.** Round-trip tests and same-source vectors cannot catch a
wrong-but-self-consistent cipher. The only thing that did was diffing against an
independent implementation (OpenSSL) on random inputs. That check stays in the
suite, and `test/aes.test.mjs` adds a regression test that passes both a Buffer
and a Uint8Array and asserts identical output plus untouched caller buffers.

**Related trap.** `Buffer.from(uint8array)` produces a *Buffer*, so a helper
that "converts on the way in" re-introduces the problem. `copyBytes` uses
`new Uint8Array` deliberately.

## H2 — Don't hand-transcribe reference vectors from memory

**Symptom.** Repeated chases down the wrong function because the "expected"
FIPS-197 intermediate values I wrote from memory were wrong, while the code was
right (and vice versa).

**Fix.** Never assert a value that was not produced by an executable source of
truth. `test/` derives every expected value from OpenSSL or from the live site,
not from recall. Where a literal appears (FIPS-197 Appendix C, site vectors) it
was pasted from the captured output in `docs/vectors.json`.

## H3 — `createCipheriv` with `setAutoPadding(false)`

**Symptom.** A test compared our output against OpenSSL and failed, with OpenSSL
returning one extra block.

**Cause.** The test padded by hand *and* left OpenSSL's autopadding enabled, so
the reference got padded twice.

**Fix.** When you pad manually, always call `setAutoPadding(false)` on the
reference side.
