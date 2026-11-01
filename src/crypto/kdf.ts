/**
 * SHA-256 / HMAC-SHA256 / HKDF-SHA256 / PBKDF2-HMAC-SHA256.
 *
 * Node's `crypto` module is used for the hash primitive only. This is a
 * deliberate trust boundary: SHA-256 has no known practical weakness and is
 * not the thing being reverse engineered. Everything with a *design* decision
 * in it (key derivation, envelope layout, MAC scope) lives in this repository.
 */

import { createHash, createHmac, pbkdf2Sync, hkdfSync, randomBytes } from 'node:crypto';

/** SHA-256 digest of arbitrary bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** HMAC-SHA256. */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', key).update(data).digest());
}

/**
 * HKDF-SHA256 (RFC 5869) extract-and-expand.
 *
 * @param ikm  input keying material (the master key)
 * @param salt optional salt; a zero-length salt is what RFC 5869 prescribes when none is given
 * @param info domain-separation label — each label yields an independent subkey
 * @param length output length in bytes (max 255*32)
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (length <= 0 || length > 255 * 32) {
    throw new RangeError(`HKDF output length must be 1..${255 * 32} bytes (got ${length}).`);
  }
  const out = new Uint8Array(hkdfSync('sha256', ikm, salt, info, length));
  return out;
}

/** Cryptographic random bytes. */
export function randomBytesOf(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(`random length must be a positive integer (got ${length}).`);
  }
  return new Uint8Array(randomBytes(length));
}

/** PBKDF2-HMAC-SHA256. Used only when the caller supplies a passphrase, not a key file. */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Uint8Array {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new RangeError('PBKDF2 iterations must be a positive integer.');
  }
  return new Uint8Array(
    pbkdf2Sync(Buffer.from(password), Buffer.from(salt), iterations, length, 'sha256'),
  );
}
