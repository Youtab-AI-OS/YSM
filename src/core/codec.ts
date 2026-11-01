/**
 * Byte / string / base64 primitives shared by both envelopes.
 *
 * All boundaries are explicit: UTF-8 is used for text, base64 is strict on
 * decode, and constant-time comparison is used for every tag check.
 */

import { timingSafeEqual } from 'node:crypto';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

/** UTF-8 encode a string. */
export function utf8Encode(s: string): Uint8Array {
  return encoder.encode(s);
}

/** UTF-8 decode bytes. Invalid sequences become U+FFFD (never throws). */
export function utf8Decode(b: Uint8Array): string {
  return decoder.decode(b);
}

/** Strict base64 encode (standard alphabet, padded). */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

/**
 * Strict base64 decode. Whitespace is rejected rather than skipped so that a
 * corrupted envelope fails loudly instead of decrypting to something wrong.
 */
export function fromBase64(text: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new Error('not valid base64 (unexpected character or length)');
  }
  const buf = Buffer.from(text, 'base64');
  // Round-trip check catches non-canonical padding / trailing bits.
  if (buf.toString('base64') !== text) {
    throw new Error('not canonical base64');
  }
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/** Standard base64 with whitespace tolerated (used by the legacy decoder). */
export function fromBase64Lenient(text: string): Uint8Array {
  const stripped = text.replace(/\s+/g, '');
  const buf = Buffer.from(stripped, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/** Base64url without padding (used for envelope wrapper fields, not for ciphertext). */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Decode unpadded base64url. */
export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not valid base64url');
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const buf = Buffer.from(padded, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/** Plain (non-secret) hex helpers for digests and fingerprints. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}

/** Parse hex, requiring an even number of valid digits. */
export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error('not valid hex');
  }
  return new Uint8Array(Buffer.from(text, 'hex'));
}

/** Concatenate byte arrays. */
export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time equality for same-length byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Mirror of PHP's default `trim()` on a byte string before UTF-8 decoding.
 * PHP trim strips " \t\n\r\0\x0B" from both ends; this is applied to the
 * decrypted *bytes* so multi-byte characters are never damaged.
 */
const PHP_TRIM = new Set([0x20, 0x09, 0x0a, 0x0d, 0x00, 0x0b]);

export function phpTrimBytes(bytes: Uint8Array): Uint8Array {
  let start = 0;
  let end = bytes.length;
  while (start < end && PHP_TRIM.has(bytes[start]!)) start++;
  while (end > start && PHP_TRIM.has(bytes[end - 1]!)) end--;
  return bytes.subarray(start, end);
}
