/**
 * Field-level encryption for stored records.
 *
 * Every user-data column is encrypted with AES-256-GCM under a subkey derived
 * from the vault key and bound to that column's context. Moving a ciphertext from
 * one column to another therefore fails to decrypt, instead of silently becoming
 * a valid value in the wrong place.
 *
 * This is application-layer encryption, not SQLCipher. Queries operate on
 * ciphertext, so there is no searchable index over message text, and an attacker
 * reading the raw file sees ciphertext plus structural metadata (row counts,
 * approximate sizes, insert timing). That trade is stated in docs/ARCHITECTURE.md
 * rather than blurred.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface VaultCipher {
  /** Encrypt a UTF-8 string into a storable blob (nonce || ciphertext || tag). */
  encryptText(plaintext: string, context: string): Uint8Array;
  /** Decrypt such a blob back to a string. Throws on failure. */
  decryptText(blob: Uint8Array, context: string): string;
  /** Encrypt raw bytes. */
  encryptBytes(plaintext: Uint8Array, context: string): Uint8Array;
  /** Decrypt raw bytes. */
  decryptBytes(blob: Uint8Array, context: string): Uint8Array;
}

const NONCE_BYTES = 12;

export function createVaultCipher(vaultKey: Uint8Array): VaultCipher {
  if (vaultKey.length !== 32) throw new RangeError('vault key must be 32 bytes');

  const subkey = (context: string): Uint8Array =>
    hkdf(sha256, vaultKey, new Uint8Array(0), new TextEncoder().encode(`ysm/v1/field:${context}`), 32);

  const enc = (data: Uint8Array, context: string): Uint8Array => {
    const nonce = new Uint8Array(NONCE_BYTES);
    globalThis.crypto.getRandomValues(nonce);
    // The context is also authenticated as AAD, so tampering with it is detected.
    const ct = gcm(subkey(context), nonce, new TextEncoder().encode(context)).encrypt(data);
    const out = new Uint8Array(NONCE_BYTES + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_BYTES);
    return out;
  };

  const dec = (blob: Uint8Array, context: string): Uint8Array => {
    if (blob.length < NONCE_BYTES + 16) throw new Error('ciphertext is too short');
    const nonce = blob.subarray(0, NONCE_BYTES);
    const ct = blob.subarray(NONCE_BYTES);
    return gcm(subkey(context), nonce, new TextEncoder().encode(context)).decrypt(ct);
  };

  return {
    encryptText: (p, c) => enc(new TextEncoder().encode(p), c),
    decryptText: (b, c) => new TextDecoder().decode(dec(toBytes(b), c)),
    encryptBytes: (p, c) => enc(p, c),
    decryptBytes: (b, c) => dec(toBytes(b), c),
  };
}

/**
 * Coerce an engine value to Uint8Array.
 *
 * Engines disagree on BLOB representation, so normalising here keeps every
 * consumer free of platform branches.
 */
export function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value as number[]);
  if (typeof value === 'string') {
    const out = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i++) out[i] = value.charCodeAt(i) & 0xff;
    return out;
  }
  throw new TypeError('expected a BLOB column, got a different type');
}
