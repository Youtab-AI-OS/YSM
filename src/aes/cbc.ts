/**
 * Cipher-block-chaining mode over the pure AES block cipher, plus PKCS#7 padding.
 *
 * Deliberately implemented directly (not via a platform CBC API) so that the
 * exact byte sequence is defined by this repository. Used both by the legacy
 * aesencryption.net-compatible path and by the hardened v2 envelope.
 */

import {
  BLOCK_SIZE,
  copyBytes,
  decryptBlock,
  encryptBlock,
  expandKey,
  type KeySchedule,
} from './block.js';

/** PKCS#7 pad: always adds 1..16 bytes, so full blocks gain a whole pad block. */
export function pkcs7Pad(data: Uint8Array): Uint8Array {
  const pad = BLOCK_SIZE - (data.length % BLOCK_SIZE); // 1..16
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

/**
 * Strict PKCS#7 unpad. Every padding byte is verified; a malformed pad throws
 * rather than silently truncating. Placeholder for a richer error later.
 */
export function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new PadError(`invalid ciphertext length ${data.length}`);
  }
  const pad = data[data.length - 1]!;
  if (pad < 1 || pad > BLOCK_SIZE) {
    throw new PadError(`invalid padding byte 0x${pad.toString(16)}`);
  }
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) {
      throw new PadError('inconsistent padding bytes');
    }
  }
  return data.subarray(0, data.length - pad);
}

/** Raised when PKCS#7 padding is not well formed (usually a wrong key). */
export class PadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PadError';
  }
}

function assertIv(iv: Uint8Array): void {
  if (iv.length !== BLOCK_SIZE) {
    throw new RangeError(`IV must be ${BLOCK_SIZE} bytes (got ${iv.length}).`);
  }
}

/** CBC encrypt with PKCS#7 padding. Output length is a multiple of 16. */
export function cbcEncrypt(plain: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  assertIv(iv);
  const ks: KeySchedule = expandKey(key);
  const data = pkcs7Pad(plain);
  const out = new Uint8Array(data.length);
  let prev: Uint8Array = copyBytes(iv);
  const x = new Uint8Array(BLOCK_SIZE);
  for (let off = 0; off < data.length; off += BLOCK_SIZE) {
    for (let i = 0; i < BLOCK_SIZE; i++) x[i] = data[off + i]! ^ prev[i]!;
    const enc = encryptBlock(x, ks);
    out.set(enc, off);
    prev = enc;
  }
  return out;
}

/** CBC decrypt, then strict PKCS#7 unpad. Throws PadError on a bad pad. */
export function cbcDecrypt(cipher: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  assertIv(iv);
  if (cipher.length === 0 || cipher.length % BLOCK_SIZE !== 0) {
    throw new PadError(`invalid ciphertext length ${cipher.length}`);
  }
  const ks = expandKey(key);
  const out = new Uint8Array(cipher.length);
  let prev: Uint8Array = copyBytes(iv);
  for (let off = 0; off < cipher.length; off += BLOCK_SIZE) {
    const block = cipher.subarray(off, off + BLOCK_SIZE);
    const dec = decryptBlock(block, ks);
    for (let i = 0; i < BLOCK_SIZE; i++) out[off + i] = dec[i]! ^ prev[i]!;
    prev = copyBytes(block);
  }
  return pkcs7Unpad(out);
}

/**
 * CBC decrypt without unpadding. Used by the v2 envelope, which must read the
 * encrypted payload before the MAC over the ciphertext is verified.
 */
export function cbcDecryptRaw(cipher: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  assertIv(iv);
  if (cipher.length === 0 || cipher.length % BLOCK_SIZE !== 0) {
    throw new RangeError(`ciphertext length must be a positive multiple of 16 (got ${cipher.length}).`);
  }
  const ks = expandKey(key);
  const out = new Uint8Array(cipher.length);
  let prev: Uint8Array = copyBytes(iv);
  for (let off = 0; off < cipher.length; off += BLOCK_SIZE) {
    const block = cipher.subarray(off, off + BLOCK_SIZE);
    const dec = decryptBlock(block, ks);
    for (let i = 0; i < BLOCK_SIZE; i++) out[off + i] = dec[i]! ^ prev[i]!;
    prev = copyBytes(block);
  }
  return out;
}
