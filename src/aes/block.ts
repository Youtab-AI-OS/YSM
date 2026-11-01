/**
 * Pure TypeScript AES block cipher (FIPS-197), 128 / 192 / 256-bit keys.
 *
 * Written from the standard rather than delegated to Web Crypto because:
 *  - AES-192 is not available in the Web Crypto API on several Chromium builds,
 *  - a byte-exact, auditable implementation is required for compatibility with
 *    the aesencryption.net reference tool (see docs/SPEC.md),
 *  - block-level access is needed for CBC plus the authenticated mode.
 *
 * State layout follows FIPS-197: 16 bytes, column-major.
 *   state[r + 4c]  where r = row, c = column
 */

/** Multiplication by x (0x02) in GF(2^8), reducing by x^8+x^4+x^3+x+1. */
function xtime(a: number): number {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
}

/** EXP/LOG tables for GF(2^8) with generator 0x03. */
const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);
{
  let p = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = p;
    LOG[p] = i;
    p = (p ^ xtime(p)) & 0xff; // p *= 3
  }
  EXP[255] = EXP[0]!;
}

/** Field multiplication. */
function gmul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a]! + LOG[b]!) % 255]!;
}

/** S-box and inverse S-box, derived from the field so no table is hand-copied. */
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
{
  for (let i = 0; i < 256; i++) {
    const inv = i === 0 ? 0 : EXP[(255 - LOG[i]!) % 255]!;
    let x = inv;
    let s = inv;
    for (let t = 0; t < 4; t++) {
      s = ((s << 1) | (s >> 7)) & 0xff; // rotate left by 1
      x ^= s;
    }
    x = (x ^ 0x63) & 0xff;
    SBOX[i] = x;
    INV_SBOX[x] = i;
  }
}

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

/** Expanded key schedule: 4*(Nr+1) words of 4 bytes. */
export interface KeySchedule {
  readonly w: Uint8Array; // flat: word index * 4 + byte
  readonly Nr: number; // number of rounds
  readonly keyBits: 128 | 192 | 256;
}

/**
 * Copy bytes into a plain Uint8Array.
 *
 * Critical: `Buffer.prototype.slice()` returns a *view* over the same memory,
 * unlike `Uint8Array.prototype.slice()`. Code that mutates a "copy" of caller
 * data would otherwise corrupt the caller's buffer whenever a Node Buffer is
 * passed in — and a Buffer aliased into the AES state produces silently wrong
 * ciphertext that still round-trips against itself. Every internal routine that
 * copies state or key material goes through this, and callers are normalised
 * on entry so the invariant holds regardless of what they hand us.
 */
export function copyBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/** Copy the 16-byte AES state. */
function copyState(src: Uint8Array): Uint8Array {
  return copyBytes(src);
}

export type AesKeyBits = 128 | 192 | 256;

export const BLOCK_SIZE = 16;

const VALID_KEY_BITS: ReadonlySet<number> = new Set([128, 192, 256]);

/** Validate a key length in bits, returning the narrowed literal type. */
export function assertKeyBits(bits: number): AesKeyBits {
  if (!VALID_KEY_BITS.has(bits)) {
    throw new RangeError(`AES key size must be 128, 192 or 256 bits (got ${bits}).`);
  }
  return bits as AesKeyBits;
}

function keyExpansion(key: Uint8Array): KeySchedule {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new RangeError(`AES key must be 16, 24 or 32 bytes (got ${key.length}).`);
  }
  const Nk = key.length / 4;
  const Nr = Nk + 6;
  const totalWords = 4 * (Nr + 1);
  const w = new Uint8Array(totalWords * 4);

  // Copy rather than alias: a Node Buffer would otherwise share memory with
  // the caller's key buffer and a later mutation there would change the schedule.
  w.set(copyBytes(key), 0);

  const temp = new Uint8Array(4);
  for (let i = Nk; i < totalWords; i++) {
    temp.set(w.subarray((i - 1) * 4, i * 4));
    if (i % Nk === 0) {
      // RotWord
      const b0 = temp[0]!;
      temp[0] = temp[1]!;
      temp[1] = temp[2]!;
      temp[2] = temp[3]!;
      temp[3] = b0;
      // SubWord
      temp[0] = SBOX[temp[0]!]!;
      temp[1] = SBOX[temp[1]!]!;
      temp[2] = SBOX[temp[2]!]!;
      temp[3] = SBOX[temp[3]!]!;
      // Rcon
      temp[0] = temp[0]! ^ RCON[i / Nk - 1]!;
    } else if (Nk > 6 && i % Nk === 4) {
      // SubWord (AES-256 only)
      temp[0] = SBOX[temp[0]!]!;
      temp[1] = SBOX[temp[1]!]!;
      temp[2] = SBOX[temp[2]!]!;
      temp[3] = SBOX[temp[3]!]!;
    }
    const prev = (i - Nk) * 4;
    const cur = i * 4;
    w[cur] = w[prev]! ^ temp[0]!;
    w[cur + 1] = w[prev + 1]! ^ temp[1]!;
    w[cur + 2] = w[prev + 2]! ^ temp[2]!;
    w[cur + 3] = w[prev + 3]! ^ temp[3]!;
  }

  return { w, Nr, keyBits: (key.length * 8) as AesKeyBits };
}

/** Expand a raw key into a reusable schedule. */
export function expandKey(key: Uint8Array): KeySchedule {
  return keyExpansion(key);
}

function addRoundKey(s: Uint8Array, ks: KeySchedule, round: number): void {
  const base = round * 16;
  for (let i = 0; i < 16; i++) s[i] = s[i]! ^ ks.w[base + i]!;
}

function subBytes(s: Uint8Array): void {
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]!]!;
}

function invSubBytes(s: Uint8Array): void {
  for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]!]!;
}

/**
 * ShiftRows: row r is rotated LEFT by r positions (r = 1, 2, 3).
 *
 * State layout is column-major, matching addRoundKey / subBytes / mixColumns:
 * byte (row r, column c) lives at index `c * 4 + r`. Row r is the strided
 * sequence [r, 4+r, 8+r, 12+r].
 *
 * Rotating row r left by r means the new byte at column c is the old byte at
 * column (c + r) mod 4 — i.e. `t[((c + r) mod 4) * 4 + r]`. Note the shifted
 * term multiplies by 4 to select a *column*; writing it without the stride
 * selects a neighbouring row instead and silently yields a non-standard cipher.
 *
 * A wrong index here still round-trips against its own inverse, so it is pinned
 * against OpenSSL and FIPS-197 in the test suite rather than left to review.
 */
function shiftRows(s: Uint8Array): void {
  const t = copyState(s);
  for (let row = 1; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      s[col * 4 + row] = t[((col + row) % 4) * 4 + row]!;
    }
  }
}

/** Inverse ShiftRows: row r is rotated RIGHT by r positions. */
function invShiftRows(s: Uint8Array): void {
  const t = copyState(s);
  for (let row = 1; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      s[col * 4 + row] = t[((col - row + 4) % 4) * 4 + row]!;
    }
  }
}

function mixColumns(s: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = s[i]!;
    const a1 = s[i + 1]!;
    const a2 = s[i + 2]!;
    const a3 = s[i + 3]!;
    s[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    s[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    s[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    s[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
}

function invMixColumns(s: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = s[i]!;
    const a1 = s[i + 1]!;
    const a2 = s[i + 2]!;
    const a3 = s[i + 3]!;
    s[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
    s[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
    s[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
    s[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
  }
}

/** Encrypt one 16-byte block into a new buffer. */
export function encryptBlock(block: Uint8Array, ks: KeySchedule): Uint8Array {
  if (block.length !== BLOCK_SIZE) {
    throw new RangeError(`AES block must be ${BLOCK_SIZE} bytes (got ${block.length}).`);
  }
  const s = copyState(block);
  addRoundKey(s, ks, 0);
  for (let round = 1; round < ks.Nr; round++) {
    subBytes(s);
    shiftRows(s);
    mixColumns(s);
    addRoundKey(s, ks, round);
  }
  subBytes(s);
  shiftRows(s);
  addRoundKey(s, ks, ks.Nr);
  return s;
}

/** Decrypt one 16-byte block into a new buffer. */
export function decryptBlock(block: Uint8Array, ks: KeySchedule): Uint8Array {
  if (block.length !== BLOCK_SIZE) {
    throw new RangeError(`AES block must be ${BLOCK_SIZE} bytes (got ${block.length}).`);
  }
  const s = copyState(block);
  addRoundKey(s, ks, ks.Nr);
  for (let round = ks.Nr - 1; round >= 1; round--) {
    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, ks, round);
    invMixColumns(s);
  }
  invShiftRows(s);
  invSubBytes(s);
  addRoundKey(s, ks, 0);
  return s;
}

/** Expose tables for test vectors and diagnostics only. */
export const internals = {
  SBOX: SBOX.slice(),
  INV_SBOX: INV_SBOX.slice(),
  gmul,
  keyExpansion,
};
