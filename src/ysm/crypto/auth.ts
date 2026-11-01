/**
 * Account authentication: password → key-encryption-key, and TOTP.
 *
 * The security model:
 *
 *   password + salt --Argon2id--> KEK
 *   KEK --AES-256-GCM--> unwraps the random 32-byte vault key
 *   vault key encrypts every record written to the database
 *
 * Consequences that matter:
 *   - The database file alone is useless without the password.
 *   - The password is never stored, only a verifier derived independently.
 *   - TOTP is checked BEFORE the vault key is released, so a stolen password
 *     does not open the vault.
 *   - Changing the password re-wraps the vault key; it does not re-encrypt data.
 *
 * Argon2id parameters are recorded per-account so they can be raised later
 * without breaking old accounts.
 */

import { argon2id } from '@noble/hashes/argon2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { random } from './identity.js';
import { equalBytes } from './envelope.js';

/**
 * Argon2id parameters.
 *
 * 64 MiB / time=3 / p=1 is the OWASP-recommended baseline for Argon2id at
 * interactive latency. It is recorded in the account record so it can be
 * increased later; existing accounts keep working with their stored values.
 *
 * Bounds are enforced on read: an attacker who can write the account file must
 * not be able to set memory=8 GiB and turn unlock into an out-of-memory crash.
 */
export interface ArgonParams {
  readonly memoryKiB: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

export const DEFAULT_ARGON: ArgonParams = { memoryKiB: 65536, timeCost: 3, parallelism: 1 };
export const MIN_ARGON_MEMORY_KIB = 8192;
export const MAX_ARGON_MEMORY_KIB = 1024 * 1024;
export const MIN_ARGON_TIME = 1;
export const MAX_ARGON_TIME = 20;
export const MIN_ARGON_PARALLELISM = 1;
export const MAX_ARGON_PARALLELISM = 8;

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 1024;

/** Validate stored Argon2 parameters before using them. */
export function validateArgonParams(p: ArgonParams): void {
  if (!Number.isInteger(p.memoryKiB) || p.memoryKiB < MIN_ARGON_MEMORY_KIB || p.memoryKiB > MAX_ARGON_MEMORY_KIB) {
    throw new RangeError(`argon2 memoryKiB out of range [${MIN_ARGON_MEMORY_KIB}, ${MAX_ARGON_MEMORY_KIB}]: ${p.memoryKiB}`);
  }
  if (!Number.isInteger(p.timeCost) || p.timeCost < MIN_ARGON_TIME || p.timeCost > MAX_ARGON_TIME) {
    throw new RangeError(`argon2 timeCost out of range: ${p.timeCost}`);
  }
  if (!Number.isInteger(p.parallelism) || p.parallelism < MIN_ARGON_PARALLELISM || p.parallelism > MAX_ARGON_PARALLELISM) {
    throw new RangeError(`argon2 parallelism out of range: ${p.parallelism}`);
  }
}

/**
 * Derive the key-encryption-key from a password.
 *
 * `domain` separates the KEK from the password *verifier* so that even if the
 * verifier leaks, it cannot be used as the KEK or vice versa.
 */
export function deriveKeyEncryptionKey(
  password: string,
  salt: Uint8Array,
  params: ArgonParams = DEFAULT_ARGON,
): Uint8Array {
  validateArgonParams(params);
  const bytes = new TextEncoder().encode(password);
  return argon2id(bytes, salt, {
    t: params.timeCost,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: 32,
  });
}

/**
 * A separate verifier used only to detect a wrong password.
 *
 * Why a separate value: if we used the KEK itself as the check, a wrong password
 * would be indistinguishable from a corrupted wrapped key. An independent
 * verifier gives a clean "wrong password" signal without weakening the KEK.
 */
export function deriveVerifier(password: string, salt: Uint8Array, params: ArgonParams = DEFAULT_ARGON): Uint8Array {
  validateArgonParams(params);
  const bytes = new TextEncoder().encode(password);
  // Domain-separated by hashing a distinct info string into the salt input.
  const info = new TextEncoder().encode('ysm/v1/verify');
  const mixed = new Uint8Array(salt.length + info.length);
  mixed.set(salt, 0);
  mixed.set(info, salt.length);
  return argon2id(bytes, mixed, {
    t: params.timeCost,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: 32,
  });
}

// ---------------------------------------------------------------------------
// Password strength
// ---------------------------------------------------------------------------

/**
 * A deliberately small check, not a substitute for an entropy meter.
 *
 * We enforce a length floor and reject the handful of passwords that appear at
 * the top of every breach list. Claiming more than this (e.g. estimating
 * "entropy" from character classes) is guesswork dressed as security, so we do
 * not do it.
 */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456789012', '1234567890123',
  'qwertyuiop12', 'qwertyuiop123', 'letmein12345', 'iloveyou1234',
  'welcome12345', 'admin123456', 'abc123456789', 'passwordpassword',
  '111111111111', '000000000000', 'qwerty123456', 'monkey123456',
  'dragon123456', 'football1234', 'baseball1234', 'sunshine1234',
]);

export type PasswordCheck =
  | { ok: true }
  | { ok: false; code: 'TOO_SHORT' | 'TOO_LONG' | 'COMMON' | 'REPEATED' | 'SAME_CHARACTER'; message: string };

export function checkPasswordStrength(password: string): PasswordCheck {
  const chars = [...password];
  if (chars.length < MIN_PASSWORD_LENGTH) {
    return {
      ok: false,
      code: 'TOO_SHORT',
      message: `password must be at least ${MIN_PASSWORD_LENGTH} characters (got ${chars.length})`,
    };
  }
  if (chars.length > MAX_PASSWORD_LENGTH) {
    return { ok: false, code: 'TOO_LONG', message: `password must be at most ${MAX_PASSWORD_LENGTH} characters` };
  }
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) {
    return { ok: false, code: 'COMMON', message: 'this password appears in common-password lists; choose another' };
  }
  if (new Set(chars).size === 1) {
    return { ok: false, code: 'SAME_CHARACTER', message: 'password cannot be a single repeated character' };
  }
  // Reject "ababababababab" style patterns: at most two distinct values in the
  // whole string is almost always a pattern, not a secret.
  if (new Set(chars).size <= 2 && chars.length < 24) {
    return { ok: false, code: 'REPEATED', message: 'password looks like a repeated pattern; choose another' };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Vault key wrapping
// ---------------------------------------------------------------------------

export interface WrappedKey {
  /** ciphertext || tag of the 32-byte vault key. */
  readonly ciphertext: string;
  readonly nonce: string;
}

/** Wrap (encrypt) the vault key under the KEK. */
export function wrapVaultKey(vaultKey: Uint8Array, kek: Uint8Array): WrappedKey {
  if (vaultKey.length !== 32) throw new RangeError('vault key must be 32 bytes');
  if (kek.length !== 32) throw new RangeError('KEK must be 32 bytes');
  const nonce = random(12);
  const ct = gcm(kek, nonce, new TextEncoder().encode('ysm/v1/wrap')).encrypt(vaultKey);
  return {
    ciphertext: Buffer.from(ct).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
  };
}

/** Unwrap the vault key. Returns null on a wrong KEK (AEAD tag failure). */
export function unwrapVaultKey(wrapped: WrappedKey, kek: Uint8Array): Uint8Array | null {
  try {
    const nonce = new Uint8Array(Buffer.from(wrapped.nonce, 'base64'));
    const ct = new Uint8Array(Buffer.from(wrapped.ciphertext, 'base64'));
    if (nonce.length !== 12 || ct.length !== 32 + 16) return null;
    const key = gcm(kek, nonce, new TextEncoder().encode('ysm/v1/wrap')).decrypt(ct);
    return key.length === 32 ? new Uint8Array(key) : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

export const TOTP_DIGITS = 6;
export const TOTP_PERIOD_SECONDS = 30;
/** Accept the adjacent windows to tolerate clock skew, as every authenticator does. */
export const TOTP_WINDOW = 1;
const TOTP_SECRET_BYTES = 20; // RFC 4226 recommends 160 bits

/** Base32 (RFC 4648) without padding, as authenticator apps expect. */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Generate a new TOTP secret. */
export function generateTotpSecret(): Uint8Array {
  return random(TOTP_SECRET_BYTES);
}

/** Build the `otpauth://` URI an authenticator app scans. */
export function totpUri(secret: Uint8Array, accountName: string, issuer = 'YSM'): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** HOTP value for a counter (RFC 4226). */
export function hotp(secret: Uint8Array, counter: number): string {
  const buf = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const mac = hmac(sha1, secret, buf);
  const offset = mac[mac.length - 1]! & 0x0f;
  const code =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);
  return String(code % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/** TOTP value for a given time. */
export function totp(secret: Uint8Array, unixSeconds: number): string {
  return hotp(secret, Math.floor(unixSeconds / TOTP_PERIOD_SECONDS));
}

/**
 * Verify a TOTP code, tolerating ±TOTP_WINDOW periods.
 *
 * Returns the matched counter so the caller can persist it and reject replays:
 * without that, a code observed once stays valid for its whole window.
 */
export function verifyTotp(
  secret: Uint8Array,
  code: string,
  unixSeconds: number,
  lastUsedCounter?: number,
): { ok: true; counter: number } | { ok: false; reason: 'FORMAT' | 'MISMATCH' | 'REPLAY' } {
  const clean = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return { ok: false, reason: 'FORMAT' };

  const current = Math.floor(unixSeconds / TOTP_PERIOD_SECONDS);
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    const counter = current + delta;
    if (counter < 0) continue;
    const expected = hotp(secret, counter);
    // Constant-time compare via HMAC of both, so timing does not reveal the
    // position of the first differing digit.
    if (equalBytes(new TextEncoder().encode(expected), new TextEncoder().encode(clean))) {
      if (lastUsedCounter !== undefined && counter <= lastUsedCounter) {
        return { ok: false, reason: 'REPLAY' };
      }
      return { ok: true, counter };
    }
  }
  return { ok: false, reason: 'MISMATCH' };
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

export const RECOVERY_CODE_COUNT = 10;
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/0/1

/**
 * Generate single-use recovery codes.
 *
 * Each is 20 characters over a 32-symbol alphabet (100 bits), displayed in
 * groups of 5. The plaintext codes are shown to the user exactly once; only
 * their hashes are stored.
 */
export function generateRecoveryCodes(): { plaintext: string[]; hashes: string[] } {
  const plaintext: string[] = [];
  const hashes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const raw = random(20);
    let code = '';
    for (const byte of raw) code += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
    const formatted = code.match(/.{5}/g)!.join('-');
    plaintext.push(formatted);
    hashes.push(hashRecoveryCode(formatted));
  }
  return { plaintext, hashes };
}

/** Hash a recovery code for storage. */
export function hashRecoveryCode(code: string): string {
  const normalised = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const salt = new TextEncoder().encode('ysm/v1/recovery');
  const digest = new Uint8Array(salt.length + normalised.length);
  digest.set(salt, 0);
  digest.set(new TextEncoder().encode(normalised), salt.length);
  return Buffer.from(sha256(digest)).toString('hex');
}
