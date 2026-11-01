/**
 * The v2 message envelope: a self-describing, authenticated, versioned container.
 *
 * Wire format (text form, one line per field group):
 *
 *   CMSG1.<base64url(header)>.<base64url(ciphertext)>.<base64url(tag)>
 *
 * `CMSG1` is the literal magic+version. The header is a canonical, length-free
 * JSON object whose bytes are exactly the bytes authenticated by the MAC:
 *
 *   {
 *     "v": 2,                          envelope format version
 *     "alg": "AES-CBC-HMAC-SHA256",    composition, not a bare cipher
 *     "cipher": "AES-256-CBC",
 *     "kdf": "HKDF-SHA256" | "PBKDF2-SHA256-HKDF-SHA256",
 *     "p2c": <iterations>,             present only for PBKDF2
 *     "salt": <base64url>,             KDF salt
 *     "iv":   <base64url>,             16-byte per-message IV
 *     "aad":  <base64url>,             caller-supplied associated data
 *     "kid":  <string>,                optional recipient/key identifier
 *     "ts":   <unix seconds>,          optional creation time, authenticated
 *   }
 *
 * Design rules, and why:
 *
 *  - Encrypt-then-MAC over header || ciphertext. The MAC is computed over the
 *    exact ASCII bytes of the serialized header (so any field edit breaks it)
 *    followed by the raw ciphertext.
 *  - Encryption key and MAC key are separate, via HKDF with distinct `info`
 *    labels, so a CBC padding oracle cannot be used to forge a tag and no key
 *    is ever reused across the two primitives.
 *  - A fresh random IV per message, so equal plaintexts give different
 *    ciphertexts (fixes the legacy scheme's biggest leak).
 *  - The MAC is checked BEFORE the padding is looked at, so padding errors are
 *    only ever reported for messages that already proved authenticity.
 *  - Base64url without padding for the fields; strict decoding everywhere.
 */

import { cbcDecryptRaw, cbcEncrypt, pkcs7Unpad, PadError } from '../aes/cbc.js';
import { BLOCK_SIZE } from '../aes/block.js';
import {
  constantTimeEqual,
  concat,
  fromBase64Url,
  toBase64Url,
  utf8Decode,
  utf8Encode,
} from '../core/codec.js';
import { fail, ok, type Result } from '../core/result.js';
import { hkdfSha256, hmacSha256, pbkdf2Sha256, randomBytesOf, sha256 } from '../crypto/kdf.js';

export const MAGIC = 'CMSG1';
export const ENVELOPE_VERSION = 2;
export const ALGORITHM = 'AES-CBC-HMAC-SHA256';

export const MIN_SALT_BYTES = 16;
export const MIN_TAG_BYTES = 32;
export const MIN_PBKDF2_ITERATIONS = 100_000;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const MAX_PBKDF2_ITERATIONS = 10_000_000;

export type CipherName = 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';
export type KdfName = 'HKDF-SHA256' | 'PBKDF2-SHA256-HKDF-SHA256';

const CIPHER_KEY_BYTES: Record<CipherName, number> = {
  'AES-128-CBC': 16,
  'AES-192-CBC': 24,
  'AES-256-CBC': 32,
};

export function cipherKeyBytes(cipher: CipherName): number {
  return CIPHER_KEY_BYTES[cipher];
}

export const CIPHER_NAMES = Object.keys(CIPHER_KEY_BYTES) as CipherName[];

/** HKDF domain-separation labels. Changing these is a format break. */
const INFO_ENC = utf8Encode('cmsg v2 enc');
const INFO_MAC = utf8Encode('cmsg v2 mac');

/** Authenticated header, in the exact shape that gets serialized. */
export interface EnvelopeHeader {
  readonly v: number;
  readonly alg: string;
  readonly cipher: CipherName;
  readonly kdf: KdfName;
  readonly p2c?: number;
  readonly salt: string;
  readonly iv: string;
  readonly aad: string;
  readonly kid?: string;
  readonly ts?: number;
}

/** A fully specified envelope ready to be serialized. */
export interface Envelope {
  readonly header: EnvelopeHeader;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

/**
 * Serialize the header canonically: fixed key order, no spaces, no optional
 * keys omitted-vs-null ambiguity. The output is the MAC input, so it must be
 * deterministic across runs and platforms.
 */
export function serializeHeader(h: EnvelopeHeader): string {
  const parts: string[] = [];
  parts.push(`"v":${h.v}`);
  parts.push(`"alg":${JSON.stringify(h.alg)}`);
  parts.push(`"cipher":${JSON.stringify(h.cipher)}`);
  parts.push(`"kdf":${JSON.stringify(h.kdf)}`);
  if (h.p2c !== undefined) parts.push(`"p2c":${h.p2c}`);
  parts.push(`"salt":"${h.salt}"`);
  parts.push(`"iv":"${h.iv}"`);
  parts.push(`"aad":"${h.aad}"`);
  if (h.kid !== undefined) parts.push(`"kid":${JSON.stringify(h.kid)}`);
  if (h.ts !== undefined) parts.push(`"ts":${h.ts}`);
  return `{${parts.join(',')}}`;
}

/** Text form of an envelope. */
export function serializeEnvelope(env: Envelope): string {
  return [
    MAGIC,
    toBase64Url(utf8Encode(serializeHeader(env.header))),
    toBase64Url(env.ciphertext),
    toBase64Url(env.tag),
  ].join('.');
}

/** Parsed but not yet authenticated envelope. */
export interface ParsedEnvelope {
  readonly header: EnvelopeHeader;
  /** Exact bytes that were authenticated along with the ciphertext. */
  readonly headerBytes: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Strict structural parse. This does NOT verify the MAC — callers must treat
 * the returned header as untrusted until `open` has authenticated it.
 */
export function parseEnvelope(text: string): Result<ParsedEnvelope> {
  const trimmed = text.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) {
    return fail('INVALID_ENVELOPE', `expected 4 dot-separated fields, found ${parts.length}`);
  }
  const [magic, headerPart, ctPart, tagPart] = parts as [string, string, string, string];
  if (magic !== MAGIC) {
    return fail('INVALID_ENVELOPE', `unknown envelope magic ${JSON.stringify(magic)}; expected ${MAGIC}`);
  }

  let headerBytes: Uint8Array;
  let ciphertext: Uint8Array;
  let tag: Uint8Array;
  try {
    headerBytes = fromBase64Url(headerPart);
  } catch (e) {
    return fail('INVALID_BASE64', 'header is not valid base64url', e);
  }
  try {
    ciphertext = fromBase64Url(ctPart);
  } catch (e) {
    return fail('INVALID_BASE64', 'ciphertext is not valid base64url', e);
  }
  try {
    tag = fromBase64Url(tagPart);
  } catch (e) {
    return fail('INVALID_BASE64', 'tag is not valid base64url', e);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(headerBytes));
  } catch (e) {
    return fail('INVALID_ENVELOPE', 'header is not valid JSON', e);
  }
  if (!isRecord(parsed)) {
    return fail('INVALID_ENVELOPE', 'header is not a JSON object');
  }

  const v = parsed['v'];
  if (typeof v !== 'number' || !Number.isInteger(v)) {
    return fail('INVALID_ENVELOPE', 'header.v must be an integer');
  }
  if (v !== ENVELOPE_VERSION) {
    return fail('UNSUPPORTED_VERSION', `envelope version ${v} is not supported (this build reads v${ENVELOPE_VERSION})`);
  }
  const alg = parsed['alg'];
  if (alg !== ALGORITHM) {
    return fail('UNSUPPORTED_ALGORITHM', `unsupported alg ${JSON.stringify(alg)}; expected ${ALGORITHM}`);
  }
  const cipher = parsed['cipher'];
  if (typeof cipher !== 'string' || !(cipher in CIPHER_KEY_BYTES)) {
    return fail('UNSUPPORTED_CIPHER', `unsupported cipher ${JSON.stringify(cipher)}`);
  }
  const kdf = parsed['kdf'];
  if (kdf !== 'HKDF-SHA256' && kdf !== 'PBKDF2-SHA256-HKDF-SHA256') {
    return fail('UNSUPPORTED_KDF', `unsupported kdf ${JSON.stringify(kdf)}`);
  }
  if (typeof parsed['salt'] !== 'string' || typeof parsed['iv'] !== 'string' || typeof parsed['aad'] !== 'string') {
    return fail('INVALID_ENVELOPE', 'header.salt, header.iv and header.aad must be strings');
  }

  const p2cRaw = parsed['p2c'];
  let p2c: number | undefined;
  if (p2cRaw !== undefined) {
    if (typeof p2cRaw !== 'number' || !Number.isInteger(p2cRaw)) {
      return fail('INVALID_ENVELOPE', 'header.p2c must be an integer');
    }
    p2c = p2cRaw;
  }
  if (kdf === 'PBKDF2-SHA256-HKDF-SHA256' && p2c === undefined) {
    return fail('MALFORMED_PARAMETER', 'PBKDF2 envelope is missing header.p2c');
  }
  if (kdf === 'HKDF-SHA256' && p2c !== undefined) {
    return fail('MALFORMED_PARAMETER', 'HKDF envelope must not declare header.p2c');
  }

  const kidRaw = parsed['kid'];
  if (kidRaw !== undefined && typeof kidRaw !== 'string') {
    return fail('INVALID_ENVELOPE', 'header.kid must be a string');
  }
  const tsRaw = parsed['ts'];
  if (tsRaw !== undefined && (typeof tsRaw !== 'number' || !Number.isInteger(tsRaw))) {
    return fail('INVALID_ENVELOPE', 'header.ts must be an integer');
  }

  const header: EnvelopeHeader = {
    v,
    alg,
    cipher: cipher as CipherName,
    kdf: kdf as KdfName,
    ...(p2c !== undefined ? { p2c } : {}),
    salt: parsed['salt'] as string,
    iv: parsed['iv'] as string,
    aad: parsed['aad'] as string,
    ...(kidRaw !== undefined ? { kid: kidRaw as string } : {}),
    ...(tsRaw !== undefined ? { ts: tsRaw as number } : {}),
  };

  const issues = validateHeaderParameters(header);
  if (issues) return issues;

  const ct = ciphertext;
  if (ct.length === 0 || ct.length % BLOCK_SIZE !== 0) {
    return fail('INVALID_ENVELOPE', `ciphertext length ${ct.length} is not a positive multiple of ${BLOCK_SIZE}`);
  }
  if (tag.length !== MIN_TAG_BYTES) {
    return fail('INVALID_ENVELOPE', `tag must be ${MIN_TAG_BYTES} bytes (got ${tag.length})`);
  }

  return ok({ header, headerBytes, ciphertext: ct, tag });
}

/** Bound every declared parameter so a hostile header cannot exhaust resources. */
function validateHeaderParameters(h: EnvelopeHeader): Result<never> | null {
  let salt: Uint8Array;
  try {
    salt = fromBase64Url(h.salt);
  } catch (e) {
    return fail('INVALID_BASE64', 'header.salt is not valid base64url', e);
  }
  if (salt.length < MIN_SALT_BYTES || salt.length > 64) {
    return fail('MALFORMED_PARAMETER', `salt must be ${MIN_SALT_BYTES}..64 bytes (got ${salt.length})`);
  }
  let iv: Uint8Array;
  try {
    iv = fromBase64Url(h.iv);
  } catch (e) {
    return fail('INVALID_BASE64', 'header.iv is not valid base64url', e);
  }
  if (iv.length !== BLOCK_SIZE) {
    return fail('MALFORMED_PARAMETER', `iv must be ${BLOCK_SIZE} bytes (got ${iv.length})`);
  }
  try {
    fromBase64Url(h.aad);
  } catch (e) {
    return fail('INVALID_BASE64', 'header.aad is not valid base64url', e);
  }
  if (h.p2c !== undefined && (h.p2c < MIN_PBKDF2_ITERATIONS || h.p2c > MAX_PBKDF2_ITERATIONS)) {
    return fail(
      'MALFORMED_PARAMETER',
      `p2c must be ${MIN_PBKDF2_ITERATIONS}..${MAX_PBKDF2_ITERATIONS} (got ${h.p2c})`,
    );
  }
  return null;
}

/** Derived subkeys for one envelope. */
export interface MessageKeys {
  readonly encKey: Uint8Array;
  readonly macKey: Uint8Array;
}

/**
 * Derive the MAC key from the master key and the per-message salt.
 * Kept separate from the encryption key so a padding oracle reveals nothing
 * about the MAC.
 */
export function deriveMacKey(masterKey: Uint8Array, salt: Uint8Array, cipher: CipherName): Uint8Array {
  return hkdfSha256(masterKey, salt, concat(INFO_MAC, utf8Encode(cipher)), 32);
}

/** Derive the encryption key (length follows the declared cipher). */
export function deriveEncKey(masterKey: Uint8Array, salt: Uint8Array, cipher: CipherName): Uint8Array {
  return hkdfSha256(masterKey, salt, concat(INFO_ENC, utf8Encode(cipher)), cipherKeyBytes(cipher));
}

/** Both subkeys in one pass of HKDF labels. */
export function deriveMessageKeys(
  masterKey: Uint8Array,
  salt: Uint8Array,
  cipher: CipherName,
): MessageKeys {
  return {
    encKey: deriveEncKey(masterKey, salt, cipher),
    macKey: deriveMacKey(masterKey, salt, cipher),
  };
}

/** The exact byte string the MAC covers: ASCII header bytes followed by ciphertext. */
export function macInput(headerBytes: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concat(headerBytes, ciphertext);
}

/** Compute the authentication tag. */
export function computeTag(macKey: Uint8Array, headerBytes: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return hmacSha256(macKey, macInput(headerBytes, ciphertext));
}

/**
 * Turn a passphrase into a 32-byte master key with PBKDF2 over a random salt.
 * Only used when the caller has a passphrase rather than a raw key.
 */
export function deriveMasterKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Uint8Array {
  return pbkdf2Sha256(utf8Encode(passphrase), salt, iterations, 32);
}

/** A fresh random salt for a new envelope. */
export function newSalt(bytes = MIN_SALT_BYTES): Uint8Array {
  return randomBytesOf(bytes);
}

/** A fresh random IV. Never reuse an IV with the same key. */
export function newIv(): Uint8Array {
  return randomBytesOf(BLOCK_SIZE);
}

/**
 * Decrypt + authenticate.
 *
 * Order matters: authenticate first, then unpad. A failure at the padding stage
 * is therefore only ever reported for a message whose tag already matched, and
 * is a genuine format error rather than an oracle.
 */
export function openEnvelope(
  parsed: ParsedEnvelope,
  masterKey: Uint8Array,
): Result<{ plaintext: Uint8Array; aad: Uint8Array; header: EnvelopeHeader }> {
  const { header, headerBytes, ciphertext, tag } = parsed;

  let salt: Uint8Array;
  let iv: Uint8Array;
  let aad: Uint8Array;
  try {
    salt = fromBase64Url(header.salt);
    iv = fromBase64Url(header.iv);
    aad = fromBase64Url(header.aad);
  } catch (e) {
    return fail('INVALID_BASE64', 'envelope parameters are not valid base64url', e);
  }

  const { encKey, macKey } = deriveMessageKeys(masterKey, salt, header.cipher);

  const expected = computeTag(macKey, headerBytes, ciphertext);
  if (!constantTimeEqual(expected, tag)) {
    return fail('INTEGRITY_FAILURE', 'authentication tag mismatch: wrong key, wrong passphrase, or the message was modified');
  }

  let padded: Uint8Array;
  try {
    padded = cbcDecryptRaw(ciphertext, encKey, iv);
  } catch (e) {
    return fail('MALFORMED_PARAMETER', 'ciphertext could not be decrypted', e);
  }

  let plaintext: Uint8Array;
  try {
    plaintext = pkcs7Unpad(padded);
  } catch (e) {
    // Authentic but structurally broken: the sender produced a bad pad.
    if (e instanceof PadError) {
      return fail('PADDING_FAILURE', 'authentic message has malformed PKCS#7 padding', e);
    }
    throw e;
  }

  return ok({ plaintext, aad, header });
}

/** Encrypt to an in-memory envelope. Does not derive caller keys. */
export function sealWithKeys(
  plaintext: Uint8Array,
  keys: MessageKeys,
  header: EnvelopeHeader,
): Envelope {
  const iv = fromBase64Url(header.iv);
  const ciphertext = cbcEncrypt(plaintext, keys.encKey, iv);
  const headerBytes = utf8Encode(serializeHeader(header));
  const tag = computeTag(keys.macKey, headerBytes, ciphertext);
  return { header, ciphertext, tag };
}

/** Stable, non-secret fingerprint of a message (for logs and dedup). */
export function fingerprint(text: string): string {
  return Buffer.from(sha256(utf8Encode(text)).subarray(0, 8)).toString('hex');
}
