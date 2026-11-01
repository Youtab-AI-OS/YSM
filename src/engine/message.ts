/**
 * The message engine: the public, task-shaped API.
 *
 * Two modes, one entry point each:
 *
 *  - `seal` / `unseal`  — v2, authenticated, random IV, HKDF-separated keys.
 *                          This is what you use for real messages.
 *  - `legacyEncrypt` / `legacyDecrypt` (src/engine/legacy.ts) — byte-compatible
 *    with aesencryption.net. Interop and recovery only.
 *
 * The engine owns:
 *  - turning either a raw key or a passphrase into a master key,
 *  - building the authenticated header,
 *  - resource bounds on everything an attacker controls,
 *  - the order of operations (authenticate, then unpad).
 */

import { assertKeyBits } from '../aes/block.js';
import { fromBase64Url, toBase64, fromBase64, utf8Encode, toBase64Url } from '../core/codec.js';
import { fail, ok, type Result } from '../core/result.js';
import { hkdfSha256 } from '../crypto/kdf.js';
import {
  ALGORITHM,
  CIPHER_NAMES,
  DEFAULT_PBKDF2_ITERATIONS,
  ENVELOPE_VERSION,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  MIN_SALT_BYTES,
  deriveMasterKeyFromPassphrase,
  deriveMessageKeys,
  newIv,
  newSalt,
  openEnvelope,
  parseEnvelope,
  sealWithKeys,
  serializeEnvelope,
  serializeHeader,
  type CipherName,
  type EnvelopeHeader,
  type ParsedEnvelope,
} from './envelope.js';

/** Hard bound on a single message body. Enforced before any allocation. */
export const MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024; // 64 MiB
export const MAX_ENVELOPE_CHARS = Math.ceil((MAX_PLAINTEXT_BYTES * 4) / 3) + 4096;

/** Key material the caller can supply. */
export type KeyInput =
  | { readonly kind: 'key'; readonly key: Uint8Array }
  | { readonly kind: 'passphrase'; readonly passphrase: string };

/** Options for sealing a message. */
export interface SealOptions {
  /** Raw 16/24/32-byte key. Mutually exclusive with `passphrase`. */
  readonly key?: Uint8Array;
  /** Human passphrase, stretched with PBKDF2. Mutually exclusive with `key`. */
  readonly passphrase?: string;
  /** PBKDF2 iterations when using a passphrase. Defaults to 600 000. */
  readonly iterations?: number;
  /** Cipher suite. Defaults to AES-256-CBC. */
  readonly cipher?: CipherName;
  /** Associated data bound into the MAC but not encrypted. */
  readonly aad?: Uint8Array;
  /** Recipient/key identifier recorded in the (authenticated) header. */
  readonly kid?: string;
  /** Record creation time in the header. Defaults to false. */
  readonly includeTimestamp?: boolean;
}

/** Options for opening a message. */
export interface UnsealOptions {
  readonly key?: Uint8Array;
  readonly passphrase?: string;
  /**
   * When true, the caller's AAD must equal the AAD stored in the envelope.
   * Off by default because the stored AAD is already MAC-protected.
   */
  readonly expectAad?: Uint8Array;
  /**
   * Reject messages whose timestamp is older than this many seconds.
   * Requires `includeTimestamp` at seal time. Off by default.
   */
  readonly maxAgeSeconds?: number;
  /** Reference clock, injectable for tests. */
  readonly now?: () => number;
}

/** A successfully opened message. */
export interface OpenedMessage {
  readonly plaintext: Uint8Array;
  readonly text: string;
  readonly aad: Uint8Array;
  readonly header: EnvelopeHeader;
  /** Machine-checkable report of what the envelope declared. */
  readonly info: MessageInfo;
}

/** The public, non-secret facts about an envelope. */
export interface MessageInfo {
  readonly version: number;
  readonly algorithm: string;
  readonly cipher: CipherName;
  readonly kdf: string;
  readonly keyBits: number;
  readonly saltBytes: number;
  readonly iterations?: number;
  readonly kid?: string;
  readonly createdAt?: number;
  readonly ciphertextBytes: number;
}

function keyBitsFor(cipher: CipherName): number {
  return { 'AES-128-CBC': 128, 'AES-192-CBC': 192, 'AES-256-CBC': 256 }[cipher];
}

function normalizeCipher(cipher: string | undefined): Result<CipherName> {
  const c = cipher ?? 'AES-256-CBC';
  if (!(CIPHER_NAMES as readonly string[]).includes(c)) {
    return fail('UNSUPPORTED_CIPHER', `cipher must be one of ${CIPHER_NAMES.join(', ')} (got ${c})`);
  }
  return ok(c as CipherName);
}

/** Validate a raw key against the cipher it will be used with. */
function checkRawKey(key: Uint8Array, cipher: CipherName): Result<Uint8Array> {
  const need = keyBitsFor(cipher) / 8;
  if (key.length !== need) {
    return fail(
      'BAD_KEY_LENGTH',
      `${cipher} needs a ${need}-byte key (got ${key.length}). Use --gen-key to create one.`,
    );
  }
  return ok(key);
}

/**
 * Reject passphrases that cannot plausibly resist offline guessing.
 * Length is the only cheap, language-independent proxy we can enforce without
 * lying about entropy; the message names the requirement instead of silently
 * accepting a weak secret.
 */
export const MIN_PASSPHRASE_LENGTH = 12;

function checkPassphrase(passphrase: string): Result<string> {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    return fail('BAD_PASSWORD', 'passphrase is empty');
  }
  if ([...passphrase].length < MIN_PASSPHRASE_LENGTH) {
    return fail(
      'WEAK_PASSWORD',
      `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters (got ${[...passphrase].length})`,
    );
  }
  return ok(passphrase);
}

function checkIterations(iterations: number | undefined): Result<number> {
  const n = iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  if (!Number.isInteger(n) || n < MIN_PBKDF2_ITERATIONS || n > MAX_PBKDF2_ITERATIONS) {
    return fail(
      'MALFORMED_PARAMETER',
      `iterations must be ${MIN_PBKDF2_ITERATIONS}..${MAX_PBKDF2_ITERATIONS} (got ${n})`,
    );
  }
  return ok(n);
}

/**
 * Encrypt a message into a v2 envelope string.
 *
 * @param plaintext message bytes
 * @param options   key or passphrase, plus optional AAD / kid / cipher
 */
export function seal(plaintext: Uint8Array, options: SealOptions): Result<string> {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    return fail('MALFORMED_PARAMETER', `message is ${plaintext.length} bytes; the limit is ${MAX_PLAINTEXT_BYTES}`);
  }
  if ((options.key === undefined) === (options.passphrase === undefined)) {
    return fail('BAD_PASSWORD', 'exactly one of `key` or `passphrase` is required');
  }

  const cipherRes = normalizeCipher(options.cipher);
  if (!cipherRes.ok) return cipherRes;
  const cipher = cipherRes.value;

  const salt = newSalt(MIN_SALT_BYTES);
  const iv = newIv();
  const aad = options.aad ?? new Uint8Array(0);

  let masterKey: Uint8Array;
  let iterations: number | undefined;

  if (options.passphrase !== undefined) {
    const ppRes = checkPassphrase(options.passphrase);
    if (!ppRes.ok) return ppRes;
    const iterRes = checkIterations(options.iterations);
    if (!iterRes.ok) return iterRes;
    iterations = iterRes.value;
    masterKey = deriveMasterKeyFromPassphrase(ppRes.value, salt, iterations);
  } else {
    const keyRes = checkRawKey(options.key!, cipher);
    if (!keyRes.ok) return keyRes;
    masterKey = keyRes.value;
  }

  const keys = deriveMessageKeys(masterKey, salt, cipher);
  const header: EnvelopeHeader = {
    v: ENVELOPE_VERSION,
    alg: ALGORITHM,
    cipher,
    kdf: iterations === undefined ? 'HKDF-SHA256' : 'PBKDF2-SHA256-HKDF-SHA256',
    ...(iterations === undefined ? {} : { p2c: iterations }),
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    aad: toBase64Url(aad),
    ...(options.kid === undefined ? {} : { kid: options.kid }),
    ...(options.includeTimestamp ? { ts: Math.floor(Date.now() / 1000) } : {}),
  };

  const env = sealWithKeys(plaintext, keys, header);
  return ok(serializeEnvelope(env));
}

/**
 * Decrypt and authenticate a v2 envelope.
 *
 * Never returns plaintext that failed the MAC check.
 */
export function unseal(text: string, options: UnsealOptions): Result<OpenedMessage> {
  if (text.length > MAX_ENVELOPE_CHARS) {
    return fail('MALFORMED_PARAMETER', `envelope is ${text.length} characters; the limit is ${MAX_ENVELOPE_CHARS}`);
  }
  if ((options.key === undefined) === (options.passphrase === undefined)) {
    return fail('BAD_PASSWORD', 'exactly one of `key` or `passphrase` is required');
  }

  const parsedRes = parseEnvelope(text);
  if (!parsedRes.ok) return parsedRes;
  const parsed: ParsedEnvelope = parsedRes.value;

  // Only validate raw key material when the caller actually supplied a key;
  // in passphrase mode there is no key to check, and dereferencing it here
  // would throw before the KDF mismatch could be reported cleanly.
  let rawKey: Uint8Array | undefined;
  if (options.key !== undefined) {
    const keyRes = checkRawKey(options.key, parsed.header.cipher);
    if (!keyRes.ok) return keyRes;
    rawKey = keyRes.value;
  }

  let masterKey: Uint8Array;
  if (options.passphrase !== undefined) {
    if (parsed.header.kdf !== 'PBKDF2-SHA256-HKDF-SHA256') {
      return fail(
        'UNSUPPORTED_KDF',
        `envelope was sealed with a raw key (${parsed.header.kdf}); supply --key-file, not a passphrase`,
      );
    }
    const iter = parsed.header.p2c!;
    const salt = fromBase64Url(parsed.header.salt);
    masterKey = deriveMasterKeyFromPassphrase(options.passphrase, salt, iter);
  } else {
    if (parsed.header.kdf !== 'HKDF-SHA256') {
      return fail(
        'UNSUPPORTED_KDF',
        `envelope was sealed with a passphrase (${parsed.header.kdf}); supply --passphrase, not a key file`,
      );
    }
    masterKey = rawKey!;
  }

  const opened = openEnvelope(parsed, masterKey);
  if (!opened.ok) return opened;

  if (options.expectAad !== undefined && !Buffer.from(options.expectAad).equals(Buffer.from(opened.value.aad))) {
    return fail('INTEGRITY_FAILURE', 'associated data does not match the value bound into this message');
  }

  if (options.maxAgeSeconds !== undefined) {
    if (opened.value.header.ts === undefined) {
      return fail('MALFORMED_PARAMETER', 'this message has no authenticated timestamp, so freshness cannot be checked');
    }
    const nowSec = Math.floor((options.now ?? Date.now)() / 1000);
    const age = nowSec - opened.value.header.ts;
    if (age > options.maxAgeSeconds) {
      return fail('RECIPIENT_EXPIRED', `message is ${age}s old; the limit is ${options.maxAgeSeconds}s`);
    }
  }

  return ok({
    plaintext: opened.value.plaintext,
    text: new TextDecoder('utf-8', { fatal: false }).decode(opened.value.plaintext),
    aad: opened.value.aad,
    header: opened.value.header,
    info: describe(opened.value.header, parsed.ciphertext.length),
  });
}

/** Describe an envelope's declared parameters without decrypting it. */
export function describe(header: EnvelopeHeader, ciphertextBytes: number): MessageInfo {
  return {
    version: header.v,
    algorithm: header.alg,
    cipher: header.cipher,
    kdf: header.kdf,
    keyBits: keyBitsFor(header.cipher),
    saltBytes: fromBase64Url(header.salt).length,
    ...(header.p2c === undefined ? {} : { iterations: header.p2c }),
    ...(header.kid === undefined ? {} : { kid: header.kid }),
    ...(header.ts === undefined ? {} : { createdAt: header.ts }),
    ciphertextBytes,
  };
}

/** Inspect an envelope without any key. Structural validation only. */
export function inspect(text: string): Result<MessageInfo & { tagBytes: number; authenticated: false }> {
  const parsed = parseEnvelope(text);
  if (!parsed.ok) return parsed;
  return ok({
    ...describe(parsed.value.header, parsed.value.ciphertext.length),
    tagBytes: parsed.value.tag.length,
    authenticated: false,
  });
}

/** Generate a new random key of the requested size in bits. */
export function generateKey(bits: number = 256): Result<Uint8Array> {
  try {
    const b = assertKeyBits(bits);
    return ok(newSalt(b / 8));
  } catch (e) {
    return fail('BAD_KEY_LENGTH', e instanceof Error ? e.message : String(e), e);
  }
}

/**
 * A short non-secret fingerprint of a key, for labelling key files and for
 * out-of-band verification that two parties hold the same key.
 *
 * The fingerprint is HKDF(key, salt="", info="cmsg key fingerprint") truncated
 * to 8 bytes (64 bits) — a one-way function of the key, printed with colons
 * for easy reading. 64 bits is far too little to search against a 128-bit key,
 * and it discloses nothing about the key beyond "same / not same".
 */
export function keyFingerprint(key: Uint8Array): string {
  const raw = hkdfSha256(key, new Uint8Array(0), utf8Encode('cmsg key fingerprint'), 8);
  return Buffer.from(raw).toString('hex').match(/../g)!.join(':');
}

/** Re-exported helpers so the CLI has a single import site. */
export { toBase64, fromBase64, utf8Encode };

/** Re-exported legacy entry points, intentionally namespaced. */
export { legacyDecrypt, legacyEncrypt, LEGACY_IV_STRING } from './legacy.js';
