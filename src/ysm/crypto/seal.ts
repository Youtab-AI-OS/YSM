/**
 * Sealed references: encrypt a message or a file, and hand over two strings.
 *
 * The model, in plain terms
 * -------------------------
 * A user types a message (or attaches a file) and presses "Create crypto". They
 * get back **two** things:
 *
 *   1. a reference string   YSM_<64 hex chars>
 *   2. a random passphrase  shown once, changing for every message
 *
 * To let someone else read it, the user sends **both**. The reader pastes the
 * reference into the app, types the passphrase, and gets the original content
 * back — text as text, a file in its original name and format, downloadable.
 *
 * Why the key is separate from the reference
 * -----------------------------------------
 * The obvious design is to put the key inside the reference
 * (`YSM_<hash>_<key>`), so one string is enough. That is what aesencryption.net
 * effectively does, and it means the string *is* the secret: anything that
 * records it — a mail server, a chat backup, a screenshot, a clipboard manager,
 * shoulder-surfing — can read the message forever. Separating the key into a
 * second string that is never stored anywhere means a captured reference is
 * useless on its own.
 *
 * The reference is still an identifier: it is derived from the ciphertext, so it
 * cannot be guessed, and it lets the app find the message locally (for the author)
 * without revealing anything about it.
 *
 * Construction (per message)
 * --------------------------
 *   salt     32 random bytes
 *   key      Argon2id(passphrase, salt)        -> 32 bytes
 *   nonce    12 random bytes
 *   cipher   AES-256-GCM(key, nonce, aad)      -> ciphertext || tag
 *   ref      "YSM_" + SHA-256(salt || nonce || ciphertext) as hex
 *
 * Argon2id is used rather than a bare hash because the passphrase, while random,
 * is short enough to be transported by hand; the KDF cost is what makes an
 * offline guess against a stolen blob expensive.
 *
 * What the reference reveals
 * --------------------------
 * Length of the payload (from ciphertext size, rounded to 16 bytes), and that it
 * is a YSM message with this format version. Nothing else: salt, nonce and
 * ciphertext are all indistinguishable from random.
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { random } from './identity.js';

/** Prefix every reference starts with. */
export const REF_PREFIX = 'YSM_';

/** Length of the hex digest after the prefix. */
export const REF_HEX_LENGTH = 64;

/** Format version, so a future change can be detected rather than misparsed. */
export const SEAL_VERSION = 1;

const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;

/**
 * Passphrase length in bytes, before Base32.
 *
 * 20 bytes = 160 bits of entropy, which is far beyond guessable, and encodes to
 * 32 Base32 characters — short enough to copy by hand without truncation.
 */
const PASSPHRASE_BYTES = 20;

/**
 * Argon2id parameters.
 *
 * 64 MiB, 3 passes. Chosen so a single seal takes roughly a second on a laptop
 * while making each offline guess cost that much on an attacker's GPU fleet. The
 * values are stored in the payload header, so raising them later does not break
 * old messages.
 */
export const SEAL_ARGON = { t: 3, m: 65536, p: 1 } as const;

/** A sealed payload, as stored locally by the sender. */
export interface SealedPayload {
  /** `YSM_` + 64 hex characters. */
  readonly reference: string;
  /** The random passphrase, shown to the user once and never persisted. */
  readonly passphrase: string;
  /** True when the payload is a file rather than plain text. */
  readonly isFile: boolean;
  /** Original filename, for files. */
  readonly fileName?: string;
  /** MIME type, for files. */
  readonly mimeType?: string;
  /** Plaintext size in bytes, for display. */
  readonly size: number;
}

/** The encrypted form, which is what gets stored and later decrypted. */
export interface SealedBlob {
  readonly reference: string;
  readonly version: number;
  readonly argon: { t: number; m: number; p: number };
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  /** Payload kind and metadata, all inside the ciphertext. */
}

export type SealResult =
  | { ok: true; value: SealedBlob }
  | { ok: false; code: 'TOO_LARGE' | 'ENCODE_FAILED'; message: string };

export type OpenResult =
  | { ok: true; data: Uint8Array; fileName?: string; mimeType?: string }
  | {
      ok: false;
      code: 'BAD_REFERENCE' | 'BAD_PASSPHRASE' | 'UNSUPPORTED_VERSION' | 'CORRUPT';
      message: string;
    };

/** Encode bytes as unpadded Base32 (RFC 4648 alphabet, no padding). */
export function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}

/** Decode unpadded Base32. Throws on an invalid character. */
export function base32Decode(text: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = text.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const value = alphabet.indexOf(ch);
    if (value < 0) throw new Error(`invalid base32 character ${JSON.stringify(ch)}`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Derive the key from a passphrase. Isolated so tests can use cheaper params. */
function deriveKey(passphrase: string, salt: Uint8Array, argon: { t: number; m: number; p: number }): Uint8Array {
  const passBytes = new TextEncoder().encode(passphrase);
  return argon2id(passBytes, salt, { t: argon.t, m: argon.m, p: argon.p, dkLen: KEY_BYTES });
}

/** Compute the reference string from the encrypted parts. */
export function computeReference(salt: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): string {
  const input = new Uint8Array(salt.length + nonce.length + ciphertext.length);
  input.set(salt, 0);
  input.set(nonce, salt.length);
  input.set(ciphertext, salt.length + nonce.length);
  const digest = sha256(input);
  let hex = '';
  for (const b of digest) hex += b.toString(16).padStart(2, '0');
  return REF_PREFIX + hex;
}

/** Is this string shaped like a reference? Does not verify the contents. */
export function looksLikeReference(text: string): boolean {
  return new RegExp(`^${REF_PREFIX}[0-9a-fA-F]{${REF_HEX_LENGTH}}$`).test(text.trim());
}

/**
 * Generate a fresh passphrase.
 *
 * Base32 of 20 random bytes: 32 characters, all uppercase letters and digits,
 * no ambiguous padding, safe to read aloud or retype.
 */
export function generatePassphrase(): string {
  return base32Encode(random(PASSPHRASE_BYTES));
}

/** The plaintext envelope stored inside the ciphertext. */
interface InnerPayload {
  /** Bumped independently of the outer format if the inner shape changes. */
  readonly kind: 'text' | 'file';
  readonly text?: string;
  readonly fileName?: string;
  readonly mimeType?: string;
  readonly data?: string;
}

/**
 * Encrypt a text message or a file.
 *
 * `passphrase` is supplied by the caller so a test can use a fixed one; the
 * service always passes `generatePassphrase()`.
 */
export function seal(input: {
  data: Uint8Array;
  passphrase: string;
  isFile: boolean;
  fileName?: string;
  mimeType?: string;
  argon?: { t: number; m: number; p: number };
}): SealResult {
  const argon = input.argon ?? SEAL_ARGON;
  const salt = random(SALT_BYTES);
  const nonce = random(NONCE_BYTES);
  const key = deriveKey(input.passphrase, salt, argon);

  // Metadata travels inside the ciphertext, never beside it: a filename such as
  // "resignation-letter.pdf" leaks as much as the contents.
  const inner: InnerPayload = input.isFile
    ? {
        kind: 'file',
        fileName: input.fileName ?? 'file',
        mimeType: input.mimeType ?? 'application/octet-stream',
        data: bytesToBase64(input.data),
      }
    : { kind: 'text', text: new TextDecoder().decode(input.data) };

  const plaintext = new TextEncoder().encode(JSON.stringify(inner));
  const aad = new TextEncoder().encode(`${REF_PREFIX}v${SEAL_VERSION}`);
  const ciphertext = gcm(key, nonce, aad).encrypt(plaintext);

  // The key is no longer needed; wipe it rather than leave it for the GC.
  key.fill(0);

  const reference = computeReference(salt, nonce, ciphertext);

  return {
    ok: true,
    value: { reference, version: SEAL_VERSION, argon, salt, nonce, ciphertext },
  };
}

/**
 * Decrypt with a passphrase.
 *
 * The reference is recomputed from the ciphertext and compared before any
 * decryption is attempted, so a blob whose bytes were altered is rejected up
 * front rather than after paying the Argon2 cost.
 */
export function open(blob: SealedBlob, passphrase: string): OpenResult {
  if (blob.version !== SEAL_VERSION) {
    return {
      ok: false,
      code: 'UNSUPPORTED_VERSION',
      message: `this message uses format version ${blob.version}; this build understands ${SEAL_VERSION}`,
    };
  }

  const recomputed = computeReference(blob.salt, blob.nonce, blob.ciphertext);
  if (recomputed !== blob.reference) {
    return {
      ok: false,
      code: 'CORRUPT',
      message: 'the stored payload does not match its reference; it was altered after it was sealed',
    };
  }

  const key = deriveKey(passphrase.trim().toUpperCase(), blob.salt, blob.argon);
  const aad = new TextEncoder().encode(`${REF_PREFIX}v${blob.version}`);

  let plaintext: Uint8Array;
  try {
    plaintext = gcm(key, blob.nonce, aad).decrypt(blob.ciphertext);
  } catch {
    key.fill(0);
    return {
      ok: false,
      code: 'BAD_PASSPHRASE',
      message: 'wrong passphrase (or the message was altered)',
    };
  }
  key.fill(0);

  let inner: InnerPayload;
  try {
    inner = JSON.parse(new TextDecoder().decode(plaintext)) as InnerPayload;
  } catch {
    return { ok: false, code: 'CORRUPT', message: 'the decrypted payload is not readable' };
  }

  if (inner.kind === 'text') {
    return { ok: true, data: new TextEncoder().encode(inner.text ?? '') };
  }
  if (inner.kind === 'file') {
    return {
      ok: true,
      data: base64ToBytes(inner.data ?? ''),
      fileName: inner.fileName,
      mimeType: inner.mimeType,
    };
  }
  return { ok: false, code: 'CORRUPT', message: 'the decrypted payload has an unknown kind' };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    // noUncheckedIndexedAccess makes the element `number | undefined`; the index
    // is provably in range, so coalesce rather than assert.
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(binary);
}

function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) & 0xff;
  return out;
}
