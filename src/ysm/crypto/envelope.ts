/**
 * YSM message envelope: encrypt, sign, verify, decrypt.
 *
 * Wire format (all fields base64url, unpadded, dot-separated):
 *
 *   YSM1.<header>.<salt>.<nonce>.<ciphertext>.<signature>
 *
 * The header is canonical JSON carrying the sender/recipient public keys, a
 * message id, a timestamp, the content kind, and — for attachments — the chunk
 * count. It is bound into the AEAD as associated data AND covered by the
 * Ed25519 signature, so neither can be altered independently.
 *
 * Order of operations on open:
 *   1. structural parse (strict, bounded)
 *   2. verify the Ed25519 signature over header||salt||nonce||ciphertext
 *   3. derive the message key and AEAD-decrypt
 *
 * The signature is checked before decryption so a forger learns nothing from
 * the decryption path, and so a decryption failure can be attributed to a
 * corrupt-but-authentic message rather than an attack.
 */

import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { x25519 } from '@noble/curves/ed25519.js';

import { random, sign, verify, type Identity, type PublicIdentity } from './identity.js';

export const MAGIC = 'YSM1';
export const PROTOCOL_VERSION = 1;
export const SALT_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const SIGNATURE_BYTES = 64;
/** Upper bound on a single envelope. Attachments are chunked well below this. */
export const MAX_ENVELOPE_BYTES = 96 * 1024 * 1024;

const INFO_MSG = new TextEncoder().encode('ysm/v1/msg');

export type ContentKind = 'text' | 'file-start' | 'file-chunk' | 'file-end';

export interface EnvelopeHeader {
  /** Protocol version. */
  readonly v: number;
  /** Sender's X25519 public key. */
  readonly from: string;
  /** Sender's Ed25519 public key. */
  readonly fromSign: string;
  /** Recipient's X25519 public key. */
  readonly to: string;
  /** Unique message id (16 random bytes). */
  readonly mid: string;
  /** Creation time, unix milliseconds. */
  readonly ts: number;
  /** What this envelope carries. */
  readonly kind: ContentKind;
  /** Room id this message belongs to (opaque, derived by participants). */
  readonly room: string;
  /** For file envelopes: transfer id shared by all chunks. */
  readonly file?: string;
  /** For file-chunk: 0-based chunk index. */
  readonly idx?: number;
  /** For file-start: total chunk count. */
  readonly chunks?: number;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();
const utf8d = new TextDecoder('utf-8', { fatal: false });

export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function fromB64u(text: string): Uint8Array {
  // Strict: reject anything that is not canonical base64url, so corruption is an
  // error rather than silently decoding to different bytes.
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('invalid base64url');
  const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/** Canonical header serialization: fixed field order, no whitespace. */
export function serializeHeader(h: EnvelopeHeader): string {
  const parts = [
    `"v":${h.v}`,
    `"from":"${h.from}"`,
    `"fromSign":"${h.fromSign}"`,
    `"to":"${h.to}"`,
    `"mid":"${h.mid}"`,
    `"ts":${h.ts}`,
    `"kind":"${h.kind}"`,
    `"room":"${h.room}"`,
    ...(h.file === undefined ? [] : [`"file":"${h.file}"`]),
    ...(h.idx === undefined ? [] : [`"idx":${h.idx}`]),
    ...(h.chunks === undefined ? [] : [`"chunks":${h.chunks}`]),
  ];
  return `{${parts.join(',')}}`;
}

// ---------------------------------------------------------------------------
// Key agreement
// ---------------------------------------------------------------------------

/**
 * Derive the per-message key.
 *
 * The long-term ECDH secret is only ever HKDF input, never a key itself. A fresh
 * random salt per message means a single message key compromise reveals nothing
 * about other messages, and there is no counter to desynchronise.
 *
 * Both public keys are bound into the derivation, but they MUST be ordered
 * canonically: the sender knows them as (own, peer) and the recipient as
 * (peer, own), so hashing them in call order would produce two different keys
 * and decryption would fail. Sorting by byte value makes the derivation
 * symmetric for both sides.
 */
export function deriveMessageKey(
  ownSecret: Uint8Array,
  peerAgreementPublic: Uint8Array,
  salt: Uint8Array,
  ownAgreementPublic: Uint8Array,
  ownSigningPublic: Uint8Array,
  peerSigningPublic: Uint8Array,
): Uint8Array {
  const shared = x25519.getSharedSecret(ownSecret, peerAgreementPublic);

  // Canonical order, computed independently on each side, so both participants
  // build an identical info string. Two separate sorted pairs: agreement keys
  // together, signing keys together. Never mix the two kinds.
  const [agreementLo, agreementHi] = sortedPair(ownAgreementPublic, peerAgreementPublic);
  const [signLo, signHi] = sortedPair(ownSigningPublic, peerSigningPublic);

  const info = new Uint8Array(INFO_MSG.length + 128);
  info.set(INFO_MSG, 0);
  info.set(agreementLo, INFO_MSG.length);
  info.set(agreementHi, INFO_MSG.length + 32);
  info.set(signLo, INFO_MSG.length + 64);
  info.set(signHi, INFO_MSG.length + 96);
  return hkdf(sha256, shared, salt, info, 32);
}

/** Order two same-length keys by byte value so both peers agree. */
function sortedPair(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
  return compareBytes(a, b) <= 0 ? [a, b] : [b, a];
}

/** Byte-wise comparison used for canonical key ordering. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

// ---------------------------------------------------------------------------
// Seal
// ---------------------------------------------------------------------------

export interface SealInput {
  readonly identity: Identity;
  readonly peer: PublicIdentity;
  readonly room: string;
  readonly kind: ContentKind;
  readonly body: Uint8Array;
  readonly file?: string;
  readonly idx?: number;
  readonly chunks?: number;
  /** Injectable clock for tests. */
  readonly now?: () => number;
}

/**
 * Encrypt and sign one envelope.
 *
 * `body` is the plaintext payload (message text as UTF-8, or one file chunk).
 */
export function seal(input: SealInput): string {
  const { identity, peer, room, kind, body } = input;

  if (body.length > MAX_ENVELOPE_BYTES) {
    throw new RangeError(`body exceeds ${MAX_ENVELOPE_BYTES} bytes; attachments must be chunked`);
  }

  const salt = random(SALT_BYTES);
  const nonce = random(NONCE_BYTES);
  const mid = b64u(random(16));

  const header: EnvelopeHeader = {
    v: PROTOCOL_VERSION,
    from: b64u(identity.agreement.publicKey),
    fromSign: b64u(identity.signing.publicKey),
    to: b64u(peer.agreement),
    mid,
    ts: (input.now ?? Date.now)(),
    kind,
    room,
    ...(input.file === undefined ? {} : { file: input.file }),
    ...(input.idx === undefined ? {} : { idx: input.idx }),
    ...(input.chunks === undefined ? {} : { chunks: input.chunks }),
  };

  const headerJson = serializeHeader(header);
  const headerBytes = utf8.encode(headerJson);

  const key = deriveMessageKey(
    identity.agreement.secretKey,
    peer.agreement,
    salt,
    identity.agreement.publicKey,
    identity.signing.publicKey,
    peer.signing,
  );

  const ciphertext = gcm(key, nonce, headerBytes).encrypt(body);

  // Sign everything that matters: header bytes, salt, nonce, ciphertext.
  const signed = concat(headerBytes, salt, nonce, ciphertext);
  const signature = sign(identity, signed);

  return [MAGIC, b64u(headerBytes), b64u(salt), b64u(nonce), b64u(ciphertext), b64u(signature)].join('.');
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

export interface ParsedEnvelope {
  readonly header: EnvelopeHeader;
  readonly headerBytes: Uint8Array;
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly signature: Uint8Array;
}

export type OpenFailure =
  | { ok: false; code: 'INVALID_FORMAT'; message: string }
  | { ok: false; code: 'UNSUPPORTED_VERSION'; message: string }
  | { ok: false; code: 'BAD_SIGNATURE'; message: string }
  | { ok: false; code: 'DECRYPT_FAILED'; message: string }
  | { ok: false; code: 'WRONG_RECIPIENT'; message: string }
  | { ok: false; code: 'NOT_YOUR_MESSAGE'; message: string };

export type OpenResult =
  | {
      ok: true;
      header: EnvelopeHeader;
      body: Uint8Array;
      sender: PublicIdentity;
    }
  | OpenFailure;

const VALID_KINDS: ReadonlySet<string> = new Set(['text', 'file-start', 'file-chunk', 'file-end']);

/** Strict structural parse. Does not authenticate. */
export function parseEnvelope(text: string): { ok: true; value: ParsedEnvelope } | OpenFailure {
  const trimmed = text.trim();
  if (trimmed.length > MAX_ENVELOPE_BYTES) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'envelope is too large' };
  }
  const parts = trimmed.split('.');
  if (parts.length !== 6) {
    return { ok: false, code: 'INVALID_FORMAT', message: `expected 6 fields, found ${parts.length}` };
  }
  if (parts[0] !== MAGIC) {
    return { ok: false, code: 'INVALID_FORMAT', message: `unknown magic ${JSON.stringify(parts[0])}` };
  }

  let headerBytes: Uint8Array, salt: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, signature: Uint8Array;
  try {
    headerBytes = fromB64u(parts[1]!);
    salt = fromB64u(parts[2]!);
    nonce = fromB64u(parts[3]!);
    ciphertext = fromB64u(parts[4]!);
    signature = fromB64u(parts[5]!);
  } catch (err) {
    return { ok: false, code: 'INVALID_FORMAT', message: `field is not valid base64url: ${(err as Error).message}` };
  }

  if (salt.length !== SALT_BYTES) return { ok: false, code: 'INVALID_FORMAT', message: `salt must be ${SALT_BYTES} bytes` };
  if (nonce.length !== NONCE_BYTES) return { ok: false, code: 'INVALID_FORMAT', message: `nonce must be ${NONCE_BYTES} bytes` };
  if (signature.length !== SIGNATURE_BYTES) return { ok: false, code: 'INVALID_FORMAT', message: `signature must be ${SIGNATURE_BYTES} bytes` };
  if (ciphertext.length < TAG_BYTES) return { ok: false, code: 'INVALID_FORMAT', message: 'ciphertext is shorter than the AEAD tag' };

  let header: EnvelopeHeader;
  try {
    header = JSON.parse(utf8d.decode(headerBytes)) as EnvelopeHeader;
  } catch {
    return { ok: false, code: 'INVALID_FORMAT', message: 'header is not valid JSON' };
  }

  if (typeof header !== 'object' || header === null) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'header is not an object' };
  }
  if (header.v !== PROTOCOL_VERSION) {
    return { ok: false, code: 'UNSUPPORTED_VERSION', message: `protocol version ${String(header.v)} is not supported` };
  }
  if (!VALID_KINDS.has(header.kind)) {
    return { ok: false, code: 'INVALID_FORMAT', message: `unknown content kind ${JSON.stringify(header.kind)}` };
  }
  for (const field of ['from', 'fromSign', 'to', 'mid', 'room'] as const) {
    if (typeof header[field] !== 'string' || header[field].length === 0) {
      return { ok: false, code: 'INVALID_FORMAT', message: `header.${field} must be a non-empty string` };
    }
  }
  if (typeof header.ts !== 'number' || !Number.isFinite(header.ts)) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'header.ts must be a number' };
  }
  // Bounded integers: a hostile header must not be able to claim an absurd
  // chunk index or count and drive allocation later.
  if (header.idx !== undefined && (!Number.isInteger(header.idx) || header.idx < 0 || header.idx > 1_000_000)) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'header.idx out of range' };
  }
  if (header.chunks !== undefined && (!Number.isInteger(header.chunks) || header.chunks < 1 || header.chunks > 1_000_000)) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'header.chunks out of range' };
  }

  return { ok: true, value: { header, headerBytes, salt, nonce, ciphertext, signature } };
}

/**
 * Verify authenticity and decrypt.
 *
 * The recipient's identity is required: only the intended recipient can derive
 * the message key. The recipient's own keys are also checked against the header
 * so a message addressed elsewhere produces a clear error rather than a
 * signature failure.
 */
export function open(text: string, identity: Identity): OpenResult {
  const parsed = parseEnvelope(text);
  if (!parsed.ok) return parsed;

  const { header, headerBytes, salt, nonce, ciphertext, signature } = parsed.value;

  const senderAgreement = fromB64u(header.from);
  const senderSigning = fromB64u(header.fromSign);
  const recipient = fromB64u(header.to);

  if (senderAgreement.length !== 32 || senderSigning.length !== 32 || recipient.length !== 32) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'public keys in the header have the wrong length' };
  }

  if (!equalBytes(recipient, identity.agreement.publicKey)) {
    return { ok: false, code: 'WRONG_RECIPIENT', message: 'this message was not addressed to this identity' };
  }

  // 1. Authenticity first. If this fails, nothing else is trusted.
  const signed = concat(headerBytes, salt, nonce, ciphertext);
  if (!verify(signature, signed, senderSigning)) {
    return {
      ok: false,
      code: 'BAD_SIGNATURE',
      message: 'signature does not verify: the message was modified or was not sent by the claimed sender',
    };
  }

  // 2. Then confidentiality.
  let key: Uint8Array;
  try {
    key = deriveMessageKey(
      identity.agreement.secretKey,
      senderAgreement,
      salt,
      identity.agreement.publicKey,
      identity.signing.publicKey,
      senderSigning,
    );
  } catch (err) {
    return { ok: false, code: 'INVALID_FORMAT', message: `key agreement failed: ${(err as Error).message}` };
  }

  let body: Uint8Array;
  try {
    body = gcm(key, nonce, headerBytes).decrypt(ciphertext);
  } catch {
    return {
      ok: false,
      code: 'DECRYPT_FAILED',
      message: 'decryption failed: the ciphertext is corrupt or the signature does not match the key agreement',
    };
  }

  return {
    ok: true,
    header,
    body,
    sender: { agreement: senderAgreement, signing: senderSigning },
  };
}

// ---------------------------------------------------------------------------

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

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
