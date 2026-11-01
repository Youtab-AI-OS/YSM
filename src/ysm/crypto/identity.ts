/**
 * YSM identity keys.
 *
 * Every account holds two long-term keypairs:
 *   - X25519  for key agreement (ECDH)
 *   - Ed25519 for signatures (authenticity)
 *
 * Both are needed. A shared ECDH secret proves that two parties *can* derive the
 * same key, but it does not prove which of them sent a given message: either
 * side holds the same secret. The Ed25519 signature is what makes "this came
 * from A" checkable.
 *
 * All keys are generated with the platform CSPRNG and never leave the device
 * except as public keys inside a signed contact card.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/ciphers/utils.js';

export interface KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** A full local identity: both keypairs plus derived identifiers. */
export interface Identity {
  readonly agreement: KeyPair;
  readonly signing: KeyPair;
}

const X25519_PUBLIC_BYTES = 32;
const X25519_SECRET_BYTES = 32;
const ED25519_PUBLIC_BYTES = 32;
const ED25519_SECRET_BYTES = 32;

/** Generate a fresh identity. Uses the CSPRNG; never derived from a password. */
export function generateIdentity(): Identity {
  const agreementSecret = x25519.utils.randomSecretKey();
  const signingSecret = ed25519.utils.randomSecretKey();
  return {
    agreement: {
      secretKey: agreementSecret,
      publicKey: x25519.getPublicKey(agreementSecret),
    },
    signing: {
      secretKey: signingSecret,
      publicKey: ed25519.getPublicKey(signingSecret),
    },
  };
}

/** The public half of an identity — safe to share. */
export interface PublicIdentity {
  readonly agreement: Uint8Array;
  readonly signing: Uint8Array;
}

/** Extract the shareable public identity. */
export function publicIdentityOf(id: Identity): PublicIdentity {
  return { agreement: id.agreement.publicKey, signing: id.signing.publicKey };
}

export type PublicIdentityResult =
  | { ok: true; value: PublicIdentity }
  | { ok: false; code: 'BAD_PUBLIC_KEY'; message: string };

/** Validate that two buffers look like an X25519 + Ed25519 public identity. */
export function parsePublicIdentity(agreement: Uint8Array, signing: Uint8Array): PublicIdentityResult {
  if (agreement.length !== X25519_PUBLIC_BYTES) {
    return { ok: false, code: 'BAD_PUBLIC_KEY', message: `agreement key must be ${X25519_PUBLIC_BYTES} bytes (got ${agreement.length})` };
  }
  if (signing.length !== ED25519_PUBLIC_BYTES) {
    return { ok: false, code: 'BAD_PUBLIC_KEY', message: `signing key must be ${ED25519_PUBLIC_BYTES} bytes (got ${signing.length})` };
  }
  // Reject low-order / invalid points up front rather than failing later during
  // key agreement, where the error is harder to attribute.
  try {
    x25519.getSharedSecret(new Uint8Array(X25519_SECRET_BYTES).fill(1), agreement);
  } catch {
    return { ok: false, code: 'BAD_PUBLIC_KEY', message: 'agreement key is not a valid X25519 public key' };
  }
  return { ok: true, value: { agreement: new Uint8Array(agreement), signing: new Uint8Array(signing) } };
}

/**
 * Validate a secret key length before use, so a truncated stored key produces a
 * clear error instead of a cryptic library exception.
 */
export function assertSecretKey(secret: Uint8Array, kind: 'x25519' | 'ed25519'): void {
  const expected = kind === 'x25519' ? X25519_SECRET_BYTES : ED25519_SECRET_BYTES;
  if (secret.length !== expected) {
    throw new RangeError(`${kind} secret key must be ${expected} bytes (got ${secret.length})`);
  }
}

/** Sign a message with the identity's Ed25519 key. */
export function sign(identity: Identity, message: Uint8Array): Uint8Array {
  assertSecretKey(identity.signing.secretKey, 'ed25519');
  return ed25519.sign(message, identity.signing.secretKey);
}

/** Verify a signature against a signing public key. Never throws on bad input. */
export function verify(signature: Uint8Array, message: Uint8Array, signingPublicKey: Uint8Array): boolean {
  try {
    if (signature.length !== 64 || signingPublicKey.length !== ED25519_PUBLIC_BYTES) return false;
    return ed25519.verify(signature, message, signingPublicKey);
  } catch {
    return false;
  }
}

/**
 * The safety number: a short, human-comparable fingerprint of both public keys.
 *
 * Two users read this aloud and confirm it matches. It binds *both* keys of both
 * parties, so substituting either key changes the number. It is 40 decimal
 * digits (about 132 bits), displayed as 8 groups of 5 which is short enough to
 * compare verbally and long enough that a collision is not a practical attack.
 *
 * This is the only defence against a man-in-the-middle, and it only works if the
 * users actually compare it out of band. The UI must say so.
 */
export function safetyNumber(a: PublicIdentity, b: PublicIdentity): string {
  // Order the two identities deterministically so both sides compute the same
  // number regardless of who is "first".
  const pack = (id: PublicIdentity): Uint8Array => {
    const out = new Uint8Array(64);
    out.set(id.agreement, 0);
    out.set(id.signing, 32);
    return out;
  };
  const pa = pack(a);
  const pb = pack(b);
  const [first, second] = compareBytes(pa, pb) <= 0 ? [pa, pb] : [pb, pa];

  const material = new Uint8Array(128 + 16);
  material.set(first, 0);
  material.set(second, 64);
  material.set(new TextEncoder().encode('ysm/v1/safety'), 128);

  const digest = sha256(material);
  // Expand 32 bytes into 40 decimal digits: take 5 chunks of 8 bytes, each
  // reduced modulo 10^8, giving 8 digits per chunk.
  let out = '';
  for (let i = 0; i < 5; i++) {
    const slice = digest.subarray(i * 6, i * 6 + 6);
    let value = 0n;
    for (const byte of slice) value = (value << 8n) | BigInt(byte);
    out += (value % 100_000_000n).toString().padStart(8, '0');
  }
  const digits = out.slice(0, 40);
  return digits.match(/.{5}/g)!.join(' ');
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

/** Hex rendering of a public key for display, grouped for readability. */
export function publicKeyHex(key: Uint8Array): string {
  return Buffer.from(key).toString('hex').match(/.{2}/g)!.join(':');
}

/** Fresh random bytes from the platform CSPRNG. */
export function random(n: number): Uint8Array {
  return randomBytes(n);
}
