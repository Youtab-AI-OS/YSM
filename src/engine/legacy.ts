/**
 * aesencryption.net compatible AES ("legacy" scheme).
 *
 * Reference behaviour, recovered from https://aesencryption.net/js/aes-browser.js
 * (see docs/SPEC.md for the full derivation):
 *
 *   cipher      AES-{128|192|256}-CBC
 *   padding     PKCS#7
 *   IV          fixed 16 bytes: ASCII "12345678b0z2345n"
 *   key         UTF-8 bytes of the password, truncated to the key length and
 *               zero-padded when shorter. NOT a KDF.
 *   output      standard base64 of the ciphertext (padding included)
 *   decryption  PKCS#7 unpad, decode UTF-8, then trim like PHP's trim()
 *
 * These properties are intentionally preserved so ciphertext round-trips with
 * the website and with the PHP/Java/Python examples it publishes. They are also
 * why the legacy scheme must not be used for anything important: the fixed IV
 * leaks equality of plaintexts and there is no integrity protection. Use the
 * v2 envelope (src/engine/message.ts) for real messages.
 */

import { cbcDecrypt, cbcEncrypt } from '../aes/cbc.js';
import { assertKeyBits, type AesKeyBits } from '../aes/block.js';
import {
  fromBase64Lenient,
  phpTrimBytes,
  toBase64,
  utf8Decode,
  utf8Encode,
} from '../core/codec.js';

/** The fixed IV baked into the server's AES::getIV(). */
export const LEGACY_IV_STRING = '12345678b0z2345n';

/** Fixed IV as bytes. */
export const LEGACY_IV: Uint8Array = utf8Encode(LEGACY_IV_STRING);

/** Key sizes the site offers. */
export type LegacyKeyBits = AesKeyBits;

/**
 * Build the legacy key: raw UTF-8 password bytes, truncated to `bits/8`,
 * right-padded with zero bytes when shorter.
 */
export function legacyKey(password: string | Uint8Array, bits: number): Uint8Array {
  const keyBits = assertKeyBits(bits);
  const keyLen = keyBits / 8;
  const raw = typeof password === 'string' ? utf8Encode(password) : password;
  const key = new Uint8Array(keyLen);
  key.set(raw.subarray(0, keyLen));
  return key;
}

/**
 * Encrypt like the website.
 *
 * @param plainText text to encrypt (UTF-8)
 * @param password  secret key as typed by the user
 * @param bits      128 | 192 | 256
 * @returns base64 ciphertext
 *
 * Note: the site refuses empty/whitespace-only *input text*; that is a UI rule,
 * not a crypto rule, and is not enforced here so the engine stays usable for
 * empty payloads (it produces a single pad block).
 */
export function legacyEncrypt(plainText: string, password: string, bits: LegacyKeyBits = 256): string {
  const ct = cbcEncrypt(utf8Encode(plainText), legacyKey(password, bits), LEGACY_IV);
  return toBase64(ct);
}

/**
 * Decrypt like the website.
 *
 * White space in the base64 input is tolerated (the site pastes from anywhere),
 * the pad is verified strictly, and the decrypted bytes are trimmed with PHP's
 * character set before being decoded as UTF-8 — matching `trim($ret)`.
 *
 * @throws {PadError} when the key is wrong or the ciphertext is truncated.
 */
export function legacyDecrypt(
  base64Text: string,
  password: string,
  bits: LegacyKeyBits = 256,
): string {
  const raw = fromBase64Lenient(base64Text);
  const pt = cbcDecrypt(raw, legacyKey(password, bits), LEGACY_IV);
  return utf8Decode(phpTrimBytes(pt));
}

/**
 * Decrypt and report whether the result looked structurally valid.
 *
 * A wrong key fails the PKCS#7 check with probability 255/256, so a *true*
 * `paddingValid` is weak evidence. It exists for diagnostics only.
 */
export function legacyDecryptDiagnostic(
  base64Text: string,
  password: string,
  bits: LegacyKeyBits = 256,
): { text: string; paddingValid: boolean } {
  try {
    return { text: legacyDecrypt(base64Text, password, bits), paddingValid: true };
  } catch (err) {
    if (err instanceof Error && err.name === 'PadError') {
      return { text: '', paddingValid: false };
    }
    throw err;
  }
}
