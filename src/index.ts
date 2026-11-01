/**
 * Public entry point.
 *
 * Anything a consumer needs should be importable from here. Submodules are
 * implementation detail and may be reorganised.
 */

export {
  // v2 authenticated engine
  seal,
  unseal,
  inspect,
  describe,
  generateKey,
  keyFingerprint,
  MAX_PLAINTEXT_BYTES,
  MIN_PASSPHRASE_LENGTH,
  type KeyInput,
  type SealOptions,
  type UnsealOptions,
  type OpenedMessage,
  type MessageInfo,
} from './engine/message.js';

export {
  // legacy aesencryption.net compatibility
  legacyEncrypt,
  legacyDecrypt,
  legacyDecryptDiagnostic,
  legacyKey,
  LEGACY_IV,
  LEGACY_IV_STRING,
  type LegacyKeyBits,
} from './engine/legacy.js';

export {
  // envelope format
  MAGIC,
  ENVELOPE_VERSION,
  ALGORITHM,
  DEFAULT_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  MAX_PBKDF2_ITERATIONS,
  CIPHER_NAMES,
  parseEnvelope,
  serializeEnvelope,
  deriveMessageKeys,
  computeTag,
  type CipherName,
  type KdfName,
  type EnvelopeHeader,
  type Envelope,
  type MessageKeys,
  type ParsedEnvelope,
} from './engine/envelope.js';

export {
  // key material on disk
  readKeyFile,
  writeKeyFile,
  writeKeyToRing,
  readKeyFromRing,
  listKeyring,
  isValidKid,
} from './engine/keys.js';

export {
  // result algebra
  ok,
  fail,
  unwrap,
  mapResult,
  CryptoMessageError,
  type Result,
  type Failure,
  type ErrorCode,
} from './core/result.js';

export {
  // low-level AES, exported for verification and reuse
  expandKey,
  encryptBlock,
  decryptBlock,
  BLOCK_SIZE,
  type KeySchedule,
  type AesKeyBits,
} from './aes/block.js';

export { cbcEncrypt, cbcDecrypt, pkcs7Pad, pkcs7Unpad, PadError } from './aes/cbc.js';

export { sha256, hmacSha256, hkdfSha256, pbkdf2Sha256, randomBytesOf } from './crypto/kdf.js';

export { toBase64, fromBase64, toBase64Url, fromBase64Url, toHex, fromHex, utf8Encode, utf8Decode } from './core/codec.js';
