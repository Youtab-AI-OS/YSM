/**
 * Encrypted record storage.
 *
 * Two separate layers, deliberately:
 *
 *   app layer        each field that holds user data is AES-256-GCM encrypted
 *                    before it reaches the database
 *   file layer       the database file is an ordinary SQLite file
 *
 * This is application-layer encryption, NOT SQLCipher. The distinction matters
 * and is stated rather than blurred: queries operate on ciphertext, so there is
 * no searchable index over message text, and an attacker reading the raw file
 * sees only ciphertext plus structural metadata (row counts, approximate sizes,
 * insert timing).
 *
 * Engine choice: `node:sqlite` (built into Node 22+/Electron 30+). Using it means
 * there is no native module to compile or keep in ABI sync with Electron, which
 * removes the single largest source of "works for me, crashes on install"
 * packaging failures in an Electron app.
 */

import { DatabaseSync } from 'node:sqlite';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export interface VaultCipher {
  /** Encrypt a UTF-8 string into a storable blob (nonce || ciphertext || tag). */
  encryptText(plaintext: string, context: string): Uint8Array;
  /** Decrypt such a blob back to a string. Throws on failure. */
  decryptText(blob: Uint8Array, context: string): string;
  /** Encrypt raw bytes. */
  encryptBytes(plaintext: Uint8Array, context: string): Uint8Array;
  /** Decrypt raw bytes. */
  decryptBytes(blob: Uint8Array, context: string): Uint8Array;
}

const NONCE_BYTES = 12;

/**
 * Build a cipher bound to the vault key.
 *
 * `context` is mixed into the key derivation per field, so a ciphertext lifted
 * from one column cannot be replayed into another (for example, copying an
 * encrypted message into the contact-name column). This is the standard
 * "context binding" technique and costs one HKDF call per field.
 */
export function createVaultCipher(vaultKey: Uint8Array): VaultCipher {
  if (vaultKey.length !== 32) throw new RangeError('vault key must be 32 bytes');

  const subkey = (context: string): Uint8Array =>
    hkdf(sha256, vaultKey, new Uint8Array(0), new TextEncoder().encode(`ysm/v1/field:${context}`), 32);

  const enc = (data: Uint8Array, context: string): Uint8Array => {
    const nonce = new Uint8Array(NONCE_BYTES);
    globalThis.crypto.getRandomValues(nonce);
    const ct = gcm(subkey(context), nonce, new TextEncoder().encode(context)).encrypt(data);
    const out = new Uint8Array(NONCE_BYTES + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_BYTES);
    return out;
  };

  const dec = (blob: Uint8Array, context: string): Uint8Array => {
    if (blob.length < NONCE_BYTES + 16) throw new Error('ciphertext is too short');
    const nonce = blob.subarray(0, NONCE_BYTES);
    const ct = blob.subarray(NONCE_BYTES);
    return gcm(subkey(context), nonce, new TextEncoder().encode(context)).decrypt(ct);
  };

  return {
    encryptText: (p, c) => enc(new TextEncoder().encode(p), c),
    decryptText: (b, c) => new TextDecoder().decode(dec(toBytes(b), c)),
    encryptBytes: (p, c) => enc(p, c),
    decryptBytes: (b, c) => dec(toBytes(b), c),
  };
}

/** node:sqlite returns BLOBs as Uint8Array; normalise defensively anyway. */
function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return new TextEncoder().encode(value);
  throw new TypeError('expected a BLOB column, got a different type');
}

/** Schema. Every user-data column is BLOB and holds ciphertext. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  id             TEXT PRIMARY KEY,
  display_name   BLOB NOT NULL,
  agreement_pub  BLOB NOT NULL,
  signing_pub    BLOB NOT NULL,
  verified       INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id           TEXT PRIMARY KEY,
  name         BLOB NOT NULL,
  kind         TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
  room_id    TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  PRIMARY KEY (room_id, contact_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id        TEXT PRIMARY KEY,
  room_id   TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  sent_at   INTEGER NOT NULL,
  body      BLOB NOT NULL,
  kind      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, sent_at);

CREATE TABLE IF NOT EXISTS transfers (
  id         TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  name       BLOB NOT NULL,
  mime       TEXT NOT NULL,
  size       INTEGER NOT NULL,
  sha256     TEXT NOT NULL,
  category   TEXT NOT NULL,
  chunks     INTEGER NOT NULL,
  received   INTEGER NOT NULL DEFAULT 0,
  data       BLOB,
  status     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  message_id TEXT PRIMARY KEY,
  room_id    TEXT NOT NULL,
  payload    BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_state (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  failed_count  INTEGER NOT NULL DEFAULT 0,
  locked_until  INTEGER NOT NULL DEFAULT 0,
  last_totp_ctr INTEGER
);
`;

export interface OpenDatabaseOptions {
  readonly path: string;
}

/**
 * Open the database and ensure the schema exists.
 *
 * WAL keeps reads from blocking writes; `synchronous = FULL` costs a little speed
 * and guarantees a committed row survives a power cut, which matters more than
 * throughput for a message store.
 */
export function openDatabase(opts: OpenDatabaseOptions): DatabaseSync {
  const db = new DatabaseSync(opts.path);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = OFF;');
  db.exec('PRAGMA synchronous = FULL;');
  db.exec(SCHEMA);
  db.prepare('INSERT OR IGNORE INTO auth_state (id, failed_count, locked_until) VALUES (1, 0, 0)').run();
  return db;
}

/**
 * Run `fn` inside a transaction, rolling back if it throws.
 *
 * `node:sqlite` has no `db.transaction()` wrapper (unlike better-sqlite3), so
 * this provides the same semantics explicitly. Multi-statement writes in this
 * app are security-relevant — for example, consuming a recovery code must not
 * happen unless the unlock also succeeds — so the rollback path matters.
 */
export function withTransaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // A rollback failure means the transaction is already gone; the original
      // error is the one worth surfacing.
    }
    throw error;
  }
}

export type { DatabaseSync };
