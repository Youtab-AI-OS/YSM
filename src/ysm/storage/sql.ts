/**
 * Storage abstraction.
 *
 * The vault, contacts and messaging layers talk to SQL through this narrow
 * interface rather than to `node:sqlite` directly. That is what makes the same
 * cryptography and the same application logic run on desktop (`node:sqlite`)
 * and on mobile (Capacitor SQLite) without duplicating either.
 *
 * The contract is deliberately SQL-shaped but tiny: `exec` for statements with
 * no results, `run` for parameterised writes, `get` for one row, `all` for many.
 * Transactions are explicit so a platform without a `transaction()` helper (both
 * of ours) behaves identically.
 *
 * Values are limited to what both engines accept: string, number, null and
 * Uint8Array (stored as BLOB). Nothing else is allowed, because a platform
 * mismatch would surface as silent corruption rather than a clear error.
 */

/** A value that can be bound to a statement. */
export type SqlValue = string | number | null | Uint8Array;

/** A row as returned by the engine; values are read by column name. */
export type SqlRow = Record<string, unknown>;

export interface SqlStatement {
  /** Execute a write and return the number of affected rows where known. */
  run(...params: SqlValue[]): { changes: number };
  /** Fetch the first row, or undefined. */
  get(...params: SqlValue[]): SqlRow | undefined;
  /** Fetch every row. */
  all(...params: SqlValue[]): SqlRow[];
}

export interface SqlDatabase {
  /** Run one or more statements with no parameters. */
  exec(sql: string): void;
  /** Prepare a parameterised statement. */
  prepare(sql: string): SqlStatement;
  /** Begin a transaction. */
  begin(): void;
  /** Commit the open transaction. */
  commit(): void;
  /** Roll back the open transaction. */
  rollback(): void;
  /** Close the database. */
  close(): void;
}

/**
 * Run `fn` inside a transaction, rolling back if it throws.
 *
 * Multi-statement writes here are security-relevant — consuming a recovery code
 * must not happen unless the unlock also succeeds — so the rollback path matters
 * as much as the happy path.
 */
export function withTransaction<T>(db: SqlDatabase, fn: () => T): T {
  db.begin();
  try {
    const result = fn();
    db.commit();
    return result;
  } catch (error) {
    try {
      db.rollback();
    } catch {
      // A rollback failure means the transaction is already gone; the original
      // error is the one worth surfacing.
    }
    throw error;
  }
}

/** Schema. Every user-data column is BLOB and holds ciphertext. */
export const SCHEMA = `
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

/** Statements applied after the schema, idempotently. */
export const POST_SCHEMA_SQL =
  'INSERT OR IGNORE INTO auth_state (id, failed_count, locked_until) VALUES (1, 0, 0)';

/**
 * Coerce an engine value to Uint8Array.
 *
 * Engines disagree on BLOB representation: `node:sqlite` returns Uint8Array,
 * Capacitor returns base64 in some configurations and a plain array in others.
 * Normalising once here keeps every consumer free of platform branches.
 */
export function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value as number[]);
  if (typeof value === 'string') {
    // Some engines hand back a binary string; encode it losslessly.
    const out = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i++) out[i] = value.charCodeAt(i) & 0xff;
    return out;
  }
  throw new TypeError('expected a BLOB column, got a different type');
}
