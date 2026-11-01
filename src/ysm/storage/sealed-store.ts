/**
 * Storage for sealed payloads.
 *
 * The passphrase never reaches this module. It is generated in the service, shown
 * to the user once, and dropped; this layer only ever sees ciphertext and the
 * reference. That separation is deliberate: a memory dump of this layer cannot
 * yield a decryption key, and no code path here can accidentally log one.
 */
import { toBytes } from './cipher.js';
import { withTransaction, type SqlDatabase } from './sql.js';

/** One sealed row, as read back from storage. */
export interface StoredSealed {
  readonly reference: string;
  readonly version: number;
  readonly argon: { t: number; m: number; p: number };
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly role: 'out' | 'in';
  readonly isFile: boolean;
  readonly size: number;
  readonly createdAt: number;
}

export interface InsertSealed {
  readonly reference: string;
  readonly version: number;
  readonly argon: { t: number; m: number; p: number };
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly role: 'out' | 'in';
  readonly isFile: boolean;
  readonly size: number;
  readonly now: number;
}

/**
 * Store a sealed payload. Idempotent: storing the same reference twice is a
 * no-op, because the reference is a hash of the content and the content is
 * therefore identical.
 */
export function insertSealed(db: SqlDatabase, item: InsertSealed): void {
  withTransaction(db, () => {
    db.prepare(
      `INSERT OR IGNORE INTO sealed
         (reference, version, argon_t, argon_m, argon_p, salt, nonce, ciphertext, role, is_file, size, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      item.reference,
      item.version,
      item.argon.t,
      item.argon.m,
      item.argon.p,
      item.salt,
      item.nonce,
      item.ciphertext,
      item.role,
      item.isFile ? 1 : 0,
      item.size,
      item.now,
    );
  });
}

/** Does this reference already exist? Used to distinguish "new" from "imported". */
export function existsSealed(db: SqlDatabase, reference: string): boolean {
  const row = db.prepare('SELECT reference FROM sealed WHERE reference = ?').get(reference);
  return row !== undefined;
}

/** Read one sealed payload by reference, or null. */
export function getSealed(db: SqlDatabase, reference: string): StoredSealed | null {
  const row = db
    .prepare(
      `SELECT reference, version, argon_t, argon_m, argon_p, salt, nonce, ciphertext, role, is_file, size, created_at
         FROM sealed WHERE reference = ?`,
    )
    .get(reference);
  if (row === undefined) return null;
  return rowToSealed(row);
}

/** Every stored reference, newest first. Metadata only — no ciphertext. */
export interface SealedSummary {
  readonly reference: string;
  readonly role: 'out' | 'in';
  readonly isFile: boolean;
  readonly size: number;
  readonly createdAt: number;
}

export function listSealed(db: SqlDatabase, limit = 200): SealedSummary[] {
  const rows = db
    .prepare(
      `SELECT reference, role, is_file, size, created_at
         FROM sealed ORDER BY created_at DESC LIMIT ?`,
    )
    .all(limit);
  return rows.map((row) => ({
    reference: String(row['reference']),
    role: row['role'] === 'in' ? 'in' : 'out',
    isFile: Number(row['is_file']) === 1,
    size: Number(row['size'] ?? 0),
    createdAt: Number(row['created_at'] ?? 0),
  }));
}

/** Remove a sealed payload. The author may do this; an imported copy too. */
export function deleteSealed(db: SqlDatabase, reference: string): boolean {
  const before = existsSealed(db, reference);
  if (!before) return false;
  db.prepare('DELETE FROM sealed WHERE reference = ?').run(reference);
  return true;
}

function rowToSealed(row: Record<string, unknown>): StoredSealed {
  return {
    reference: String(row['reference']),
    version: Number(row['version'] ?? 1),
    argon: {
      t: Number(row['argon_t'] ?? 3),
      m: Number(row['argon_m'] ?? 65536),
      p: Number(row['argon_p'] ?? 1),
    },
    salt: toBytes(row['salt']),
    nonce: toBytes(row['nonce']),
    ciphertext: toBytes(row['ciphertext']),
    role: row['role'] === 'in' ? 'in' : 'out',
    isFile: Number(row['is_file']) === 1,
    size: Number(row['size'] ?? 0),
    createdAt: Number(row['created_at'] ?? 0),
  };
}
