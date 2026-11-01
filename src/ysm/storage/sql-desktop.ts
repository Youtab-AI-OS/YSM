/**
 * Desktop adapter: `node:sqlite` behind the `SqlDatabase` interface.
 *
 * Using the built-in engine means there is no native module to compile and keep
 * in ABI sync with Electron, which removes the single largest cause of
 * "works on my machine, crashes after install" in an Electron app.
 */
import { DatabaseSync } from 'node:sqlite';
import { POST_SCHEMA_SQL, SCHEMA, type SqlDatabase, type SqlRow, type SqlStatement, type SqlValue } from './sql.js';

/** node:sqlite accepts Uint8Array directly for BLOB binding. */
function bind(params: SqlValue[]): SqlValue[] {
  return params;
}

export function openDesktopDatabase(path: string): SqlDatabase {
  const raw = new DatabaseSync(path);

  // WAL keeps reads from blocking writes. `synchronous = FULL` costs a little
  // throughput and guarantees a committed row survives a power cut, which
  // matters more for a message store.
  raw.exec('PRAGMA journal_mode = WAL;');
  raw.exec('PRAGMA foreign_keys = OFF;');
  raw.exec('PRAGMA synchronous = FULL;');
  raw.exec(SCHEMA);
  raw.exec(POST_SCHEMA_SQL);

  let depth = 0;

  const db: SqlDatabase = {
    exec(sql: string): void {
      raw.exec(sql);
    },

    prepare(sql: string): SqlStatement {
      const stmt = raw.prepare(sql);
      return {
        run(...params: SqlValue[]) {
          const r = stmt.run(...bind(params));
          return { changes: Number(r.changes ?? 0) };
        },
        get(...params: SqlValue[]): SqlRow | undefined {
          const row = stmt.get(...bind(params));
          return row as SqlRow | undefined;
        },
        all(...params: SqlValue[]): SqlRow[] {
          return stmt.all(...bind(params)) as SqlRow[];
        },
      };
    },

    begin(): void {
      // Nested BEGIN is an error in SQLite, so track depth and use SAVEPOINT for
      // the inner levels. A security-critical call can then nest safely.
      if (depth === 0) raw.exec('BEGIN');
      else raw.exec(`SAVEPOINT sp${depth}`);
      depth += 1;
    },

    commit(): void {
      depth -= 1;
      if (depth === 0) raw.exec('COMMIT');
      else raw.exec(`RELEASE sp${depth}`);
    },

    rollback(): void {
      depth -= 1;
      if (depth === 0) raw.exec('ROLLBACK');
      else raw.exec(`ROLLBACK TO sp${depth}`);
    },

    close(): void {
      raw.close();
    },
  };

  return db;
}
