/**
 * Key files and a small keyring.
 *
 * A key file on disk must be exactly 32 raw bytes (or 16/24 for the smaller
 * ciphers). Keeping the key out of argv, shell history and process listings is
 * the point; permissions are tightened to 0600 on POSIX and the file is
 * rejected if it is group/world readable.
 *
 * The keyring is a directory of <kid>.key files. It is intentionally simple:
 * no encryption-at-rest (that would just move the problem to another secret),
 * no network access, no automatic key generation behind the caller's back.
 */

import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fail, ok, type Result } from '../core/result.js';
import { fromHex, toHex } from '../core/codec.js';

/** Accepted raw key lengths. */
const ALLOWED_KEY_BYTES: ReadonlySet<number> = new Set([16, 24, 32]);

/** Key identifier accepted as a file name. Deliberately narrow. */
const KID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function isValidKid(kid: string): boolean {
  return KID_PATTERN.test(kid);
}

function isPosix(): boolean {
  return process.platform !== 'win32';
}

/**
 * Read a raw key from a file.
 *
 * Accepts either raw bytes or a hex text file (as produced by `--gen-key
 * --hex`), decided by length + charset so a mislabelled file cannot be used
 * with half the wrong key.
 */
export function readKeyFile(path: string): Result<Uint8Array> {
  const abs = resolve(path);
  let st: ReturnType<typeof statSync>;
  try {
    st = statSync(abs);
  } catch {
    return fail('BAD_KEY_LENGTH', `key file not found: ${abs}`);
  }
  if (!st.isFile()) return fail('BAD_KEY_LENGTH', `key path is not a regular file: ${abs}`);

  if (isPosix() && (st.mode & 0o077) !== 0) {
    return fail(
      'BAD_KEY_LENGTH',
      `key file ${abs} is accessible by other users (mode ${(st.mode & 0o777).toString(8)}); run: chmod 600 "${abs}"`,
    );
  }

  const raw = readFileSync(abs);
  if (ALLOWED_KEY_BYTES.has(raw.length)) return ok(new Uint8Array(raw));

  const asText = raw.toString('utf8').trim();
  if (/^[0-9a-fA-F]+$/.test(asText) && asText.length % 2 === 0 && ALLOWED_KEY_BYTES.has(asText.length / 2)) {
    try {
      return ok(fromHex(asText));
    } catch (e) {
      return fail('BAD_KEY_LENGTH', 'key file looks like hex but could not be parsed', e);
    }
  }

  return fail(
    'BAD_KEY_LENGTH',
    `key file ${abs} must be 16, 24 or 32 raw bytes, or a hex string of 32/48/64 characters (got ${raw.length} bytes)`,
  );
}

/**
 * Write a new key file. Fails if the target already exists so a key is never
 * silently overwritten.
 */
export function writeKeyFile(path: string, key: Uint8Array, asHex = false): Result<string> {
  const abs = resolve(path);
  if (existsSync(abs)) {
    return fail('MALFORMED_PARAMETER', `refusing to overwrite existing key file: ${abs}`);
  }
  if (!ALLOWED_KEY_BYTES.has(key.length)) {
    return fail('BAD_KEY_LENGTH', `key must be 16, 24 or 32 bytes (got ${key.length})`);
  }
  try {
    writeFileSync(abs, asHex ? `${toHex(key)}\n` : Buffer.from(key), {
      mode: 0o600,
      flag: 'wx',
    });
    if (isPosix()) chmodSync(abs, 0o600);
  } catch (e) {
    return fail('MALFORMED_PARAMETER', `could not write key file ${abs}`, e);
  }
  return ok(abs);
}

/** Resolve a key identifier to its key file inside a keyring directory. */
export function keyringPath(keyringDir: string, kid: string): Result<string> {
  if (!isValidKid(kid)) {
    return fail(
      'MALFORMED_PARAMETER',
      `key id ${JSON.stringify(kid)} is invalid: use 1-64 chars of A-Z a-z 0-9 . _ - and do not start with a dot`,
    );
  }
  return ok(join(resolve(keyringDir), `${kid}.key`));
}

/** Read a key from a keyring directory by identifier. */
export function readKeyFromRing(keyringDir: string, kid: string): Result<Uint8Array> {
  const p = keyringPath(keyringDir, kid);
  if (!p.ok) return p;
  if (!existsSync(p.value)) {
    return fail('UNKNOWN_RECIPIENT', `no key named ${JSON.stringify(kid)} in ${resolve(keyringDir)}`);
  }
  return readKeyFile(p.value);
}

/** Create the keyring directory if needed and write a key into it. */
export function writeKeyToRing(
  keyringDir: string,
  kid: string,
  key: Uint8Array,
  asHex = false,
): Result<string> {
  const p = keyringPath(keyringDir, kid);
  if (!p.ok) return p;
  try {
    mkdirSync(resolve(keyringDir), { recursive: true, mode: 0o700 });
  } catch (e) {
    return fail('MALFORMED_PARAMETER', `could not create keyring ${resolve(keyringDir)}`, e);
  }
  return writeKeyFile(p.value, key, asHex);
}

/** List the key identifiers present in a keyring directory. */
export function listKeyring(keyringDir: string): Result<string[]> {
  const dir = resolve(keyringDir);
  if (!existsSync(dir)) return ok([]);
  try {
    return ok(
      readdirSync(dir)
        .filter((f) => f.endsWith('.key'))
        .map((f) => basename(f, '.key'))
        .sort(),
    );
  } catch (e) {
    return fail('MALFORMED_PARAMETER', `could not read keyring ${dir}`, e);
  }
}
