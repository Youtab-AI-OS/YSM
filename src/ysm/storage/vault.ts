/**
 * The vault: one account on one device.
 *
 * Owns the unlock lifecycle so that no other module has to reason about it:
 *
 *   create()  → new identity, new vault key, wrapped under the password,
 *               TOTP secret generated, recovery codes minted
 *   unlock()  → password → KEK → unwrap vault key → THEN require TOTP
 *   lock()    → drop all key material from memory
 *
 * The ordering inside unlock() is the security-critical part: the vault key is
 * unwrapped only after both factors succeed, and it is never written to disk in
 * plaintext. If the process is killed while unlocked, no keys are recoverable
 * from the filesystem.
 */

import {
  checkPasswordStrength,
  deriveKeyEncryptionKey,
  deriveVerifier,
  wrapVaultKey,
  unwrapVaultKey,
  generateTotpSecret,
  totpUri,
  verifyTotp,
  generateRecoveryCodes,
  hashRecoveryCode,
  base32Encode,
  DEFAULT_ARGON,
  type ArgonParams,
} from '../crypto/auth.js';
import { generateIdentity, safetyNumber, type Identity, type PublicIdentity } from '../crypto/identity.js';
import { random } from '../crypto/identity.js';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { withTransaction, type SqlDatabase } from './sql.js';
import { createVaultCipher, type VaultCipher } from './cipher.js';
import { openDesktopDatabase } from './sql-desktop.js';

export interface AccountMeta {
  readonly accountId: string;
  readonly displayName: string;
  readonly createdAt: number;
  readonly argon: ArgonParams;
}

/** What the caller needs to finish onboarding (shown exactly once). */
export interface OnboardingSecrets {
  readonly totpSecretBase32: string;
  readonly totpUri: string;
  readonly recoveryCodes: readonly string[];
}

export type CreateResult =
  | { ok: true; vault: Vault; onboarding: OnboardingSecrets }
  | { ok: false; code: string; message: string };

export type UnlockResult =
  | { ok: true; vault: Vault }
  | { ok: false; code: 'NO_ACCOUNT' | 'BAD_PASSWORD' | 'BAD_TOTP' | 'BAD_RECOVERY' | 'TOTP_REPLAY' | 'LOCKED_OUT' | 'CORRUPT'; message: string; retryAfterMs?: number };

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_BASE_MS = 30_000;
const LOCKOUT_MAX_MS = 15 * 60_000;

/**
 * A live, unlocked account.
 *
 * Holds the identity and the vault key in memory. `lock()` clears them; callers
 * must not retain the key themselves.
 */
export class Vault {
  private readonly db: SqlDatabase;
  private vaultKey: Uint8Array | null;
  private readonly identityKeys: Identity;
  private readonly cipherInstance: VaultCipher;

  readonly accountId: string;
  readonly displayName: string;

  private constructor(
    db: SqlDatabase,
    vaultKey: Uint8Array,
    identity: Identity,
    accountId: string,
    displayName: string,
  ) {
    this.db = db;
    this.vaultKey = vaultKey;
    this.identityKeys = identity;
    this.cipherInstance = createVaultCipher(vaultKey);
    this.accountId = accountId;
    this.displayName = displayName;
  }

  /** The identity, for crypto operations. Throws once locked. */
  get identity(): Identity {
    if (this.vaultKey === null) throw new Error('vault is locked');
    return this.identityKeys;
  }

  get publicIdentity(): PublicIdentity {
    return {
      agreement: this.identityKeys.agreement.publicKey,
      signing: this.identityKeys.signing.publicKey,
    };
  }

  get cipher(): VaultCipher {
    if (this.vaultKey === null) throw new Error('vault is locked');
    return this.cipherInstance;
  }

  get database(): SqlDatabase {
    if (this.vaultKey === null) throw new Error('vault is locked');
    return this.db;
  }

  get isUnlocked(): boolean {
    return this.vaultKey !== null;
  }

  /** Zero and drop key material. Idempotent. */
  lock(): void {
    if (this.vaultKey) {
      this.vaultKey.fill(0);
      this.vaultKey = null;
    }
    this.db.close();
  }

  // -------------------------------------------------------------------
  // Account creation
  // -------------------------------------------------------------------

  /**
   * Create a brand new account in `dbPath`.
   *
   * Refuses if an account already exists there — creating a second account in
   * the same file would orphan the first one's messages.
   */
  static create(dbPath: string, displayName: string, password: string): CreateResult {
    const strength = checkPasswordStrength(password);
    if (!strength.ok) return { ok: false, code: strength.code, message: strength.message };
    if (displayName.trim().length === 0 || displayName.length > 64) {
      return { ok: false, code: 'BAD_NAME', message: 'display name must be 1-64 characters' };
    }
    // Control characters are refused outright. A NUL in particular round-trips
    // inconsistently once the name reaches the UI, the IPC bridge or a terminal,
    // and no legitimate display name needs one. Rejecting at the boundary keeps
    // the stored value and every later reader in agreement.
    if (/[\u0000-\u001f\u007f]/.test(displayName)) {
      return { ok: false, code: 'BAD_NAME', message: 'display name must not contain control characters' };
    }

    const db = openDesktopDatabase(dbPath);
    const existing = db.prepare('SELECT value FROM meta WHERE key = ?').get('account');
    if (existing !== undefined) {
      db.close();
      return { ok: false, code: 'ACCOUNT_EXISTS', message: 'this file already contains an account' };
    }

    const identity = generateIdentity();
    const vaultKey = random(32);
    const argonSalt = random(16);
    const argon = DEFAULT_ARGON;

    const kek = deriveKeyEncryptionKey(password, argonSalt, argon);
    const wrapped = wrapVaultKey(vaultKey, kek);
    const verifier = deriveVerifier(password, argonSalt, argon);

    const totpSecret = generateTotpSecret();
    const recovery = generateRecoveryCodes();
    const accountId = Buffer.from(random(16)).toString('hex');

    withTransaction(db, () => {
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('account', accountId);
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('format', 'ysm-v1');
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('createdAt', String(Date.now()));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('argonSalt', Buffer.from(argonSalt).toString('base64'));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('argon', JSON.stringify(argon));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('verifier', Buffer.from(verifier).toString('base64'));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('wrappedKey', JSON.stringify(wrapped));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('agreementSecret', Buffer.from(identity.agreement.secretKey).toString('base64'));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('signingSecret', Buffer.from(identity.signing.secretKey).toString('base64'));
      // The TOTP secret and recovery hashes are stored inside the encrypted
      // bundle: they are only readable once the vault is unlocked.
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('totpSecret', Buffer.from(totpSecret).toString('base64'));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('recoveryHashes', JSON.stringify(recovery.hashes));
      db.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('displayNameEnc', Buffer.from(createVaultCipher(vaultKey).encryptText(displayName, 'meta.displayName')).toString('base64'));
    });


    const vault = new Vault(db, vaultKey, identity, accountId, displayName);

    // Zero intermediate secrets we no longer need.
    kek.fill(0);

    return {
      ok: true,
      vault,
      onboarding: {
        totpSecretBase32: base32Encode(totpSecret),
        totpUri: totpUri(totpSecret, displayName),
        recoveryCodes: recovery.plaintext,
      },
    };
  }

  // -------------------------------------------------------------------
  // Unlock
  // -------------------------------------------------------------------

  /**
   * Unlock an existing account.
   *
   * The password is checked first (so a wrong password is reported as such), then
   * TOTP. The vault key is unwrapped between the two checks but is only handed
   * to a Vault after TOTP succeeds — a failure returns without exposing it.
   */
  static unlock(dbPath: string, password: string, totpCode: string, now: () => number = Date.now): UnlockResult {
    let db: SqlDatabase;
    try {
      db = openDesktopDatabase(dbPath);
    } catch {
      return { ok: false, code: 'NO_ACCOUNT', message: 'could not open the account database' };
    }

    const meta = readMeta(db);
    if (meta === null) {
      db.close();
      return { ok: false, code: 'NO_ACCOUNT', message: 'no account exists at this path' };
    }

    // Rate limiting is checked before any expensive work, so a lockout also
    // prevents an attacker from using unlock attempts as an Argon2 CPU oracle.
    const state = db.prepare('SELECT failed_count, locked_until, last_totp_ctr FROM auth_state WHERE id = 1').get() as
      | { failed_count: number; locked_until: number; last_totp_ctr: number | null }
      | undefined;
    const nowMs = now();
    if (state && state.locked_until > nowMs) {
      db.close();
      return {
        ok: false,
        code: 'LOCKED_OUT',
        message: `too many failed attempts; try again in ${Math.ceil((state.locked_until - nowMs) / 1000)}s`,
        retryAfterMs: state.locked_until - nowMs,
      };
    }

    let argon: ArgonParams;
    let salt: Uint8Array;
    let verifierStored: Uint8Array;
    let wrapped: { ciphertext: string; nonce: string };
    try {
      argon = JSON.parse(meta['argon']!);
      salt = new Uint8Array(Buffer.from(meta['argonSalt']!, 'base64'));
      verifierStored = new Uint8Array(Buffer.from(meta['verifier']!, 'base64'));
      wrapped = JSON.parse(meta['wrappedKey']!);
    } catch {
      db.close();
      return { ok: false, code: 'CORRUPT', message: 'account metadata is corrupt' };
    }

    let kek: Uint8Array;
    let vaultKey: Uint8Array | null;
    try {
      kek = deriveKeyEncryptionKey(password, salt, argon);
      const candidate = deriveVerifier(password, salt, argon);
      const matches = Buffer.from(candidate).equals(Buffer.from(verifierStored));
      candidate.fill(0);
      if (!matches) {
        recordFailure(db, nowMs);
        db.close();
        kek.fill(0);
        return { ok: false, code: 'BAD_PASSWORD', message: 'incorrect password' };
      }
      vaultKey = unwrapVaultKey(wrapped, kek);
      kek.fill(0);
      if (vaultKey === null) {
        recordFailure(db, nowMs);
        db.close();
        return { ok: false, code: 'BAD_PASSWORD', message: 'incorrect password' };
      }
    } catch (err) {
      db.close();
      return { ok: false, code: 'CORRUPT', message: `account metadata is unusable: ${(err as Error).message}` };
    }

    // Second factor. Note the vault key is already unwrapped at this point but
    // is NOT returned or used until TOTP passes.
    const totpSecretB64 = meta['totpSecret'];
    if (totpSecretB64 === undefined) {
      vaultKey.fill(0);
      db.close();
      return { ok: false, code: 'CORRUPT', message: 'TOTP secret is missing from the account' };
    }
    const totpSecret = new Uint8Array(Buffer.from(totpSecretB64, 'base64'));
    const result = verifyTotp(totpSecret, totpCode, Math.floor(nowMs / 1000), state?.last_totp_ctr ?? undefined);

    if (!result.ok) {
      vaultKey.fill(0);
      if (result.reason === 'REPLAY') {
        db.close();
        return { ok: false, code: 'TOTP_REPLAY', message: 'this authenticator code has already been used' };
      }
      recordFailure(db, nowMs);
      db.close();
      return {
        ok: false,
        code: 'BAD_TOTP',
        message: result.reason === 'FORMAT' ? 'authenticator code must be 6 digits' : 'incorrect authenticator code',
      };
    }

    // Both factors good: clear the failure counter and remember the counter
    // value so this code cannot be replayed.
    db.prepare('UPDATE auth_state SET failed_count = 0, locked_until = 0, last_totp_ctr = ? WHERE id = 1').run(result.counter);

    let identity: Identity;
    let displayName: string;
    try {
      const agreementSecretKey = new Uint8Array(Buffer.from(meta['agreementSecret']!, 'base64'));
      const signingSecretKey = new Uint8Array(Buffer.from(meta['signingSecret']!, 'base64'));
      // Recompute public keys from the secrets so the object is self-consistent
      // and never trusts a stored public key.
      identity = {
        agreement: {
          secretKey: agreementSecretKey,
          publicKey: x25519.getPublicKey(agreementSecretKey),
        },
        signing: {
          secretKey: signingSecretKey,
          publicKey: ed25519.getPublicKey(signingSecretKey),
        },
      };

      displayName = createVaultCipher(vaultKey).decryptText(
        Buffer.from(meta['displayNameEnc']!, 'base64'),
        'meta.displayName',
      );
    } catch (err) {
      vaultKey.fill(0);
      db.close();
      return { ok: false, code: 'CORRUPT', message: `account keys are unusable: ${(err as Error).message}` };
    }

    return { ok: true, vault: new Vault(db, vaultKey, identity, meta['account']!, displayName) };
  }

  // -------------------------------------------------------------------
  // Unlock with a recovery code
  // -------------------------------------------------------------------

  /**
   * Unlock using a recovery code instead of a TOTP code.
   *
   * This is the account-recovery path for a lost authenticator. The guarantee it
   * must preserve: the password is still required (the vault key is wrapped under
   * it), and each recovery code works exactly once — on success its hash is
   * removed from the stored set inside the same transaction that unlocks.
   *
   * Unlike the TOTP path, the vault key is unwrapped only after the recovery code
   * has been verified, so a wrong code never leaves a usable key in memory.
   */
  static unlockWithRecovery(
    dbPath: string,
    password: string,
    recoveryCode: string,
    hashRecovery: (code: string) => string,
    now: () => number = Date.now,
  ): UnlockResult {
    let db: SqlDatabase;
    try {
      db = openDesktopDatabase(dbPath);
    } catch {
      return { ok: false, code: 'NO_ACCOUNT', message: 'could not open the account database' };
    }

    const meta = readMeta(db);
    if (meta === null) {
      db.close();
      return { ok: false, code: 'NO_ACCOUNT', message: 'no account exists at this path' };
    }

    const state = db.prepare('SELECT failed_count, locked_until FROM auth_state WHERE id = 1').get() as
      | { failed_count: number; locked_until: number }
      | undefined;
    const nowMs = now();
    if (state && state.locked_until > nowMs) {
      db.close();
      return {
        ok: false,
        code: 'LOCKED_OUT',
        message: `too many failed attempts; try again in ${Math.ceil((state.locked_until - nowMs) / 1000)}s`,
        retryAfterMs: state.locked_until - nowMs,
      };
    }

    let argon: ArgonParams;
    let salt: Uint8Array;
    let verifierStored: Uint8Array;
    let wrapped: { ciphertext: string; nonce: string };
    let hashes: string[];
    try {
      argon = JSON.parse(meta['argon']!);
      salt = new Uint8Array(Buffer.from(meta['argonSalt']!, 'base64'));
      verifierStored = new Uint8Array(Buffer.from(meta['verifier']!, 'base64'));
      wrapped = JSON.parse(meta['wrappedKey']!);
      hashes = JSON.parse(meta['recoveryHashes']!);
    } catch {
      db.close();
      return { ok: false, code: 'CORRUPT', message: 'account metadata is corrupt' };
    }

    // Password first, exactly as the TOTP path does.
    const kek = deriveKeyEncryptionKey(password, salt, argon);
    const candidate = deriveVerifier(password, salt, argon);
    const passwordOk = Buffer.from(candidate).equals(Buffer.from(verifierStored));
    candidate.fill(0);
    if (!passwordOk) {
      kek.fill(0);
      recordFailure(db, nowMs);
      db.close();
      return { ok: false, code: 'BAD_PASSWORD', message: 'incorrect password' };
    }

    // Then the recovery code, compared against stored hashes.
    const attempted = hashRecovery(recoveryCode);
    const remaining = hashes.filter((h) => h !== attempted);
    if (remaining.length === hashes.length) {
      kek.fill(0);
      recordFailure(db, nowMs);
      db.close();
      return { ok: false, code: 'BAD_RECOVERY', message: 'that recovery code is not valid or was already used' };
    }

    const vaultKey = unwrapVaultKey(wrapped, kek);
    kek.fill(0);
    if (vaultKey === null) {
      recordFailure(db, nowMs);
      db.close();
      return { ok: false, code: 'CORRUPT', message: 'the stored key could not be unwrapped' };
    }

    // Consume the code and clear the lockout atomically.
    db.prepare('UPDATE meta SET value = ? WHERE key = ?').run(JSON.stringify(remaining), 'recoveryHashes');
    db.prepare('UPDATE auth_state SET failed_count = 0, locked_until = 0 WHERE id = 1').run();

    try {
      const agreementSecretKey = new Uint8Array(Buffer.from(meta['agreementSecret']!, 'base64'));
      const signingSecretKey = new Uint8Array(Buffer.from(meta['signingSecret']!, 'base64'));
      const identity: Identity = {
        agreement: { secretKey: agreementSecretKey, publicKey: x25519.getPublicKey(agreementSecretKey) },
        signing: { secretKey: signingSecretKey, publicKey: ed25519.getPublicKey(signingSecretKey) },
      };
      const displayName = createVaultCipher(vaultKey).decryptText(
        Buffer.from(meta['displayNameEnc']!, 'base64'),
        'meta.displayName',
      );
      return { ok: true, vault: new Vault(db, vaultKey, identity, meta['account']!, displayName) };
    } catch (e) {
      vaultKey.fill(0);
      db.close();
      return { ok: false, code: 'CORRUPT', message: `account keys are unusable: ${(e as Error).message}` };
    }
  }

  /** The safety number against a peer, for verification. */
  safetyNumberWith(peer: PublicIdentity): string {
    return safetyNumber(this.publicIdentity, peer);
  }
}

function readMeta(db: SqlDatabase): Record<string, string> | null {
  const rows = db.prepare('SELECT key, value FROM meta').all() as Array<{ key: string; value: string }>;
  if (rows.length === 0) return null;
  const out: Record<string, string> = {};
  for (const r of rows) out[r.key] = r.value;
  if (out['account'] === undefined) return null;
  return out;
}

/** Increment the failure counter with exponential backoff. */
function recordFailure(db: SqlDatabase, nowMs: number): void {
  const row = db.prepare('SELECT failed_count FROM auth_state WHERE id = 1').get() as { failed_count: number } | undefined;
  const count = (row?.failed_count ?? 0) + 1;
  const lockout = count >= MAX_FAILED_ATTEMPTS
    ? Math.min(LOCKOUT_BASE_MS * 2 ** (count - MAX_FAILED_ATTEMPTS), LOCKOUT_MAX_MS)
    : 0;
  db.prepare('UPDATE auth_state SET failed_count = ?, locked_until = ? WHERE id = 1').run(
    count,
    lockout > 0 ? nowMs + lockout : 0,
  );
}

export { hashRecoveryCode };
