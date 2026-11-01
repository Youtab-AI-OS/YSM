import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../build/ysm/storage/vault.js';
import { totp } from '../build/ysm/crypto/auth.js';
import { base32Decode } from '../build/ysm/crypto/auth.js';

let pass = 0, fail = 0;
/**
 * Failure detail may contain a password or a decrypted value, so it is never
 * printed. Re-run the single failing case to inspect it.
 */
const check = (n, c, _detail = '') => {
  if (c) { pass++; console.log(`  PASS ${n}`); }
  else { fail++; console.log(`  FAIL ${n} (detail withheld: may contain test secrets)`); }
};

const dir = mkdtempSync(join(tmpdir(), 'ysm-vault-'));
const dbPath = join(dir, 'account.db');
const PASSWORD = 'correct horse battery staple';
const NAME = 'Alice';

try {
  console.log('=== create account ===');
  const created = Vault.create(dbPath, NAME, PASSWORD);
  check('create ok', created.ok, created.ok ? '' : created.message);
  if (!created.ok) process.exit(1);
  const onboarding = created.onboarding;
  check('totp secret is base32', /^[A-Z2-7]+$/.test(onboarding.totpSecretBase32));
  check('otpauth uri present', onboarding.totpUri.startsWith('otpauth://totp/'));
  check('10 recovery codes', onboarding.recoveryCodes.length === 10);
  check('db file exists', existsSync(dbPath));
  const publicId = created.vault.publicIdentity;
  created.vault.lock();
  check('vault locked', !created.vault.isUnlocked);

  const rawFile = readFileSync(dbPath);
  const rawText = rawFile.toString('latin1');
  console.log('=== data-at-rest inspection ===');
  check('plaintext password not in file', !rawText.includes(PASSWORD));
  check('display name not in plaintext', !rawText.includes(NAME));
  check('totp secret not in plaintext', !Buffer.from(rawFile).includes(Buffer.from(onboarding.totpSecretBase32)));
  check('file is not trivially empty', rawFile.length > 1000);

  console.log('=== unlock: wrong password ===');
  const badPw = Vault.unlock(dbPath, 'wrong password here', '000000');
  check('wrong password rejected', !badPw.ok && badPw.code === 'BAD_PASSWORD', JSON.stringify(badPw));

  console.log('=== unlock: correct password, wrong TOTP ===');
  const secret = base32Decode(onboarding.totpSecretBase32);
  const nowSec = Math.floor(Date.now() / 1000);
  const goodCode = totp(secret, nowSec);
  const wrongCode = goodCode === '000000' ? '111111' : '000000';
  const badTotp = Vault.unlock(dbPath, PASSWORD, wrongCode);
  check('wrong TOTP rejected', !badTotp.ok && badTotp.code === 'BAD_TOTP', JSON.stringify(badTotp));

  console.log('=== unlock: both factors correct ===');
  const ok = Vault.unlock(dbPath, PASSWORD, goodCode);
  check('unlock succeeds', ok.ok, ok.ok ? '' : JSON.stringify(ok));
  if (ok.ok) {
    check('display name recovered', ok.vault.displayName === NAME, ok.vault.displayName);
    check('public identity stable',
      Buffer.from(ok.vault.publicIdentity.agreement).equals(Buffer.from(publicId.agreement)) &&
      Buffer.from(ok.vault.publicIdentity.signing).equals(Buffer.from(publicId.signing)));
    check('vault reports unlocked', ok.vault.isUnlocked);

    console.log('=== TOTP replay ===');
    const replay = Vault.unlock(dbPath, PASSWORD, goodCode);
    check('same code replayed rejected', !replay.ok && (replay.code === 'TOTP_REPLAY' || replay.code === 'LOCKED_OUT'), JSON.stringify(replay));

    ok.vault.lock();
  }

  console.log('=== lockout after repeated failures ===');
  const dir2 = mkdtempSync(join(tmpdir(), 'ysm-lock-'));
  const db2 = join(dir2, 'a.db');
  const c2 = Vault.create(db2, 'Bob', PASSWORD);
  if (c2.ok) {
    const s2 = base32Decode(c2.onboarding.totpSecretBase32);
    c2.vault.lock();
    let last;
    for (let i = 0; i < 7; i++) {
      last = Vault.unlock(db2, 'wrong password!!', '000000');
    }
    check('locked out after repeated failures', last.code === 'LOCKED_OUT' || last.code === 'BAD_PASSWORD', last.code);
    // Even the correct password must now be blocked.
    const blocked = Vault.unlock(db2, PASSWORD, totp(s2, Math.floor(Date.now() / 1000)));
    check('correct credentials blocked while locked out', !blocked.ok && blocked.code === 'LOCKED_OUT', JSON.stringify(blocked));
    rmSync(dir2, { recursive: true, force: true });
  }

  console.log('=== duplicate account refused ===');
  const dup = Vault.create(dbPath, 'Mallory', PASSWORD);
  check('second account in same file refused', !dup.ok && dup.code === 'ACCOUNT_EXISTS');

  console.log('=== weak password refused at creation ===');
  const weak = Vault.create(join(dir, 'weak.db'), 'X', 'short');
  check('weak password refused', !weak.ok && weak.code === 'TOO_SHORT');
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
