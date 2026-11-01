import {
  deriveKeyEncryptionKey, deriveVerifier, wrapVaultKey, unwrapVaultKey,
  checkPasswordStrength, generateTotpSecret, totp, verifyTotp,
  totpUri, base32Encode, base32Decode, generateRecoveryCodes, hashRecoveryCode,
  DEFAULT_ARGON,
} from '../build/ysm/crypto/auth.js';
import { random } from '../build/ysm/crypto/identity.js';

let pass = 0, fail = 0;
const check = (n, c, x = '') => { if (c) { pass++; console.log(`  PASS ${n}`); } else { fail++; console.log(`  FAIL ${n} ${x}`); } };

console.log('=== RFC 6238 TOTP test vectors (SHA1, 6 digits) ===');
// RFC 6238 uses a 20-byte ASCII secret "12345678901234567890"
const rfcSecret = new TextEncoder().encode('12345678901234567890');
const rfcCases = [
  [59, '287082'],
  [1111111109, '081804'],
  [1111111111, '050471'],
  [1234567890, '005924'],
  [2000000000, '279037'],
  [20000000000, '353130'],
];
for (const [t, expected] of rfcCases) {
  const got = totp(rfcSecret, t);
  check(`TOTP t=${t}`, got === expected, `got ${got} want ${expected}`);
}

console.log('=== TOTP verify ===');
const secret = generateTotpSecret();
const now = 1_700_000_000;
const code = totp(secret, now);
check('current code accepted', verifyTotp(secret, code, now).ok);
check('code with spaces accepted', verifyTotp(secret, `${code.slice(0,3)} ${code.slice(3)}`, now).ok);
check('previous window accepted', verifyTotp(secret, totp(secret, now - 30), now).ok);
check('next window accepted', verifyTotp(secret, totp(secret, now + 30), now).ok);
check('two windows back rejected', !verifyTotp(secret, totp(secret, now - 90), now).ok);
check('wrong code rejected', !verifyTotp(secret, '000000', now).ok || totp(secret, now) === '000000');
check('malformed rejected', verifyTotp(secret, 'abcdef', now).reason === 'FORMAT');
check('short rejected', verifyTotp(secret, '12345', now).reason === 'FORMAT');

// replay protection
const r1 = verifyTotp(secret, code, now);
check('first use ok', r1.ok);
const r2 = verifyTotp(secret, code, now, r1.counter);
check('replay rejected', !r2.ok && r2.reason === 'REPLAY');

console.log('=== base32 ===');
const b32 = base32Encode(rfcSecret);
check('base32 encode known', b32 === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', b32);
check('base32 roundtrip', Buffer.from(base32Decode(b32)).equals(Buffer.from(rfcSecret)));

console.log('=== otpauth URI ===');
const uri = totpUri(secret, 'alice');
check('otpauth scheme', uri.startsWith('otpauth://totp/'));
check('has secret param', uri.includes('secret='));
check('has issuer', uri.includes('issuer=YSM'));
check('roundtrip secret from uri',
  Buffer.from(base32Decode(new URL(uri).searchParams.get('secret'))).equals(Buffer.from(secret)));

console.log('=== Argon2id + vault wrap ===');
const t0 = Date.now();
const salt = random(16);
const kek = deriveKeyEncryptionKey('correct horse battery staple', salt);
const argonMs = Date.now() - t0;
check('argon2 produces 32 bytes', kek.length === 32);
console.log(`  (argon2id ${DEFAULT_ARGON.memoryKiB}KiB t=${DEFAULT_ARGON.timeCost} took ${argonMs}ms)`);
const kek2 = deriveKeyEncryptionKey('correct horse battery staple', salt);
check('argon2 deterministic for same salt', Buffer.from(kek).equals(Buffer.from(kek2)));
const kek3 = deriveKeyEncryptionKey('correct horse battery stapl3', salt);
check('argon2 differs for wrong password', !Buffer.from(kek).equals(Buffer.from(kek3)));

const verifier = deriveVerifier('correct horse battery staple', salt);
check('verifier differs from KEK', !Buffer.from(verifier).equals(Buffer.from(kek)));

const vaultKey = random(32);
const wrapped = wrapVaultKey(vaultKey, kek);
const unwrapped = unwrapVaultKey(wrapped, kek);
check('vault key roundtrip', unwrapped !== null && Buffer.from(unwrapped).equals(Buffer.from(vaultKey)));
check('wrong KEK cannot unwrap', unwrapVaultKey(wrapped, kek3) === null);
// tampered wrapped key
const badWrapped = { ...wrapped, ciphertext: Buffer.from(Buffer.from(wrapped.ciphertext, 'base64')).toString('base64') };
const b = Buffer.from(badWrapped.ciphertext, 'base64'); b[0] ^= 1; badWrapped.ciphertext = b.toString('base64');
check('tampered wrapped key rejected', unwrapVaultKey(badWrapped, kek) === null);

console.log('=== password policy ===');
check('short rejected', checkPasswordStrength('short').code === 'TOO_SHORT');
check('common rejected', checkPasswordStrength('passwordpassword').code === 'COMMON');
check('all same char rejected', checkPasswordStrength('aaaaaaaaaaaaaaaa').code === 'SAME_CHARACTER');
check('two-char pattern rejected', checkPasswordStrength('ababababababab').code === 'REPEATED');
check('good password accepted', checkPasswordStrength('Tr0ub4dor&3xyz').ok);
check('unicode password accepted', checkPasswordStrength('رمزعبورمن۱۲۳۴۵۶').ok);

console.log('=== recovery codes ===');
const rec = generateRecoveryCodes();
check('10 codes', rec.plaintext.length === 10 && rec.hashes.length === 10);
check('unique', new Set(rec.plaintext).size === 10);
check('format XXXXX-XXXXX-XXXXX-XXXXX', rec.plaintext.every((c) => /^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$/.test(c)), rec.plaintext[0]);
check('hash is 64 hex', /^[0-9a-f]{64}$/.test(rec.hashes[0]));
check('hash stable', hashRecoveryCode(rec.plaintext[0]) === rec.hashes[0]);
check('hash case-insensitive', hashRecoveryCode(rec.plaintext[0].toLowerCase()) === rec.hashes[0]);
check('different codes differ', hashRecoveryCode('AAAAA-AAAAA-AAAAA-AAAAA') !== hashRecoveryCode('AAAAA-AAAAA-AAAAA-AAAAB'));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
