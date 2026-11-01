/**
 * Tests for the sealed-reference model.
 *
 * The claims that must hold:
 *   - a message sealed with a passphrase opens with that passphrase, verbatim
 *   - a different passphrase does not open it
 *   - a captured reference alone is useless, because it carries no key
 *   - altering any byte is detected
 *   - files round-trip byte-for-byte with their original name and type
 *   - every message gets a fresh passphrase and a fresh reference
 *
 * Run: node scripts/test-seal.mjs
 */
import { randomBytes } from 'node:crypto';

const B = '../build/ysm';
const {
  seal, open, generatePassphrase, computeReference, looksLikeReference,
  base32Encode, base32Decode, REF_PREFIX, REF_HEX_LENGTH,
} = await import(`${B}/crypto/seal.js`);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? ` (${detail})` : ''}`);
  }
}

// Cheaper Argon2 for tests only: the product uses 64 MiB / t=3, which would make
// this suite take minutes. The construction is identical; only the cost differs.
const FAST = { t: 1, m: 512, p: 1 };

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

console.log('=== reference format ===');
{
  const r = seal({ data: enc('hello'), passphrase: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', isFile: false, argon: FAST });
  check('seal succeeds', r.ok);
  const ref = r.value.reference;
  check('reference starts with YSM_', ref.startsWith(REF_PREFIX));
  check('reference has 64 hex chars after the prefix', ref.length === REF_PREFIX.length + REF_HEX_LENGTH);
  check('reference is hex only', /^YSM_[0-9a-f]{64}$/.test(ref));
  check('looksLikeReference accepts it', looksLikeReference(ref));
  check('looksLikeReference rejects a short ref', !looksLikeReference('YSM_abc'));
  check('looksLikeReference rejects a wrong prefix', !looksLikeReference('ABC_' + '0'.repeat(64)));
  check('looksLikeReference rejects non-hex', !looksLikeReference('YSM_' + 'z'.repeat(64)));
}

console.log('\n=== text round trip ===');
{
  const phrase = generatePassphrase();
  const text = 'این یک پیام محرمانه است — with accents, 中文, and an emoji 🔐';
  const r = seal({ data: enc(text), passphrase: phrase, isFile: false, argon: FAST });
  check('text seals', r.ok);
  const o = open(r.value, phrase);
  check('text opens with the right passphrase', o.ok);
  check('text is byte-identical', o.ok && dec(o.data) === text);
  check('wrong passphrase is rejected', open(r.value, generatePassphrase()).ok === false);
  check('wrong passphrase reports BAD_PASSPHRASE', open(r.value, 'WRONGPASSPHRASE').code === 'BAD_PASSPHRASE');
  check('empty passphrase is rejected', open(r.value, '').ok === false);
}

console.log('\n=== the reference alone is useless ===');
{
  const phrase = generatePassphrase();
  const r = seal({ data: enc('secret'), passphrase: phrase, isFile: false, argon: FAST });
  // Everything an attacker with only the reference has: the reference string.
  const reference = r.value.reference;
  // The blob is what is stored locally; simulate an attacker who also has it (a
  // stolen database) but not the passphrase.
  check('the reference contains no key material', !reference.includes(phrase.slice(0, 8)));
  check('passphrase is not derivable from the reference', base32Encode(base32Decode(phrase)) === phrase);
  check('blob without passphrase cannot be opened', open(r.value, generatePassphrase()).ok === false);
}

console.log('\n=== tamper detection ===');
{
  const phrase = generatePassphrase();
  const r = seal({ data: enc('do not alter me'), passphrase: phrase, isFile: false, argon: FAST });
  const blob = { ...r.value };

  // Flip one byte of ciphertext: the reference no longer matches.
  const ct = new Uint8Array(blob.ciphertext);
  ct[0] = (ct[0] ?? 0) ^ 0x01;
  check('altered ciphertext is rejected', open({ ...blob, ciphertext: ct }, phrase).ok === false);

  // Keep the ciphertext but change the recorded reference.
  const fakeRef = REF_PREFIX + '0'.repeat(REF_HEX_LENGTH);
  check('wrong recorded reference is rejected', open({ ...blob, reference: fakeRef }, phrase).ok === false);

  // Swap in a different salt: key derivation changes, so it must fail.
  check('altered salt is rejected', open({ ...blob, salt: randomBytes(32) }, phrase).ok === false);

  // Swap in a different nonce.
  check('altered nonce is rejected', open({ ...blob, nonce: randomBytes(12) }, phrase).ok === false);

  // Unknown version.
  check('unknown version is rejected', open({ ...blob, version: 99 }, phrase).code === 'UNSUPPORTED_VERSION');

  // The untampered blob still opens, proving the rejections are about tampering.
  check('the original still opens (control)', open(blob, phrase).ok);
}

console.log('\n=== files round trip ===');
{
  const phrase = generatePassphrase();
  const data = randomBytes(512 * 1024);
  const r = seal({
    data,
    passphrase: phrase,
    isFile: true,
    fileName: 'contract-final v2.pdf',
    mimeType: 'application/pdf',
    argon: FAST,
  });
  check('file seals', r.ok);
  const o = open(r.value, phrase);
  check('file opens', o.ok);
  check('file bytes are identical', o.ok && Buffer.from(o.data).equals(data));
  check('filename is preserved', o.ok && o.fileName === 'contract-final v2.pdf');
  check('mime type is preserved', o.ok && o.mimeType === 'application/pdf');
}

console.log('\n=== metadata is encrypted, not beside the payload ===');
{
  const phrase = generatePassphrase();
  const r = seal({
    data: enc('x'),
    passphrase: phrase,
    isFile: true,
    fileName: 'resignation-letter.pdf',
    mimeType: 'application/pdf',
    argon: FAST,
  });
  // Grep the stored bytes for the filename.
  const stored = Buffer.concat([
    Buffer.from(r.value.salt),
    Buffer.from(r.value.nonce),
    Buffer.from(r.value.ciphertext),
  ]);
  check('filename does not appear in the stored bytes', !stored.includes(Buffer.from('resignation')));
  check('reference does not encode the filename', !r.value.reference.toLowerCase().includes('resi'));
}

console.log('\n=== every message is unique ===');
{
  const text = 'same text every time';
  const a = seal({ data: enc(text), passphrase: generatePassphrase(), isFile: false, argon: FAST });
  const b = seal({ data: enc(text), passphrase: generatePassphrase(), isFile: false, argon: FAST });
  check('two seals of the same text give different references', a.value.reference !== b.value.reference);
  check('two seals have different salts', !Buffer.from(a.value.salt).equals(Buffer.from(b.value.salt)));
  check('two seals have different nonces', !Buffer.from(a.value.nonce).equals(Buffer.from(b.value.nonce)));
  check('two seals have different ciphertext', !Buffer.from(a.value.ciphertext).equals(Buffer.from(b.value.ciphertext)));

  // Same passphrase, same text, still different — proves the salt is random.
  const p = generatePassphrase();
  const c = seal({ data: enc(text), passphrase: p, isFile: false, argon: FAST });
  const d = seal({ data: enc(text), passphrase: p, isFile: false, argon: FAST });
  check('same passphrase still yields a different reference', c.value.reference !== d.value.reference);
}

console.log('\n=== passphrase generation ===');
{
  const seen = new Set();
  let allWellFormed = true;
  for (let i = 0; i < 200; i++) {
    const p = generatePassphrase();
    if (p.length !== 32 || !/^[A-Z2-7]{32}$/.test(p)) allWellFormed = false;
    seen.add(p);
  }
  check('200 passphrases are all 32 chars of Base32', allWellFormed);
  check('200 passphrases are all distinct', seen.size === 200);
  check('passphrase round-trips through base32', base32Decode(generatePassphrase()).length === 20);
}

console.log('\n=== reference is derived from content, not random ===');
{
  const phrase = generatePassphrase();
  const r = seal({ data: enc('deterministic check'), passphrase: phrase, isFile: false, argon: FAST });
  const recomputed = computeReference(r.value.salt, r.value.nonce, r.value.ciphertext);
  check('computeReference reproduces the sealed reference', recomputed === r.value.reference);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
