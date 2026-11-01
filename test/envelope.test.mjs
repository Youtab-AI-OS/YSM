/**
 * The v2 authenticated envelope.
 *
 * These tests are the security contract. Each one corresponds to a concrete
 * attack or failure mode, and several of them would pass silently against a
 * naive implementation (round-trip only), which is why they assert the
 * *rejection* behaviour rather than just the happy path.
 */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  deriveMessageKeys,
  inspect,
  keyFingerprint,
  parseEnvelope,
  seal,
  unseal,
  unwrap,
} from '../dist/index.js';

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const KEY32 = randomBytes(32);
const KEY16 = randomBytes(16);
const KEY24 = randomBytes(24);

/** Seal and assert success. */
function sealOk(plaintext, opts) {
  const r = seal(plaintext, opts);
  assert.equal(r.ok, true, r.ok ? '' : `${r.code}: ${r.message}`);
  return r.value;
}

describe('v2 envelope: round trip', () => {
  it('round-trips text with the default cipher', () => {
    const env = sealOk(enc('hello world'), { key: KEY32 });
    const opened = unwrap(unseal(env, { key: KEY32 }));
    assert.equal(opened.text, 'hello world');
    assert.equal(opened.info.cipher, 'AES-256-CBC');
    assert.equal(opened.info.version, 2);
  });

  it('round-trips empty, 1-byte, block-boundary and large messages', () => {
    for (const n of [0, 1, 15, 16, 17, 255, 16 * 1024]) {
      const data = randomBytes(n);
      const env = sealOk(data, { key: KEY32 });
      const opened = unwrap(unseal(env, { key: KEY32 }));
      assert.equal(opened.plaintext.length, n, `length ${n}`);
      assert.equal(Buffer.from(opened.plaintext).toString('hex'), data.toString('hex'), `content ${n}`);
    }
  });

  it('round-trips binary data containing zero bytes and invalid UTF-8', () => {
    const data = new Uint8Array([0x00, 0xff, 0xfe, 0x80, 0x00, 0xc3, 0x28]);
    const env = sealOk(data, { key: KEY32 });
    const opened = unwrap(unseal(env, { key: KEY32 }));
    assert.deepEqual([...opened.plaintext], [...data]);
  });

  it('works with every supported key size', () => {
    for (const [key, cipher] of [
      [KEY16, 'AES-128-CBC'],
      [KEY24, 'AES-192-CBC'],
      [KEY32, 'AES-256-CBC'],
    ]) {
      const env = sealOk(enc('size test'), { key, cipher });
      const opened = unwrap(unseal(env, { key }));
      assert.equal(opened.text, 'size test');
      assert.equal(opened.info.cipher, cipher);
      assert.equal(opened.info.keyBits, Number(cipher.split('-')[1]));
    }
  });

  it('preserves Unicode exactly', () => {
    const samples = ['سلام دنیا', '🔐🔑', 'Ünïcödé', '日本語', 'עברית', 'a\nb\tc', ''];
    for (const s of samples) {
      const opened = unwrap(unseal(sealOk(enc(s), { key: KEY32 }), { key: KEY32 }));
      assert.equal(opened.text, s, JSON.stringify(s));
    }
  });
});

describe('v2 envelope: the fixed-IV leak is gone', () => {
  it('produces different ciphertext for identical plaintext', () => {
    const a = sealOk(enc('same message'), { key: KEY32 });
    const b = sealOk(enc('same message'), { key: KEY32 });
    assert.notEqual(a, b, 'a random IV per message must change the ciphertext');

    // The property that actually matters: an observer cannot tell two
    // messages are equal, because no ciphertext block repeats.
    const ctA = unwrap(parseEnvelope(a)).ciphertext;
    const ctB = unwrap(parseEnvelope(b)).ciphertext;
    for (let off = 0; off < ctA.length; off += 16) {
      const blockA = Buffer.from(ctA.subarray(off, off + 16)).toString('hex');
      for (let off2 = 0; off2 < ctB.length; off2 += 16) {
        const blockB = Buffer.from(ctB.subarray(off2, off2 + 16)).toString('hex');
        assert.notEqual(blockA, blockB, 'no ciphertext block may repeat across messages');
      }
    }
  });

  it('uses a distinct IV and salt on every seal', () => {
    const ivs = new Set();
    const salts = new Set();
    for (let i = 0; i < 50; i++) {
      const p = unwrap(parseEnvelope(sealOk(enc('x'), { key: KEY32 })));
      ivs.add(p.header.iv);
      salts.add(p.header.salt);
    }
    assert.equal(ivs.size, 50, 'IVs must be unique');
    assert.equal(salts.size, 50, 'salts must be unique');
  });
});

describe('v2 envelope: integrity', () => {
  const env = sealOk(enc('transfer 100 to alice'), { key: KEY32 });
  const parts = env.split('.');

  it('rejects any single-bit flip in the ciphertext', () => {
    const ct = Buffer.from(unwrap(parseEnvelope(env)).ciphertext);
    for (const byteIndex of [0, 1, 7, ct.length - 1]) {
      for (const bit of [0x01, 0x80]) {
        const mutated = Buffer.from(ct);
        mutated[byteIndex] ^= bit;
        const forged = [parts[0], parts[1], mutated.toString('base64url'), parts[3]].join('.');
        const r = unseal(forged, { key: KEY32 });
        assert.equal(r.ok, false, `flip at byte ${byteIndex} bit ${bit}`);
        assert.equal(r.code, 'INTEGRITY_FAILURE');
      }
    }
  });

  it('rejects a modified header (cipher downgrade attempt)', () => {
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.iv = Buffer.alloc(16, 7).toString('base64url');
    const forged = [parts[0], Buffer.from(JSON.stringify(header)).toString('base64url'), parts[2], parts[3]].join('.');
    const r = unseal(forged, { key: KEY32 });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'INTEGRITY_FAILURE');
  });

  it('rejects a modified tag', () => {
    const tag = Buffer.from(parts[3], 'base64url');
    tag[0] ^= 0xff;
    const forged = [parts[0], parts[1], parts[2], tag.toString('base64url')].join('.');
    assert.equal(unseal(forged, { key: KEY32 }).code, 'INTEGRITY_FAILURE');
  });

  it('rejects truncation of the ciphertext', () => {
    const ct = unwrap(parseEnvelope(env)).ciphertext;
    const truncated = ct.subarray(0, ct.length - 16);
    const forged = [parts[0], parts[1], Buffer.from(truncated).toString('base64url'), parts[3]].join('.');
    const r = unseal(forged, { key: KEY32 });
    assert.equal(r.ok, false, 'a truncated message must never open');
  });

  it('rejects a block-swapped ciphertext (CBC malleability)', () => {
    const ct = Buffer.from(unwrap(parseEnvelope(env)).ciphertext);
    // Swap the first two ciphertext blocks.
    const a = Buffer.from(ct.subarray(0, 16));
    const b = Buffer.from(ct.subarray(16, 32));
    b.copy(ct, 0);
    a.copy(ct, 16);
    const forged = [parts[0], parts[1], ct.toString('base64url'), parts[3]].join('.');
    assert.equal(unseal(forged, { key: KEY32 }).code, 'INTEGRITY_FAILURE');
  });

  it('checks the tag before the padding', () => {
    // With a wrong key, the failure must be INTEGRITY_FAILURE (not a padding
    // error). Reporting padding would be a decryption oracle.
    for (let i = 0; i < 40; i++) {
      const r = unseal(env, { key: randomBytes(32) });
      assert.equal(r.ok, false);
      assert.equal(r.code, 'INTEGRITY_FAILURE', 'a wrong key must not reach the padding check');
    }
  });

  it('rejects a wrong key of the correct length', () => {
    assert.equal(unseal(env, { key: randomBytes(32) }).code, 'INTEGRITY_FAILURE');
  });

  it('rejects a key of the wrong length', () => {
    assert.equal(unseal(env, { key: KEY16 }).code, 'BAD_KEY_LENGTH');
  });
});

describe('v2 envelope: associated data', () => {
  it('binds AAD into the tag', () => {
    const aad = enc('from=alice;to=bob');
    const env = sealOk(enc('payload'), { key: KEY32, aad });
    assert.equal(unwrap(unseal(env, { key: KEY32 })).text, 'payload');
    // Matching AAD is accepted when the caller insists on it.
    assert.equal(unwrap(unseal(env, { key: KEY32, expectAad: aad })).text, 'payload');
    // A mismatched AAD is rejected.
    const r = unseal(env, { key: KEY32, expectAad: enc('from=mallory;to=bob') });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'INTEGRITY_FAILURE');
  });

  it('rejects stripping the AAD from the header', () => {
    const aad = enc('critical-metadata');
    const env = sealOk(enc('payload'), { key: KEY32, aad });
    const parts = env.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.aad = '';
    const forged = [parts[0], Buffer.from(JSON.stringify(header)).toString('base64url'), parts[2], parts[3]].join('.');
    assert.equal(unseal(forged, { key: KEY32 }).code, 'INTEGRITY_FAILURE');
  });
});

describe('v2 envelope: passphrase mode', () => {
  it('round-trips with PBKDF2 and records the iteration count', () => {
    const env = sealOk(enc('passphrase message'), {
      passphrase: 'correct horse battery staple',
      iterations: 100_000,
    });
    const opened = unwrap(unseal(env, { passphrase: 'correct horse battery staple' }));
    assert.equal(opened.text, 'passphrase message');
    assert.equal(opened.info.kdf, 'PBKDF2-SHA256-HKDF-SHA256');
    assert.equal(opened.info.iterations, 100_000);
  });

  it('rejects a wrong passphrase', () => {
    const env = sealOk(enc('x'), { passphrase: 'correct horse battery staple', iterations: 100_000 });
    assert.equal(unseal(env, { passphrase: 'correct horse battery stapl3' }).code, 'INTEGRITY_FAILURE');
  });

  it('refuses a short passphrase', () => {
    const r = seal(enc('x'), { passphrase: 'short' });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'WEAK_PASSWORD');
  });

  it('refuses iterations below the floor', () => {
    const r = seal(enc('x'), { passphrase: 'correct horse battery staple', iterations: 1000 });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'MALFORMED_PARAMETER');
  });

  it('will not mix a key with a passphrase-sealed message', () => {
    const env = sealOk(enc('x'), { passphrase: 'correct horse battery staple', iterations: 100_000 });
    const r = unseal(env, { key: KEY32 });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'UNSUPPORTED_KDF');
  });

  it('will not mix a passphrase with a key-sealed message', () => {
    const env = sealOk(enc('x'), { key: KEY32 });
    const r = unseal(env, { passphrase: 'correct horse battery staple' });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'UNSUPPORTED_KDF');
  });
});

describe('v2 envelope: timestamps and freshness', () => {
  it('can bind a creation time into the header', () => {
    const env = sealOk(enc('now'), { key: KEY32, includeTimestamp: true });
    const opened = unwrap(unseal(env, { key: KEY32 }));
    const now = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(now - opened.info.createdAt) <= 5, 'timestamp should be ~now');
  });

  it('rejects a message older than maxAge', () => {
    const env = sealOk(enc('old'), { key: KEY32, includeTimestamp: true });
    const future = () => Date.now() + 10 * 60 * 1000;
    const r = unseal(env, { key: KEY32, maxAgeSeconds: 60, now: future });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'RECIPIENT_EXPIRED');
  });

  it('accepts a fresh message within maxAge', () => {
    const env = sealOk(enc('fresh'), { key: KEY32, includeTimestamp: true });
    assert.equal(unwrap(unseal(env, { key: KEY32, maxAgeSeconds: 60 })).text, 'fresh');
  });

  it('refuses to check freshness when the message has no timestamp', () => {
    const env = sealOk(enc('x'), { key: KEY32 });
    const r = unseal(env, { key: KEY32, maxAgeSeconds: 60 });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'MALFORMED_PARAMETER');
  });

  it('detects a forged timestamp', () => {
    const env = sealOk(enc('x'), { key: KEY32, includeTimestamp: true });
    const parts = env.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.ts = 1; // pretend it is ancient
    const forged = [parts[0], Buffer.from(JSON.stringify(header)).toString('base64url'), parts[2], parts[3]].join('.');
    assert.equal(unseal(forged, { key: KEY32 }).code, 'INTEGRITY_FAILURE');
  });
});

describe('v2 envelope: structural validation', () => {
  const good = sealOk(enc('x'), { key: KEY32 });

  it('rejects a non-envelope string', () => {
    assert.equal(unseal('not an envelope', { key: KEY32 }).code, 'INVALID_ENVELOPE');
  });

  it('rejects the wrong magic', () => {
    const parts = good.split('.');
    parts[0] = 'CMSG9';
    assert.equal(unseal(parts.join('.'), { key: KEY32 }).code, 'INVALID_ENVELOPE');
  });

  it('rejects an unsupported version', () => {
    const parts = good.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.v = 99;
    parts[1] = Buffer.from(JSON.stringify(header)).toString('base64url');
    assert.equal(unseal(parts.join('.'), { key: KEY32 }).code, 'UNSUPPORTED_VERSION');
  });

  it('rejects an unsupported algorithm', () => {
    const parts = good.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.alg = 'AES-CBC';
    parts[1] = Buffer.from(JSON.stringify(header)).toString('base64url');
    assert.equal(unseal(parts.join('.'), { key: KEY32 }).code, 'UNSUPPORTED_ALGORITHM');
  });

  it('rejects a hostile iteration count before doing any work', () => {
    const parts = good.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.kdf = 'PBKDF2-SHA256-HKDF-SHA256';
    header.p2c = 1e12; // would hang for years
    parts[1] = Buffer.from(JSON.stringify(header)).toString('base64url');
    const r = unseal(parts.join('.'), { passphrase: 'correct horse battery staple' });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'MALFORMED_PARAMETER');
  });

  it('rejects a non-canonical IV length', () => {
    const parts = good.split('.');
    const header = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    header.iv = Buffer.alloc(8).toString('base64url');
    parts[1] = Buffer.from(JSON.stringify(header)).toString('base64url');
    assert.equal(unseal(parts.join('.'), { key: KEY32 }).code, 'MALFORMED_PARAMETER');
  });

  it('reports parameters without a key', () => {
    const info = unwrap(inspect(good));
    assert.equal(info.version, 2);
    assert.equal(info.algorithm, 'AES-CBC-HMAC-SHA256');
    assert.equal(info.authenticated, false);
    assert.ok(info.ciphertextBytes % 16 === 0);
  });

  it('requires exactly one of key or passphrase', () => {
    assert.equal(seal(enc('x'), {}).code, 'BAD_PASSWORD');
    assert.equal(seal(enc('x'), { key: KEY32, passphrase: 'correct horse battery staple' }).code, 'BAD_PASSWORD');
  });

  it('rejects an envelope beyond the size limit', () => {
    assert.equal(unseal(`CMSG1.${'A'.repeat(200 * 1024 * 1024)}.AA.AA`, { key: KEY32 }).code, 'MALFORMED_PARAMETER');
  });
});

describe('v2 envelope: key separation', () => {
  it('derives distinct encryption and MAC keys', () => {
    const salt = randomBytes(16);
    const { encKey, macKey } = deriveMessageKeys(KEY32, salt, 'AES-256-CBC');
    assert.notEqual(Buffer.from(encKey).toString('hex'), Buffer.from(macKey).toString('hex'));
    assert.equal(encKey.length, 32);
    assert.equal(macKey.length, 32);
  });

  it('derives different keys for different salts', () => {
    const a = deriveMessageKeys(KEY32, randomBytes(16), 'AES-256-CBC');
    const b = deriveMessageKeys(KEY32, randomBytes(16), 'AES-256-CBC');
    assert.notEqual(Buffer.from(a.encKey).toString('hex'), Buffer.from(b.encKey).toString('hex'));
  });

  it('derives different keys for different ciphers', () => {
    const salt = randomBytes(16);
    const a = deriveMessageKeys(KEY32, salt, 'AES-256-CBC');
    const b = deriveMessageKeys(KEY32, salt, 'AES-128-CBC');
    assert.notEqual(Buffer.from(a.macKey).toString('hex'), Buffer.from(b.macKey).toString('hex'));
  });
});

describe('key fingerprints', () => {
  it('is stable for the same key and differs for different keys', () => {
    assert.equal(keyFingerprint(KEY32), keyFingerprint(new Uint8Array(KEY32)));
    assert.notEqual(keyFingerprint(KEY32), keyFingerprint(KEY16));
  });

  it('is a one-way, short display value', () => {
    const fp = keyFingerprint(KEY32);
    assert.match(fp, /^([0-9a-f]{2}:){7}[0-9a-f]{2}$/);
    assert.ok(!fp.includes(Buffer.from(KEY32).toString('hex')), 'must not leak the key');
  });
});
