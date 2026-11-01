/**
 * aesencryption.net compatibility.
 *
 * The expected values below were produced by the live site's own
 * js/aes-browser.js (captured via the browser console) and must not be
 * "fixed" to match this implementation — they are the contract.
 */

import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  LEGACY_IV,
  LEGACY_IV_STRING,
  legacyDecrypt,
  legacyDecryptDiagnostic,
  legacyEncrypt,
  legacyKey,
} from '../dist/index.js';

const SITE_VECTORS = [
  { text: 'My text to encrypt.', key: 'encryptor key', bits: 256, expected: 'a8FC/4chLgfmBP1MAM0C/D8KqddSjxepiw6PLI6wlVk=' },
  { text: 'My text to encrypt.', key: 'encryptor key', bits: 128, expected: 'OWcMplyUQMKwY7Qhmr+Vjr++e5MMVnIKL5/70+Oj3K8=' },
  { text: 'My text to encrypt.', key: 'encryptor key', bits: 192, expected: 'cxmHHletkHgGgN2/tGeYaaI5+LOA1Zwkk6UZMZtSoEg=' },
  { text: '', key: 'key', bits: 256, expected: '3YFrvGTNN4y8jt5Jx4TnJw==' },
  { text: 'short', key: 'k', bits: 256, expected: 'Wm8aRW1Yyt+lYGT+FBauJw==' },
  { text: 'aaaaaaaaaaaaaaaa', key: '0123456789abcdefXYZ', bits: 256, expected: 'xUv55U9aeET3PG8ThFl/CRVYOIoWD1UJ3oQMAgo/n4A=' },
  { text: 'a', key: 'طولیانیفففففففففففففففففففف', bits: 256, expected: 'rskM1pCfA4+VLcLYnQgkxQ==' },
];

describe('aesencryption.net compatibility', () => {
  it('uses the documented fixed IV', () => {
    assert.equal(LEGACY_IV_STRING, '12345678b0z2345n');
    assert.equal(LEGACY_IV.length, 16);
  });

  for (const { text, key, bits, expected } of SITE_VECTORS) {
    const label = `AES-${bits} ${JSON.stringify(text).slice(0, 22)} / ${JSON.stringify(key).slice(0, 18)}`;
    it(`reproduces the site ciphertext: ${label}`, () => {
      assert.equal(legacyEncrypt(text, key, bits), expected);
    });
  }

  it('decrypts every site ciphertext back to its plaintext', () => {
    for (const { text, key, bits, expected } of SITE_VECTORS) {
      assert.equal(legacyDecrypt(expected, key, bits), text.replace(/^\s+|\s+$/g, ''));
    }
  });

  it('derives keys by truncation and zero padding, not by hashing', () => {
    // Short key: zero padded.
    assert.equal(legacyKey('abc', 256).length, 32);
    assert.deepEqual([...legacyKey('abc', 256).slice(0, 4)], [0x61, 0x62, 0x63, 0x00]);
    // Long key: truncated, and the truncation is at the byte level.
    const long = '0123456789abcdefXYZ';
    assert.equal(Buffer.from(legacyKey(long, 128)).toString('latin1'), '0123456789abcdef');
    // 192-bit key takes 24 bytes.
    assert.equal(legacyKey(long, 192).length, 24);
  });

  it('matches OpenSSL AES-CBC with the fixed IV and padded key', () => {
    // Independent confirmation that the scheme is plain AES-CBC, not something
    // bespoke: rebuild it with OpenSSL directly.
    for (const bits of [128, 192, 256]) {
      const password = 'encryptor key';
      const keyLen = bits / 8;
      const key = Buffer.alloc(keyLen);
      Buffer.from(password, 'utf8').copy(key, 0, 0, keyLen);

      const plain = Buffer.from('My text to encrypt.', 'utf8');
      const pad = 16 - (plain.length % 16);
      const padded = Buffer.concat([plain, Buffer.alloc(pad, pad)]);

      const cipher = createCipheriv(`aes-${bits}-cbc`, key, LEGACY_IV);
      // Padding was applied above by hand, so OpenSSL must not add its own.
      cipher.setAutoPadding(false);
      const ref = Buffer.concat([cipher.update(padded), cipher.final()]).toString('base64');
      assert.equal(legacyEncrypt('My text to encrypt.', password, bits), ref, `AES-${bits}`);
    }
  });

  it('preserves UTF-8 through a round trip', () => {
    const samples = [
      'سلام دنیا',
      'secret 🔐 message',
      'Ünïcödé çhärs — em dash',
      '日本語のテキスト',
      'עברית',
      'a',
      'x'.repeat(1000),
    ];
    for (const s of samples) {
      assert.equal(legacyDecrypt(legacyEncrypt(s, 'رمز من', 256), 'رمز من', 256), s, JSON.stringify(s.slice(0, 20)));
    }
  });

  it('is deterministic — the same input yields the same ciphertext (fixed IV)', () => {
    // This documents the weakness rather than praising it: it is exactly why
    // the v2 envelope exists. If this ever changes, the format changed.
    const a = legacyEncrypt('same message', 'same key', 256);
    const b = legacyEncrypt('same message', 'same key', 256);
    assert.equal(a, b);
  });

  it('tolerates whitespace in base64 input', () => {
    const ct = legacyEncrypt('hello', 'key', 256);
    const spaced = `  ${ct.slice(0, 4)}\n${ct.slice(4)}  `;
    assert.equal(legacyDecrypt(spaced, 'key', 256), 'hello');
  });

  it('reports a wrong key as invalid padding', () => {
    const ct = legacyEncrypt('a secret that is long enough to be interesting', 'right key', 256);
    const diag = legacyDecryptDiagnostic(ct, 'wrong key', 256);
    assert.equal(diag.paddingValid, false, 'a wrong key should fail the padding check');
  });

  it('trims like PHP does after decryption', () => {
    // PHP's trim() strips leading/trailing whitespace from the *decrypted bytes*.
    const ct = legacyEncrypt('   padded text   ', 'key', 256);
    assert.equal(legacyDecrypt(ct, 'key', 256), 'padded text');
  });

  it('rejects an unsupported key size', () => {
    assert.throws(() => legacyEncrypt('x', 'key', 100), RangeError);
  });
});
