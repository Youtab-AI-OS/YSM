/**
 * AES block cipher: known-answer tests against FIPS-197 and OpenSSL.
 *
 * Why both: FIPS-197 pins the *cryptographic* answer, OpenSSL gives us an
 * independent implementation to diff against over many random inputs. A wrong
 * ShiftRows index still round-trips against its own inverse, so round-trip
 * tests alone would never have caught it.
 */

import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  BLOCK_SIZE,
  cbcDecrypt,
  cbcEncrypt,
  decryptBlock,
  encryptBlock,
  expandKey,
  pkcs7Pad,
  pkcs7Unpad,
  PadError,
} from '../dist/index.js';

const h = (b) => Buffer.from(b).toString('hex');

/** FIPS-197 Appendix C: the same plaintext under all three key sizes. */
const FIPS_PLAINTEXT = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const FIPS_CASES = [
  { bits: 128, key: '000102030405060708090a0b0c0d0e0f', expected: '69c4e0d86a7b0430d8cdb78070b4c55a' },
  {
    bits: 192,
    key: '000102030405060708090a0b0c0d0e0f1011121314151617',
    expected: 'dda97ca4864cdfe06eaf70a0ec0d7191',
  },
  {
    bits: 256,
    key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    expected: '8ea2b7ca516745bfeafc49904b496089',
  },
];

describe('AES block cipher', () => {
  for (const { bits, key, expected } of FIPS_CASES) {
    it(`matches FIPS-197 C.${bits === 128 ? 1 : bits === 192 ? 2 : 3} for AES-${bits}`, () => {
      const ks = expandKey(Buffer.from(key, 'hex'));
      assert.equal(h(encryptBlock(FIPS_PLAINTEXT, ks)), expected);
    });

    it(`round-trips AES-${bits}`, () => {
      const ks = expandKey(Buffer.from(key, 'hex'));
      const ct = encryptBlock(FIPS_PLAINTEXT, ks);
      assert.equal(h(decryptBlock(ct, ks)), h(FIPS_PLAINTEXT));
    });

    it(`agrees with OpenSSL for AES-${bits} (200 random blocks)`, () => {
      for (let i = 0; i < 200; i++) {
        const k = randomBytes(bits / 8);
        const pt = randomBytes(BLOCK_SIZE);
        const cipher = createCipheriv(`aes-${bits}-ecb`, k, null);
        cipher.setAutoPadding(false);
        const ref = Buffer.concat([cipher.update(pt), cipher.final()]);
        assert.equal(h(encryptBlock(pt, expandKey(k))), h(ref), `block ${i}`);
      }
    });
  }

  it('rejects a wrong-size block', () => {
    const ks = expandKey(randomBytes(16));
    assert.throws(() => encryptBlock(new Uint8Array(15), ks), RangeError);
    assert.throws(() => decryptBlock(new Uint8Array(17), ks), RangeError);
  });

  it('rejects a wrong-size key', () => {
    assert.throws(() => expandKey(new Uint8Array(20)), RangeError);
  });

  it('does not alias caller buffers (Node Buffer slice returns a view)', () => {
    // Regression: a Buffer passed in used to be mutated by the state copy,
    // producing a self-consistent but non-standard cipher.
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const keyBefore = h(key);
    const pt = Buffer.from(FIPS_PLAINTEXT);
    const ptBefore = h(pt);

    const ks = expandKey(key);
    encryptBlock(pt, ks);

    assert.equal(h(key), keyBefore, 'key buffer must be untouched');
    assert.equal(h(pt), ptBefore, 'plaintext buffer must be untouched');
  });

  it('produces identical output for Buffer and Uint8Array inputs', () => {
    const raw = randomBytes(32);
    const asBuffer = raw;
    const asArray = new Uint8Array(raw);
    const pt = randomBytes(BLOCK_SIZE);

    const a = h(encryptBlock(pt, expandKey(asBuffer)));
    const b = h(encryptBlock(new Uint8Array(pt), expandKey(asArray)));
    assert.equal(a, b);
  });
});

describe('PKCS#7 padding', () => {
  it('always appends at least one byte', () => {
    assert.equal(pkcs7Pad(new Uint8Array(0)).length, 16);
    assert.equal(pkcs7Pad(new Uint8Array(15)).length, 16);
    assert.equal(pkcs7Pad(new Uint8Array(16)).length, 32);
    assert.equal(pkcs7Pad(new Uint8Array(17)).length, 32);
  });

  it('round-trips every length 0..64', () => {
    for (let n = 0; n <= 64; n++) {
      const data = randomBytes(n);
      assert.equal(h(pkcs7Unpad(pkcs7Pad(data))), h(data), `length ${n}`);
    }
  });

  it('rejects malformed padding instead of silently truncating', () => {
    const bad = new Uint8Array(16).fill(0);
    bad[15] = 0x11; // pad byte 17 is impossible
    assert.throws(() => pkcs7Unpad(bad), PadError);

    const inconsistent = new Uint8Array(16).fill(3);
    inconsistent[13] = 9; // claims 3 bytes of pad, value disagrees
    assert.throws(() => pkcs7Unpad(inconsistent), PadError);
  });

  it('rejects a non-block-multiple length', () => {
    assert.throws(() => pkcs7Unpad(new Uint8Array(15)), PadError);
    assert.throws(() => pkcs7Unpad(new Uint8Array(0)), PadError);
  });
});

describe('CBC mode', () => {
  it('agrees with OpenSSL for all key sizes (200 random messages)', () => {
    for (let i = 0; i < 200; i++) {
      const bits = [128, 192, 256][i % 3];
      const key = randomBytes(bits / 8);
      const iv = randomBytes(16);
      const plain = randomBytes(1 + Math.floor(Math.random() * 100));

      const cipher = createCipheriv(`aes-${bits}-cbc`, key, iv);
      const ref = Buffer.concat([cipher.update(plain), cipher.final()]);

      const mine = cbcEncrypt(plain, key, iv);
      assert.equal(h(mine), h(ref), `case ${i} (AES-${bits})`);
      assert.equal(h(cbcDecrypt(mine, key, iv)), h(plain), `roundtrip ${i}`);
    }
  });

  it('rejects an IV that is not 16 bytes', () => {
    assert.throws(() => cbcEncrypt(new Uint8Array(16), randomBytes(16), randomBytes(15)), RangeError);
  });

  it('fails to decrypt with the wrong key (padding check)', () => {
    const key = randomBytes(32);
    const ct = cbcEncrypt(Buffer.from('a reasonably long secret message'), key, randomBytes(16));
    // A wrong key fails the padding check with probability ~255/256; over 32
    // attempts the chance of every single one passing is negligible.
    let threw = 0;
    for (let i = 0; i < 32; i++) {
      try {
        cbcDecrypt(ct, randomBytes(32), randomBytes(16));
      } catch (err) {
        if (err instanceof PadError) threw++;
      }
    }
    assert.ok(threw >= 31, `expected the padding check to reject wrong keys, got ${threw}/32`);
  });
});
