/**
 * Enforce every vector captured from the live site (docs/vectors.json).
 *
 * Kept as a separate file so the recorded evidence is the source of truth: if a
 * vector is added to the JSON after a new interop check, the suite picks it up
 * without a code change.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { legacyDecrypt, legacyEncrypt } from '../dist/index.js';

const VECTORS_PATH = fileURLToPath(new URL('../docs/vectors.json', import.meta.url));
const { vectors } = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

describe('captured site vectors', () => {
  it('has vectors to test', () => {
    assert.ok(Array.isArray(vectors) && vectors.length > 0);
  });

  for (const { text, password, bits, base64 } of vectors) {
    it(`AES-${bits}: ${JSON.stringify(text).slice(0, 30)}`, () => {
      assert.equal(legacyEncrypt(text, password, bits), base64, 'encryption must match the site');
      // The site trims the decrypted result (PHP trim), so compare on the trimmed form.
      assert.equal(legacyDecrypt(base64, password, bits), text.replace(/^[\s\0\v]+|[\s\0\v]+$/g, ''));
    });
  }
});
