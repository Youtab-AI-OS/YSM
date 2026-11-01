/**
 * End-to-end tests through the real CLI, the way a user drives it.
 *
 * Each test spawns `node dist/cli.js` in a temp directory, so file permissions,
 * stdin/stdout plumbing, exit codes and stderr messages are all exercised
 * rather than mocked.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

/** Run the CLI, returning stdout/stderr/status. */
function run(args, { stdin, cwd } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    input: stdin,
    encoding: 'utf8',
    cwd: cwd ?? process.cwd(),
  });
  return { out: r.stdout ?? '', err: r.stderr ?? '', code: r.status ?? -1 };
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'cmsg-test-'));
}

describe('CLI: help and errors', () => {
  it('prints usage', () => {
    const r = run(['help']);
    assert.equal(r.code, 0);
    assert.match(r.out, /USAGE/);
    assert.match(r.out, /legacy-encrypt/);
  });

  it('exits non-zero on an unknown command', () => {
    const r = run(['frobnicate']);
    assert.equal(r.code, 2);
    assert.match(r.err, /unknown command/);
  });

  it('exits non-zero on an unknown option', () => {
    const r = run(['encrypt', '--nope', 'x']);
    assert.equal(r.code, 2);
    assert.match(r.err, /unknown option/);
  });

  it('explains missing key material', () => {
    const r = run(['encrypt'], { stdin: 'hi' });
    assert.equal(r.code, 1);
    assert.match(r.err, /no key material/);
    assert.match(r.err, /\[BAD_PASSWORD\]/);
  });
});

describe('CLI: keygen', () => {
  it('writes a 32-byte key and prints a fingerprint', () => {
    const dir = tempDir();
    const keyPath = join(dir, 'alice.key');
    const r = run(['keygen', '--out', keyPath]);
    assert.equal(r.code, 0, r.err);
    assert.equal(statSync(keyPath).size, 32);
    assert.match(r.err, /fingerprint : ([0-9a-f]{2}:){7}[0-9a-f]{2}/);
  });

  it('refuses to overwrite an existing key', () => {
    const dir = tempDir();
    const keyPath = join(dir, 'k.key');
    assert.equal(run(['keygen', '--out', keyPath]).code, 0);
    const second = run(['keygen', '--out', keyPath]);
    assert.equal(second.code, 1);
    assert.match(second.err, /refusing to overwrite/);
  });

  it('supports hex output and 128-bit keys', () => {
    const dir = tempDir();
    const keyPath = join(dir, 'k.key');
    assert.equal(run(['keygen', '--out', keyPath, '--hex', '--key-bits', '128']).code, 0);
    const text = readFileSync(keyPath, 'utf8').trim();
    assert.match(text, /^[0-9a-f]{32}$/);
  });
});

describe('CLI: v2 encrypt/decrypt round trip', () => {
  it('round-trips text through stdin and stdout', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    run(['keygen', '--out', key]);

    const enc = run(['encrypt', '--key-file', key], { stdin: 'meet at 9 by the pier' });
    assert.equal(enc.code, 0, enc.err);
    assert.match(enc.out.trim(), /^CMSG1\./);

    const dec = run(['decrypt', '--key-file', key], { stdin: enc.out });
    assert.equal(dec.code, 0, dec.err);
    assert.equal(dec.out.trim(), 'meet at 9 by the pier');
  });

  it('round-trips through files', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    const msg = join(dir, 'msg.cmsg');
    const plain = join(dir, 'plain.txt');
    run(['keygen', '--out', key]);
    writeFileSync(join(dir, 'in.txt'), 'file based secret\n');

    assert.equal(run(['encrypt', '--key-file', key, '--in', join(dir, 'in.txt'), '--out', msg]).code, 0);
    assert.ok(existsSync(msg));
    assert.equal(run(['decrypt', '--key-file', key, '--in', msg, '--out', plain]).code, 0);
    assert.equal(readFileSync(plain, 'utf8').trim(), 'file based secret');
  });

  it('preserves Unicode end to end', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    run(['keygen', '--out', key]);
    const text = 'پیام محرمانه 🔐 — 日本語';
    const enc = run(['encrypt', '--key-file', key], { stdin: text });
    const dec = run(['decrypt', '--key-file', key], { stdin: enc.out });
    assert.equal(dec.out.trim(), text);
  });

  it('round-trips a binary file with --raw', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    const bin = join(dir, 'blob.bin');
    run(['keygen', '--out', key]);
    const payload = Buffer.from([0, 1, 2, 255, 254, 0, 128, 200, 7, 7, 7]);
    writeFileSync(bin, payload);

    const enc = run(['encrypt', '--key-file', key, '--in', bin]);
    assert.equal(enc.code, 0, enc.err);
    const outBin = join(dir, 'out.bin');
    const dec = run(['decrypt', '--key-file', key, '--in', join(dir, 'm.cmsg')], { stdin: enc.out });
    void outBin;
    // write ciphertext to a file, then decrypt raw
    writeFileSync(join(dir, 'm.cmsg'), enc.out);
    const dec2 = run(['decrypt', '--key-file', key, '--in', join(dir, 'm.cmsg'), '--raw', '--out', outBin]);
    assert.equal(dec2.code, 0, dec2.err);
    assert.deepEqual([...readFileSync(outBin)], [...payload]);
    void dec;
  });

  it('fails loudly with the wrong key', () => {
    const dir = tempDir();
    const a = join(dir, 'a.key');
    const b = join(dir, 'b.key');
    run(['keygen', '--out', a]);
    run(['keygen', '--out', b]);
    const enc = run(['encrypt', '--key-file', a], { stdin: 'secret' });
    const dec = run(['decrypt', '--key-file', b], { stdin: enc.out });
    assert.equal(dec.code, 1);
    assert.match(dec.err, /INTEGRITY_FAILURE/);
    assert.equal(dec.out.trim(), '', 'no plaintext may be emitted on failure');
  });

  it('fails on a tampered message', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    run(['keygen', '--out', key]);
    const enc = run(['encrypt', '--key-file', key], { stdin: 'pay 10' }).out.trim();
    const parts = enc.split('.');
    const ct = Buffer.from(parts[2], 'base64url');
    ct[0] ^= 0xff;
    const forged = [parts[0], parts[1], ct.toString('base64url'), parts[3]].join('.');

    const dec = run(['decrypt', '--key-file', key], { stdin: forged });
    assert.equal(dec.code, 1);
    assert.match(dec.err, /INTEGRITY_FAILURE/);
  });
});

describe('CLI: passphrase mode', () => {
  it('round-trips using a passphrase file', () => {
    const dir = tempDir();
    const pw = join(dir, 'pw.txt');
    writeFileSync(pw, 'correct horse battery staple\n');
    const enc = run(['encrypt', '--passphrase-file', pw, '--iterations', '100000'], { stdin: 'pw secret' });
    assert.equal(enc.code, 0, enc.err);
    const dec = run(['decrypt', '--passphrase-file', pw], { stdin: enc.out });
    assert.equal(dec.code, 0, dec.err);
    assert.equal(dec.out.trim(), 'pw secret');
  });

  it('rejects a short passphrase', () => {
    const dir = tempDir();
    const pw = join(dir, 'pw.txt');
    writeFileSync(pw, 'short\n');
    const r = run(['encrypt', '--passphrase-file', pw], { stdin: 'x' });
    assert.equal(r.code, 1);
    assert.match(r.err, /WEAK_PASSWORD/);
  });
});

describe('CLI: inspect', () => {
  it('describes an envelope without a key', () => {
    const dir = tempDir();
    const key = join(dir, 'k.key');
    run(['keygen', '--out', key]);
    const enc = run(['encrypt', '--key-file', key], { stdin: 'x' }).out;

    const insp = run(['inspect'], { stdin: enc });
    assert.equal(insp.code, 0, insp.err);
    assert.match(insp.out, /cipher\s+: AES-256-CBC/);
    assert.match(insp.out, /HMAC-SHA256/);
    assert.match(insp.out, /NOT authenticated/);
  });
});

describe('CLI: legacy aesencryption.net mode', () => {
  it('encrypts to the exact site ciphertext', () => {
    const r = run(['legacy-encrypt', '--key', 'encryptor key', '--bits', '256'], {
      stdin: 'My text to encrypt.',
    });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out.trim(), 'a8FC/4chLgfmBP1MAM0C/D8KqddSjxepiw6PLI6wlVk=');
  });

  it('decrypts site ciphertext', () => {
    for (const [ct, key, bits, want] of [
      ['a8FC/4chLgfmBP1MAM0C/D8KqddSjxepiw6PLI6wlVk=', 'encryptor key', '256', 'My text to encrypt.'],
      ['OWcMplyUQMKwY7Qhmr+Vjr++e5MMVnIKL5/70+Oj3K8=', 'encryptor key', '128', 'My text to encrypt.'],
      ['cxmHHletkHgGgN2/tGeYaaI5+LOA1Zwkk6UZMZtSoEg=', 'encryptor key', '192', 'My text to encrypt.'],
    ]) {
      const r = run(['legacy-decrypt', '--key', key, '--bits', bits], { stdin: ct });
      assert.equal(r.code, 0, r.err);
      assert.equal(r.out.trim(), want);
    }
  });

  it('reports a wrong legacy key instead of emitting garbage', () => {
    const ct = run(['legacy-encrypt', '--key', 'right key'], { stdin: 'a fairly long secret message' }).out.trim();
    const r = run(['legacy-decrypt', '--key', 'wrong key'], { stdin: ct });
    assert.equal(r.code, 1);
    assert.match(r.err, /INTEGRITY_FAILURE|padding/);
  });
});

describe('CLI: keyring', () => {
  it('generates and uses keys by id', () => {
    const dir = tempDir();
    const ring = join(dir, 'keys');
    assert.equal(run(['keygen', '--keyring', ring, '--kid', 'alice', '--out', 'unused']).code, 0);
    assert.ok(existsSync(join(ring, 'alice.key')));

    const enc = run(['encrypt', '--keyring', ring, '--kid', 'alice'], { stdin: 'ring secret' });
    assert.equal(enc.code, 0, enc.err);
    const dec = run(['decrypt', '--keyring', ring, '--kid', 'alice'], { stdin: enc.out });
    assert.equal(dec.out.trim(), 'ring secret');

    const list = run(['keyring-list', '--keyring', ring]);
    assert.match(list.out, /alice/);
  });

  it('reports an unknown key id', () => {
    const dir = tempDir();
    const ring = join(dir, 'keys');
    run(['keygen', '--keyring', ring, '--kid', 'alice', '--out', 'x']);
    const r = run(['encrypt', '--keyring', ring, '--kid', 'bob'], { stdin: 'x' });
    assert.equal(r.code, 1);
    assert.match(r.err, /UNKNOWN_RECIPIENT/);
  });

  it('rejects a path-traversal key id', () => {
    const dir = tempDir();
    const r = run(['keygen', '--keyring', dir, '--kid', '../escape', '--out', 'x']);
    assert.equal(r.code, 1);
    assert.match(r.err, /invalid/);
  });
});
