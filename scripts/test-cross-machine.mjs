/**
 * Cross-machine tests for the transfer string.
 *
 * The claim being tested: a message sealed in one place opens in another place
 * that has never seen it, given only the transfer string and the passphrase.
 *
 * That is exactly what the earlier reference-only design could not do, so these
 * tests use *two independent services with separate databases* to model two
 * machines. A shared store would hide the defect.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const B = '../build/ysm';
const { AppService } = await import(`${B}/app/service.js`);
const { totp, base32Decode } = await import(`${B}/crypto/auth.js`);
const { packTransfer, unpackTransfer, packFile, unpackFile } = await import(`${B}/crypto/seal.js`);

const PW = 'correct horse battery staple';

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`); }
}

const dirs = [];
function machine(name) {
  const dir = mkdtempSync(join(tmpdir(), `ysm-x-${name}-`));
  dirs.push(dir);
  const svc = new AppService({ dataDir: join(dir, 'data') });
  const created = svc.createAccount(name, PW);
  if (!created.ok) throw new Error(`could not create ${name}: ${created.code}`);
  const secret = base32Decode(created.value.totpSecretBase32);
  svc.confirmOnboarding(totp(secret, Math.floor(Date.now() / 1000)));
  return { svc, dir };
}

try {
  console.log('=== two separate machines, separate databases ===');
  const alice = machine('alice');
  const bob = machine('bob');

  check('the two machines have different data directories', alice.dir !== bob.dir);
  check('bob has no sealed items yet', bob.svc.sealedItems().value.length === 0);

  console.log('\n=== seal on alice, open on bob ===');
  const text = 'سلام، این پیام از ماشین دیگر است. ۱۲۳۴۵ تومان.';
  const sealed = alice.svc.sealPayload({ text });
  check('alice sealed the text', sealed.ok === true, JSON.stringify(sealed).slice(0, 120));

  const transfer = sealed.value.transfer;
  const reference = sealed.value.reference;
  const passphrase = sealed.value.passphrase;

  check('a transfer string is returned', typeof transfer === 'string');
  check('it is distinct from the reference', transfer !== reference);
  check('it starts with YSMT1.', transfer.startsWith('YSMT1.'), transfer.slice(0, 12));
  check('it is much longer than the reference', transfer.length > reference.length * 2, `${transfer.length} vs ${reference.length}`);

  // Bob has never seen this payload.
  check('bob still has nothing stored', bob.svc.sealedItems().value.length === 0);

  const opened = bob.svc.openSealed({ reference, passphrase, transfer });
  check('bob opens it with only the transfer string', opened.ok === true, JSON.stringify(opened).slice(0, 120));
  if (opened.ok) {
    check('the text is byte-identical', opened.value.text === text, JSON.stringify(opened.value.text || '').slice(0, 60));
    check('the reference matches what alice computed', opened.value.reference === reference);
  }
  check('bob now keeps a copy for later', bob.svc.sealedItems().value.length === 1);

  // Bob can reopen from his own store, without re-pasting the transfer string.
  const reopened = bob.svc.openSealed({ reference, passphrase });
  check('bob reopens from his own store with just the reference', reopened.ok === true);

  console.log('\n=== a bare reference without a payload is refused clearly ===');
  const carol = machine('carol');
  const bare = carol.svc.openSealed({ reference, passphrase });
  check('carol cannot open with only the reference', bare.ok === false);
  check('she is told to paste the transfer text', /YSMT1|transfer/i.test(bare.message || ''), bare.message);

  console.log('\n=== a file crosses machines intact ===');
  const bytes = Buffer.from([0x50, 0x4b, 0x03, 0x04, ...Array.from({ length: 5000 }, (_, i) => (i * 7) & 0xff)]);
  const sealedFile = alice.svc.sealPayload({
    dataBase64: bytes.toString('base64'),
    fileName: 'گزارش-مالی.xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  check('alice sealed a file', sealedFile.ok === true, JSON.stringify(sealedFile).slice(0, 120));

  const fileOpened = bob.svc.openSealed({
    reference: sealedFile.value.reference,
    passphrase: sealedFile.value.passphrase,
    transfer: sealedFile.value.transfer,
  });
  check('bob opened the file', fileOpened.ok === true, JSON.stringify(fileOpened).slice(0, 120));
  if (fileOpened.ok) {
    check('the Persian filename survived', fileOpened.value.fileName === 'گزارش-مالی.xlsx', fileOpened.value.fileName);
    check('the MIME type survived', /spreadsheetml/.test(fileOpened.value.mimeType || ''));
    const returned = Buffer.from(fileOpened.value.dataBase64 || '', 'base64');
    check('the bytes are identical', returned.equals(bytes), `${returned.length} vs ${bytes.length}`);
  }

  console.log('\n=== wrong passphrase across machines ===');
  const wrong = bob.svc.openSealed({ reference, passphrase: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', transfer });
  check('a wrong passphrase is refused', wrong.ok === false);
  check('it reports a passphrase problem', wrong.code === 'BAD_PASSPHRASE', wrong.code);

  console.log('\n=== tampering with the transfer string ===');
  const flip = (text, at) => {
    const ch = text[at];
    const next = ch === 'A' ? 'B' : 'A';
    return text.slice(0, at) + next + text.slice(at + 1);
  };
  const mid = transfer.length - 2; // in the tag region
  const tamperedTag = bob.svc.openSealed({ reference, passphrase, transfer: flip(transfer, mid) });
  check('a changed trailer is detected', tamperedTag.ok === false, tamperedTag.code);

  const bodyPos = transfer.indexOf('YSMT1.') + 20;
  const tamperedBody = bob.svc.openSealed({ reference, passphrase, transfer: flip(transfer, bodyPos) });
  check('changed ciphertext is detected', tamperedBody.ok === false, tamperedBody.code);

  const truncated = bob.svc.openSealed({ reference, passphrase, transfer: transfer.slice(0, 60) });
  check('a truncated transfer string is refused', truncated.ok === false);
  check('it says the text is incomplete', /incomplete|cut short|damaged/i.test(truncated.message || ''), truncated.message);

  console.log('\n=== pack/unpack is symmetric ===');
  const sealedSmall = alice.svc.sealPayload({ text: 'x' });
  const packed = packTransfer({
    reference: sealedSmall.value.reference,
    version: 1,
    argon: { t: 3, m: 65536, p: 1 },
    salt: new Uint8Array(32),
    nonce: new Uint8Array(12),
    ciphertext: new TextEncoder().encode('hello'),
  });
  const unpacked = unpackTransfer(packed);
  check('a hand-built blob round-trips', unpacked.ok === true, JSON.stringify(unpacked).slice(0, 80));
  if (unpacked.ok) {
    check('the ciphertext survives', new TextDecoder().decode(unpacked.blob.ciphertext) === 'hello');
    check('the argon parameters survive', unpacked.blob.argon.t === 3 && unpacked.blob.argon.m === 65536);
  }

  console.log('\n=== the .ysm file is the same payload ===');
  const asFile = packFile(unpacked.ok ? unpacked.blob : null);
  const fromFile = unpackFile(asFile);
  check('a .ysm file unpacks', fromFile.ok === true, JSON.stringify(fromFile).slice(0, 80));
  if (fromFile.ok && unpacked.ok) {
    check('the file and the string describe the same payload', fromFile.blob.reference === unpacked.blob.reference);
  }
  const notAFile = unpackFile(new Uint8Array([0xff, 0xfe, 0x00]));
  check('a non-UTF-8 file is refused', notAFile.ok === false);

  console.log('\n=== Unicode and control characters ===');
  const tricky = 'line1\nline2\ttab\u0000null 中文 العربية हिन्दी 🎉';
  const sealedTricky = alice.svc.sealPayload({ text: tricky });
  const openedTricky = bob.svc.openSealed({
    reference: sealedTricky.value.reference,
    passphrase: sealedTricky.value.passphrase,
    transfer: sealedTricky.value.transfer,
  });
  check('mixed scripts and control characters round-trip', openedTricky.ok && openedTricky.value.text === tricky,
    JSON.stringify(openedTricky.value ? openedTricky.value.text : '').slice(0, 60));
} catch (error) {
  console.error('\nUNEXPECTED:', error.name);
  fail++;
  failures.push('suite crashed');
} finally {
  for (const dir of dirs) {
    try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(fail === 0 ? 0 : 1);
