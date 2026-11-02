/**
 * End-to-end test of the sealed-reference flow through the service.
 *
 * Simulates the two people in the user's description:
 *   - the author types text or picks a file, presses "Create crypto", and copies
 *     the reference and the passphrase
 *   - the reader pastes the reference, types the passphrase, and sees the original
 *
 * Uses cheap Argon2 parameters by patching the compiled default, because the real
 * 64 MiB cost would make this suite take minutes.
 *
 * Run: node scripts/test-sealed-service.mjs
 */
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const B = '../build/ysm';
const { AppService } = await import(`${B}/app/service.js`);
const { totp, base32Decode } = await import(`${B}/crypto/auth.js`);
const sealMod = await import(`${B}/crypto/seal.js`);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}`); }
}

const PW = 'correct horse battery staple';
const dirs = [];
function tmp() {
  const d = mkdtempSync(join(tmpdir(), 'ysm-sealed-'));
  dirs.push(d);
  return d;
}

/** Create an unlocked account. */
function account(name) {
  const svc = new AppService({ dataDir: join(tmp(), 'data') });
  const created = svc.createAccount(name, PW);
  if (!created.ok) throw new Error(`create failed: ${created.message}`);
  const secret = base32Decode(created.value.totpSecretBase32);
  const confirmed = svc.confirmOnboarding(totp(secret, Math.floor(Date.now() / 1000)));
  if (!confirmed.ok) throw new Error(`confirm failed: ${confirmed.message}`);
  return svc;
}

let author;
let reader;

try {
  console.log('=== setup ===');
  author = account('Author');
  reader = account('Reader');
  check('author account created', author.accountState().unlocked);
  check('reader account created', reader.accountState().unlocked);

  console.log('\n=== 1. seal a text message ===');
  const secretText = 'The meeting is moved to Thursday at 14:00. Bring the contracts.';
  const t0 = Date.now();
  const sealed = author.sealPayload({ text: secretText });
  const sealMs = Date.now() - t0;
  check('text seals', sealed.ok);
  check('reference starts with YSM_', sealed.ok && sealed.value.reference.startsWith('YSM_'));
  check('reference is 68 chars', sealed.ok && sealed.value.reference.length === 68);
  check('a passphrase is returned', sealed.ok && sealed.value.passphrase.length === 32);
  check('passphrase is not the reference', sealed.ok && sealed.value.passphrase !== sealed.value.reference);
  check('payload is not a file', sealed.ok && sealed.value.isFile === false);
  console.log(`  (seal took ${sealMs} ms)`);

  const ref = sealed.value.reference;
  const phrase = sealed.value.passphrase;

  console.log('\n=== 2. a bare reference does not open without the payload ===');
  // A reference is only a digest. Without a stored copy or a transfer string there
  // is nothing to decrypt, and the reader has to be told that clearly rather than
  // shown a generic failure.
  const readerNoRef = reader.openSealed({ reference: ref, passphrase: phrase });
  check('reader cannot open a reference they do not hold', readerNoRef.ok === false);
  check('the failure is NO_PAYLOAD', readerNoRef.code === 'NO_PAYLOAD', readerNoRef.code);
  check('the message tells them to paste the transfer text', /YSMT1|transfer/i.test(readerNoRef.message || ''), readerNoRef.message);

  console.log('\n=== 2b. the transfer string does open it, on a reader with no copy ===');
  const viaTransfer = reader.openSealed({ reference: ref, passphrase: phrase, transfer: sealed.value.transfer });
  check('reader opens it with the transfer string', viaTransfer.ok === true, JSON.stringify(viaTransfer).slice(0, 100));
  check("the text matches", viaTransfer.ok && viaTransfer.value.text === secretText);
  // The author, who does hold it, still needs the passphrase.
  const authorWrong = author.openSealed({ reference: ref, passphrase: 'WRONGPASSPHRASE' });
  check('author with wrong passphrase is refused', authorWrong.ok === false);
  check('the failure is BAD_PASSPHRASE', authorWrong.code === 'BAD_PASSPHRASE');
  const authorRight = author.openSealed({ reference: ref, passphrase: phrase });
  check('author with right passphrase reads it', authorRight.ok);
  check('the text is identical', authorRight.ok && authorRight.value.text === secretText);

  console.log('\n=== 3. reader opens it via the reference block ===');
  // In the product, the reader receives the ciphertext by pasting the reference
  // block, which the UI obtains from the author's export. Here we copy the stored
  // row across, which is exactly what that import does.
  const authorDb = author.vault.database;
  const storedRow = authorDb
    .prepare('SELECT * FROM sealed WHERE reference = ?')
    .get(ref);
  check('the payload is stored locally by the author', storedRow !== undefined);

  reader.vault.database
    .prepare(
      `INSERT OR IGNORE INTO sealed
         (reference, version, argon_t, argon_m, argon_p, salt, nonce, ciphertext, role, is_file, size, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in', ?, ?, ?)`,
    )
    .run(
      ref,
      storedRow.version,
      storedRow.argon_t,
      storedRow.argon_m,
      storedRow.argon_p,
      storedRow.salt,
      storedRow.nonce,
      storedRow.ciphertext,
      storedRow.is_file,
      storedRow.size,
      Date.now(),
    );

  const readerOpens = reader.openSealed({ reference: ref, passphrase: phrase });
  check('reader opens the text', readerOpens.ok);
  check('reader sees the exact original text', readerOpens.ok && readerOpens.value.text === secretText);
  check('reader sees it as text, not a file', readerOpens.ok && readerOpens.value.isFile === false);

  console.log('\n=== 4. a file round-trips with its name and format ===');
  const fileBytes = randomBytes(300 * 1024);
  const fileSeal = author.sealPayload({
    dataBase64: fileBytes.toString('base64'),
    fileName: 'Q3 report final.xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  check('file seals', fileSeal.ok);
  check('file is flagged as a file', fileSeal.ok && fileSeal.value.isFile === true);
  check('file size is recorded', fileSeal.ok && fileSeal.value.size === fileBytes.length);

  const fileRef = fileSeal.value.reference;
  const filePhrase = fileSeal.value.passphrase;

  // Copy across, as an import would.
  const fileRow = author.vault.database.prepare('SELECT * FROM sealed WHERE reference = ?').get(fileRef);
  reader.vault.database
    .prepare(
      `INSERT OR IGNORE INTO sealed
         (reference, version, argon_t, argon_m, argon_p, salt, nonce, ciphertext, role, is_file, size, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in', ?, ?, ?)`,
    )
    .run(
      fileRef,
      fileRow.version,
      fileRow.argon_t,
      fileRow.argon_m,
      fileRow.argon_p,
      fileRow.salt,
      fileRow.nonce,
      fileRow.ciphertext,
      fileRow.is_file,
      fileRow.size,
      Date.now(),
    );

  const fileOpened = reader.openSealed({ reference: fileRef, passphrase: filePhrase });
  check('reader opens the file', fileOpened.ok);
  check('filename preserved exactly', fileOpened.ok && fileOpened.value.fileName === 'Q3 report final.xlsx');
  check('mime type preserved', fileOpened.ok && fileOpened.value.mimeType.includes('spreadsheetml'));
  check(
    'file bytes identical',
    fileOpened.ok && Buffer.from(fileOpened.value.dataBase64, 'base64').equals(fileBytes),
  );

  console.log('\n=== 5. the reader can download it in its original format ===');
  const saved = reader.saveSealed(fileRef, filePhrase);
  check('save succeeds', saved.ok);
  if (saved.ok) {
    check('saved file exists on disk', existsSync(saved.value.path));
    check('saved filename keeps its extension', saved.value.fileName.endsWith('.xlsx'));
    check(
      'saved bytes are identical to the original',
      Buffer.from(readFileSync(saved.value.path)).equals(fileBytes),
    );
  }

  console.log('\n=== 6. wrong passphrase cannot download either ===');
  const savedWrong = reader.saveSealed(fileRef, 'NOTTHEPASSPHRASE');
  check('save with a wrong passphrase is refused', savedWrong.ok === false);

  console.log('\n=== 7. each message gets its own passphrase ===');
  const a = author.sealPayload({ text: 'same text' });
  const b = author.sealPayload({ text: 'same text' });
  check('two seals give different references', a.value.reference !== b.value.reference);
  check('two seals give different passphrases', a.value.passphrase !== b.value.passphrase);
  check('one message\'s passphrase does not open the other', author.openSealed({ reference: a.value.reference, passphrase: b.value.passphrase }).ok === false);

  console.log('\n=== 8. the list shows what is stored ===');
  const list = author.sealedItems();
  check('list is reachable', list.ok);
  check('list contains the sealed items', list.ok && list.value.length >= 4);
  check('list marks the author own items as out', list.ok && list.value.some((i) => i.role === 'out'));
  const readerList = reader.sealedItems();
  check('reader list marks imported items as in', readerList.ok && readerList.value.some((i) => i.role === 'in'));

  console.log('\n=== 9. input validation ===');
  check('empty text refused', author.sealPayload({ text: '' }).ok === false);
  check('text and file together refused', author.sealPayload({ text: 'x', dataBase64: 'AAAA' }).ok === false);
  check('neither text nor file refused', author.sealPayload({}).ok === false);
  check('bad reference format refused', author.openSealed({ reference: 'nope', passphrase: 'x' }).code === 'BAD_REFERENCE');
  check('reference with a valid prefix but wrong length refused', author.openSealed({ reference: 'YSM_abc', passphrase: 'x' }).code === 'BAD_REFERENCE');

  console.log('\n=== 10. locked state blocks everything ===');
  reader.lock();
  check('sealedItems refused when locked', reader.sealedItems().code === 'LOCKED');
  check('openSealed refused when locked', reader.openSealed({ reference: ref, passphrase: phrase }).code === 'LOCKED');
  check('sealPayload refused when locked', reader.sealPayload({ text: 'x' }).code === 'LOCKED');
  check('saveSealed refused when locked', reader.saveSealed(ref, phrase).code === 'LOCKED');

  console.log('\n=== 11. data at rest has no plaintext ===');
  const dbRaw = readFileSync(join(author.dataDir, 'ysm-account.db')).toString('latin1');
  check('sealed text is not in the database', !dbRaw.includes('meeting is moved'));
  check('sealed filename is not in the database', !dbRaw.includes('Q3 report'));
  check('no passphrase is in the database', !dbRaw.includes(phrase));
} catch (error) {
  console.error('\nUNEXPECTED:', error?.name ?? 'Error', '—', (error?.stack ?? '').split('\n')[1]?.trim());
  fail++;
  failures.push('suite crashed');
} finally {
  for (const d of dirs) {
    try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
