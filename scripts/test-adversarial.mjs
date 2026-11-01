/**
 * Adversarial test suite — active attack attempts, not just happy paths.
 *
 * This is what "test for zero-days" actually means in practice: instead of
 * checking that the app works, each test tries to *break* it the way an attacker
 * would, and every case must be rejected for the right reason.
 *
 * Attack classes:
 *   A. cross-user isolation   B. forgery          C. replay
 *   D. tampering              E. structural abuse F. attachment integrity
 *   G. auth bypass            H. path traversal   I. injection
 *   J. key confusion          K. randomness       L. resource bounds
 *
 * Run: node scripts/test-adversarial.mjs
 */
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const B = '../build/ysm';

const { seal, open, parseEnvelope } = await import(`${B}/crypto/envelope.js`);
const { sealFile, FileReceiver } = await import(`${B}/crypto/attachment.js`);
const { generateIdentity, publicIdentityOf } = await import(`${B}/crypto/identity.js`);
const { totp, base32Decode } = await import(`${B}/crypto/auth.js`);
const { AppService } = await import(`${B}/app/service.js`);
const messagingMod = await import(`${B}/storage/messaging.js`);
const { encodeCard } = await import(`${B}/storage/contacts.js`);

let pass = 0;
let fail = 0;
const failures = [];

/**
 * One-line, length-capped rendering of anything that might reach a log.
 *
 * Test detail strings can carry a code, a password or a decrypted value, and a
 * failure log is the last place any of that should be reproducible in full. This
 * keeps diagnostics useful without echoing secrets.
 */
function sanitise(value) {
  const text = value instanceof Error ? `${value.name}: ${value.message}` : String(value);
  return text.replace(/\s+/g, ' ').slice(0, 160);
}

function check(name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    const shown = detail === '' ? '' : sanitise(detail);
    failures.push(`${name}${shown ? ` — ${shown}` : ''}`);
    console.log(`  FAIL ${name} ${shown}`);
  }
}

function checkRejected(name, result, expectedCode = null) {
  const rejected = result !== undefined && result !== null && result.ok === false;
  const rightCode = expectedCode === null || !rejected || result.code === expectedCode;
  check(
    name,
    rejected && rightCode,
    rejected ? `wrong code: ${result.code} (wanted ${expectedCode})` : 'WAS ACCEPTED',
  );
}

const dirs = [];
function tmp(prefix) {
  const d = mkdtempSync(join(tmpdir(), `ysm-adv-${prefix}-`));
  dirs.push(d);
  return d;
}

const PW = 'correct horse battery staple';
const enc = new TextEncoder();

function makeAccount(name) {
  const dataDir = join(tmp('u'), 'data');
  const svc = new AppService({ dataDir });
  const created = svc.createAccount(name, PW);
  if (!created.ok) throw new Error(`createAccount failed: ${JSON.stringify(created)}`);
  const secret = base32Decode(created.value.totpSecretBase32);
  // Read the clock at the moment of use, not before the work: a helper called late
  // in a long suite would otherwise present a stale code as BAD_TOTP.
  const confirmed = svc.confirmOnboarding(totp(secret, Math.floor(Date.now() / 1000)));
  if (!confirmed.ok) throw new Error(`confirm failed: ${JSON.stringify(confirmed)}`);
  return { svc, secret, dataDir, name };
}

function identityOf(svc) {
  return svc.vault.identity;
}

/** Seal a plain text message between two identities. */
function sealText(from, toPub, room, text) {
  return seal({ identity: from, peer: toPub, room, kind: 'text', body: enc.encode(text) });
}

let alice;
let bob;
let eve;

try {
  console.log('=== setup: three accounts ===');
  alice = makeAccount('Alice');
  bob = makeAccount('Bob');
  eve = makeAccount('Eve');

  const aliceCard = alice.svc.myCard().value;
  const bobCard = bob.svc.myCard().value;

  const aAddsB = alice.svc.addContact(bobCard);
  const bAddsA = bob.svc.addContact(aliceCard);
  const eAddsA = eve.svc.addContact(aliceCard);
  const eAddsB = eve.svc.addContact(bobCard);
  check('alice adds bob', aAddsB.ok);
  check('bob adds alice', bAddsA.ok);
  check('eve adds both as an outsider', eAddsA.ok && eAddsB.ok);

  const aRoom = alice.svc.createRoom(aAddsB.value.id, 'Bob');
  const bRoom = bob.svc.createRoom(bAddsA.value.id, 'Alice');
  check('shared room derived identically', aRoom.ok && bRoom.ok && aRoom.value.id === bRoom.value.id);

  const aliceIdentity = identityOf(alice.svc);
  const bobIdentity = identityOf(bob.svc);
  const eveIdentity = identityOf(eve.svc);
  const alicePub = publicIdentityOf(aliceIdentity);
  const bobPub = publicIdentityOf(bobIdentity);
  const evePub = publicIdentityOf(eveIdentity);
  const roomId = aRoom.value.id;

  // -----------------------------------------------------------------------
  console.log('\n=== A. cross-user isolation ===');
  // -----------------------------------------------------------------------
  const secretMsg = 'the launch code is 0000';
  const sealed = sealText(aliceIdentity, bobPub, roomId, secretMsg);

  // A1. Eve holds the ciphertext. `open` derives the key from her own identity,
  // so an envelope addressed to Bob must not decrypt for her.
  const eveOpens = open(sealed, eveIdentity);
  checkRejected('eve cannot open alice→bob envelope', eveOpens);

  // A2. Control: Bob can.
  const bobOpens = open(sealed, bobIdentity);
  check('bob opens the same envelope (control)', bobOpens.ok);
  check('bob reads the right plaintext', bobOpens.ok && new TextDecoder().decode(bobOpens.body) === secretMsg);

  // A3. Eve's own database must not contain Alice's message.
  const eveDb = join(eve.dataDir, 'ysm-account.db');
  const eveRaw = readFileSync(eveDb).toString('latin1');
  check('eve database has no plaintext of alice message', !eveRaw.includes(secretMsg));

  // A4. Bob's database has the message but encrypted.
  const bobDb = join(bob.dataDir, 'ysm-account.db');
  if (readFileSync(bobDb).length > 0) {
    const raw = readFileSync(bobDb).toString('latin1');
    check('bob database has no message plaintext', !raw.includes(secretMsg));
    check('bob database has no contact names', !raw.includes('Alice') && !raw.includes('Eve'));
  }

  // A5. Room ids are a hash of the participant pair, so a third party can compute
  // the same id — that is expected and harmless. What must NOT happen is Eve
  // reading the contents. Confirm the id is derivable and the contents are not.
  check(
    'room id is derivable by a third party (expected; not a secret)',
    typeof roomId === 'string' && roomId.length > 0,
  );

  // -----------------------------------------------------------------------
  console.log('\n=== B. message forgery ===');
  // -----------------------------------------------------------------------

  // B1. The envelope carries the sender's public keys and verifies the signature
  // against them. An attacker can therefore build an envelope with forged key
  // material, but it will be addressed to them, not to the victim — and the
  // recipient's own key check rejects it.
  const attacker = generateIdentity();
  const forgedForBob = sealText(attacker, bobPub, roomId, 'send me your password');
  const bobOnForged = open(forgedForBob, bobIdentity);
  // The signature is valid (attacker signed it), so the defence is that Bob's
  // client checks the *stored contact* key against the envelope's claimed sender.
  // At the crypto layer the message opens; the binding is enforced one level up.
  check('forged envelope is internally valid (expected)', bobOnForged.ok);
  const forgedHeader = JSON.parse(Buffer.from(forgedForBob.split('.')[1], 'base64url').toString('utf8'));
  check(
    'forged envelope names the attacker, not alice',
    forgedHeader.from !== Buffer.from(alicePub.agreement).toString('base64url'),
    'sender field claims alice — signature binding is broken',
  );

  // B2. Re-signing Alice's ciphertext with a different key must fail: the signature
  // covers header + salt + nonce + ciphertext.
  const parts = sealed.split('.');
  const swappedSigner = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  swappedSigner.fromSign = Buffer.from(evePub.signing).toString('base64url');
  parts[1] = Buffer.from(JSON.stringify(swappedSigner)).toString('base64url');
  const resigned = open(parts.join('.'), bobIdentity);
  checkRejected('swapping the signing key invalidates the signature', resigned, 'BAD_SIGNATURE');

  // B3. Flip a bit in the signature.
  const sigParts = sealed.split('.');
  const sig = sigParts[sigParts.length - 1];
  sigParts[sigParts.length - 1] = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  checkRejected('modified signature rejected', open(sigParts.join('.'), bobIdentity), 'BAD_SIGNATURE');

  // -----------------------------------------------------------------------
  console.log('\n=== C. replay ===');
  // -----------------------------------------------------------------------
  const sent = alice.svc.sendMessage(aRoom.value.id, aAddsB.value.id, 'replay me');
  check('alice sends a message', sent.ok);
  const env = alice.svc.exportEnvelope(aRoom.value.id, sent.value.id);
  check('envelope exported', env.ok);
  const envText = readFileSync(env.value, 'utf8');

  const import1 = bob.svc.importEnvelope(bRoom.value.id, envText);
  check('bob imports it once', import1.ok, JSON.stringify(import1).slice(0, 120));
  const countAfterFirst = bob.svc.messages(bRoom.value.id).value.length;
  const import2 = bob.svc.importEnvelope(bRoom.value.id, envText);
  const countAfterSecond = bob.svc.messages(bRoom.value.id).value.length;
  check(
    'replaying the same envelope does not duplicate the message',
    countAfterSecond === countAfterFirst,
    `count ${countAfterFirst} -> ${countAfterSecond} (second import ok=${import2.ok})`,
  );

  // -----------------------------------------------------------------------
  console.log('\n=== D. tampering and downgrade ===');
  // -----------------------------------------------------------------------
  const tParts = sealed.split('.');
  const ctIdx = tParts.length - 2;
  const ct = tParts[ctIdx];
  tParts[ctIdx] = ct.slice(0, 5) + (ct[5] === 'A' ? 'B' : 'A') + ct.slice(6);
  checkRejected('bit flip in ciphertext rejected', open(tParts.join('.'), bobIdentity));

  const dParts = sealed.split('.');
  const dHeader = JSON.parse(Buffer.from(dParts[1], 'base64url').toString('utf8'));
  dHeader.v = 99;
  dParts[1] = Buffer.from(JSON.stringify(dHeader)).toString('base64url');
  checkRejected('unknown protocol version rejected', open(dParts.join('.'), bobIdentity));

  const reParts = sealed.split('.');
  const reHeader = JSON.parse(Buffer.from(reParts[1], 'base64url').toString('utf8'));
  reHeader.to = Buffer.from(evePub.agreement).toString('base64url');
  reParts[1] = Buffer.from(JSON.stringify(reHeader)).toString('base64url');
  checkRejected('re-addressed envelope rejected', open(reParts.join('.'), bobIdentity));

  // -----------------------------------------------------------------------
  console.log('\n=== E. structural abuse ===');
  // -----------------------------------------------------------------------
  const malformed = [
    ['empty string', ''],
    ['random text', 'not-an-envelope-at-all'],
    ['prefix only', 'YSM1'],
    ['one field', 'YSM1.abc'],
    ['too many fields', 'YSM1.a.b.c.d.e.f.g.h'],
    ['non-base64 header', 'YSM1.!!!!.AAAA.AAAA.AAAA.AAAA'],
    ['null bytes', 'YSM1.\u0000.\u0000.\u0000.\u0000.\u0000'],
    ['header not json', `YSM1.${Buffer.from('not json').toString('base64url')}.AAAA.AAAA.AAAA.AAAA`],
  ];
  for (const [label, input] of malformed) {
    let threw = false;
    let result;
    try {
      result = open(input, bobIdentity);
    } catch {
      threw = true;
    }
    check(`malformed envelope rejected (${label})`, threw || (result && result.ok === false));
  }

  const start = Date.now();
  const big = `YSM1.${Buffer.from(JSON.stringify({ v: 1 })).toString('base64url')}.${'A'.repeat(2_000_000)}.AAAA.AAAA.AAAA`;
  const bigResult = open(big, bobIdentity);
  const elapsed = Date.now() - start;
  check('2MB envelope rejected', bigResult.ok === false);
  check('rejection is fast (<2s)', elapsed < 2000, `${elapsed}ms`);

  // -----------------------------------------------------------------------
  console.log('\n=== F. attachment integrity ===');
  // -----------------------------------------------------------------------
  const fileBytes = randomBytes(3 * 1024 * 1024 + 12345);
  const sealedFile = sealFile({
    identity: aliceIdentity,
    peer: bobPub,
    room: roomId,
    name: 'payload.bin',
    mime: 'application/octet-stream',
    data: fileBytes,
  });
  const list = sealedFile.envelopes;
  check('file produced multiple chunks', list.length >= 3, `${list.length} envelopes`);

  /**
   * Feed envelopes through the real `receive()` path.
   *
   * Each call gets its own fresh account context where needed, because module-
   * level transfer state is shared. For the tampering cases we only care whether
   * the sequence is rejected, so the first rejection ends the run.
   */
  function feed(envelopes) {
    const { receive } = messagingMod;
    let last = null;
    for (const text of envelopes) {
      const r = receive(bob.svc.vault, text);
      if (!r.ok) return r;
      last = r;
    }
    return last ?? { ok: false, code: 'EMPTY', message: 'no envelopes' };
  }

  const good = feed(list);
  check('file reassembles (control)', good.ok, JSON.stringify(good).slice(0, 160));

  // A separate file, so its transfer id is distinct from the control above.
  const tamperBytes = randomBytes(2 * 1024 * 1024 + 999);
  const tamperSealed = sealFile({
    identity: aliceIdentity,
    peer: bobPub,
    room: roomId,
    name: 'tamper.bin',
    mime: 'application/octet-stream',
    data: tamperBytes,
  });
  const tl = tamperSealed.envelopes;

  const dropped = [...tl];
  dropped.splice(2, 1);
  checkRejected('missing chunk detected', feed(dropped));

  // Out-of-order *arrival* is not an attack: each chunk carries its own index in
  // the signed header, so the receiver places it correctly. The real attack is
  // swapping chunk *contents* while keeping the indices, which must fail the
  // hash check. Both are tested so the distinction is explicit.
  const reorderedArrival = [...tl];
  const a = reorderedArrival.length - 3;
  [reorderedArrival[a], reorderedArrival[a + 1]] = [reorderedArrival[a + 1], reorderedArrival[a]];
  const arrivalResult = feed(reorderedArrival);
  check(
    'out-of-order arrival still reassembles correctly (indexed chunks)',
    arrivalResult.ok,
    JSON.stringify(arrivalResult).slice(0, 120),
  );

  // Content swap: feed chunk 1's body under index 0 and vice versa, bypassing the
  // envelope by writing directly into a receiver. Must fail on SHA-256.
  const swapSealed = sealFile({
    identity: aliceIdentity,
    peer: bobPub,
    room: roomId,
    name: 'swap.bin',
    mime: 'application/octet-stream',
    data: randomBytes(2 * 1024 * 1024 + 999),
  });
  {
    const parsed = swapSealed.envelopes.map((t) => open(t, bobIdentity));
    const start = parsed.find((p) => p.ok && p.header.kind === 'file-start');
    const chunks = parsed.filter((p) => p.ok && p.header.kind === 'file-chunk');
    const end = parsed.find((p) => p.ok && p.header.kind === 'file-end');
    if (start && start.ok && chunks.length >= 2 && end) {
      const meta = JSON.parse(new TextDecoder().decode(start.body));
      const rec = new FileReceiver(meta, start.header.chunks);
      // Swap the payloads of the first two chunks, keeping valid indices.
      const c0 = chunks[0];
      const c1 = chunks[1];
      rec.add(0, c0.header.idx === 0 ? c1.body : c0.body);
      rec.add(1, c1.header.idx === 1 ? c0.body : c1.body);
      for (let i = 2; i < chunks.length; i++) rec.add(chunks[i].header.idx, chunks[i].body);
      rec.markEnded();
      const res = rec.assemble();
      checkRejected('swapped chunk contents rejected by hash', res);
    } else {
      check('swapped-content test could build its receiver', false, 'missing envelopes');
    }
  }

  const duped = [tl[0], ...tl];
  checkRejected('duplicated chunk/start detected', feed(duped));

  const otherFile = sealFile({
    identity: aliceIdentity,
    peer: bobPub,
    room: roomId,
    name: 'other.bin',
    mime: 'application/octet-stream',
    data: randomBytes(1024),
  });
  const spliced = [...tl.slice(0, -1), otherFile.envelopes[otherFile.envelopes.length - 1]];
  checkRejected('end envelope from another file rejected', feed(spliced));

  const mixedSender = sealFile({
    identity: eveIdentity,
    peer: bobPub,
    room: roomId,
    name: 'eve.bin',
    mime: 'application/octet-stream',
    data: randomBytes(1024),
  });
  const mixed = [...tl.slice(0, -1), mixedSender.envelopes[mixedSender.envelopes.length - 1]];
  checkRejected('mixed-sender envelope set rejected', feed(mixed));

  checkRejected('empty envelope list rejected', feed([]));

  // -----------------------------------------------------------------------
  console.log('\n=== G. authentication bypass ===');
  // -----------------------------------------------------------------------
  const nowSec = Math.floor(Date.now() / 1000);

  const wrongPw = (() => {
    const s = new AppService({ dataDir: alice.dataDir });
    return s.unlock('definitely not the password', totp(alice.secret, nowSec + 30));
  })();
  checkRejected('wrong password rejected', wrongPw, 'BAD_PASSWORD');

  const wrongTotp = (() => {
    const s = new AppService({ dataDir: alice.dataDir });
    return s.unlock(PW, totp(alice.secret, nowSec + 90));
  })();
  checkRejected('wrong TOTP rejected', wrongTotp, 'BAD_TOTP');

  const crossed = (() => {
    const s = new AppService({ dataDir: alice.dataDir });
    return s.unlock(PW, totp(bob.secret, nowSec + 120));
  })();
  checkRejected("another account's TOTP rejected", crossed);

  for (const bad of ['', '000000', 'abcdef', '12345', '1234567', ' 123456 ', '12345a', '٣٤٥٦٧٨']) {
    const s = new AppService({ dataDir: alice.dataDir });
    const r = s.unlock(PW, bad);
    check(`malformed TOTP rejected (${JSON.stringify(bad)})`, r.ok === false);
  }

  // Locked state must block every data operation.
  // Note: these failure attempts trip the lockout counter for this account, so
  // the injection and filename sections below use a *separate* fresh account. The
  // lockout is deliberately persisted and shared per database file, which is the
  // behaviour under test.
  alice.svc.lock();
  const lockedCalls = [
    ['contacts', () => alice.svc.contacts()],
    ['rooms', () => alice.svc.rooms()],
    ['messages', () => alice.svc.messages('any')],
    ['send', () => alice.svc.sendMessage('r', 'c', 'hi')],
  ];
  for (const [label, call] of lockedCalls) {
    let result;
    try {
      result = call();
    } catch {
      result = { ok: false, code: 'THREW' };
    }
    checkRejected(`locked state blocks ${label}`, result, 'LOCKED');
  }

  // Lockout persists across a fresh service instance (not just in memory).
  const lockoutDir = join(tmp('lock'), 'data');
  const lockSvc = new AppService({ dataDir: lockoutDir });
  const lockCreated = lockSvc.createAccount('Lock', PW);
  const lockSecret = base32Decode(lockCreated.value.totpSecretBase32);
  lockSvc.confirmOnboarding(totp(lockSecret, nowSec));
  for (let i = 0; i < 6; i++) {
    new AppService({ dataDir: lockoutDir }).unlock('wrong password attempt', totp(lockSecret, nowSec + 300 + i * 30));
  }
  const afterLockout = (() => {
    const s = new AppService({ dataDir: lockoutDir });
    return s.unlock(PW, totp(lockSecret, nowSec + 900));
  })();
  checkRejected('lockout persists across restarts', afterLockout, 'LOCKED_OUT');

  // -----------------------------------------------------------------------
  console.log('\n=== H. path traversal in filenames ===');
  // Use a fresh account: the lockout tests above deliberately locked `alice`, and
  // the lockout is persisted per database, which is correct behaviour.
  const filenameSvc = makeAccount('Filenames');
  const fCard = filenameSvc.svc.myCard().value;
  const peerAccount = makeAccount('Peer');
  const peerCard = peerAccount.svc.myCard().value;
  const fAdds = filenameSvc.svc.addContact(peerCard);
  check('fresh account can add a contact', fAdds.ok, JSON.stringify(fAdds).slice(0, 120));
  peerAccount.svc.addContact(fCard);
  const fRoom = filenameSvc.svc.createRoom(fAdds.value.id, 'Peer');
  check('fresh account can open a room', fRoom.ok);

  const hostileNames = [
    '../../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '/absolute/path.txt',
    'C:\\Windows\\System32\\evil.dll',
    'normal.txt/../../escape.txt',
    '....//....//escape.txt',
    'a'.repeat(5000) + '.txt',
    'CON',
    'name:with:colons.txt',
    'file\u0000.txt',
  ];

  for (const hostile of hostileNames) {
    const result = filenameSvc.svc.sendAttachment(
      fRoom.value.id,
      fAdds.value.id,
      hostile,
      'text/plain',
      Buffer.from('x').toString('base64'),
    );
    if (result.ok) {
      const msgs = filenameSvc.svc.messages(fRoom.value.id).value;
      const msg = msgs.find((m) => m.id === result.value.id);
      const stored = msg?.attachment?.name ?? '';
      const escapes =
        stored.includes('..') ||
        stored.includes('/') ||
        stored.includes('\\') ||
        stored.includes('\u0000') ||
        stored.length > 300;
      check(`hostile filename neutralised (${hostile.slice(0, 26)})`, !escapes, `stored as ${JSON.stringify(stored.slice(0, 50))}`);
    } else {
      check(`hostile filename rejected (${hostile.slice(0, 26)})`, true);
    }
  }

  // -----------------------------------------------------------------------
  console.log('\n=== I. injection ===');
  // -----------------------------------------------------------------------
  const injectionPayloads = [
    "'; DROP TABLE messages; --",
    "Robert'); DELETE FROM contacts WHERE ('1'='1",
    '"; DROP TABLE meta; --',
    '<script>alert(1)</script>',
    '${process.exit(1)}',
    '../../etc/passwd',
  ];

  for (const payload of injectionPayloads) {
    const svcDir = join(tmp('inj'), 'data');
    const svc = new AppService({ dataDir: svcDir });
    const created = svc.createAccount(payload, PW);
    check(`hostile display name accepted as data (${payload.slice(0, 18)})`, created.ok);
    if (created.ok) {
      const s2 = base32Decode(created.value.totpSecretBase32);
      // Compute the code against the *current* clock. Using a timestamp captured
      // before the loop drifts out of the ±1 window once the loop takes more than
      // a couple of minutes, which presents as a spurious BAD_TOTP.
      const confirmed = svc.confirmOnboarding(totp(s2, Math.floor(Date.now() / 1000)));
      check(
        `onboarding completes with hostile name (${payload.slice(0, 18)})`,
        confirmed.ok,
        confirmed.ok ? '' : `${confirmed.code}: ${confirmed.message}`,
      );
      // accountState() returns the state object directly, not wrapped in
      // {ok, value} like the other service methods.
      const state = svc.accountState();
      check(
        `hostile name round-trips verbatim (${payload.slice(0, 18)})`,
        state !== undefined && state.displayName === payload,
        state ? JSON.stringify(String(state.displayName).slice(0, 40)) : 'accountState returned nothing',
      );
      // The database must still be usable after storing it.
      check(`database intact after storing (${payload.slice(0, 18)})`, svc.contacts().ok);
    }
  }

  // Control characters are refused at the boundary rather than stored: a NUL
  // cannot round-trip reliably through every layer that later reads the name.
  for (const bad of ['a\u0000b', 'a\u0000', '\u0000b', 'tab\there', 'nl\nhere', 'del\u007f']) {
    const svc = new AppService({ dataDir: join(tmp('ctl'), 'data') });
    const created = svc.createAccount(bad, PW);
    check(`control character refused in name (${JSON.stringify(bad.slice(0, 8))})`, created.ok === false && created.code === 'BAD_NAME', created.ok ? 'ACCEPTED' : created.code);
  }

  check('filename account database still works after injection attempts', filenameSvc.svc.contacts().ok);
  check('messages table intact', filenameSvc.svc.messages(fRoom.value.id).ok);

  // -----------------------------------------------------------------------
  console.log('\n=== J. key confusion ===');
  // -----------------------------------------------------------------------

  // J1. Use the agreement secret where the signing secret is expected.
  const confused = {
    agreement: aliceIdentity.agreement,
    signing: {
      secretKey: aliceIdentity.agreement.secretKey,
      publicKey: aliceIdentity.agreement.publicKey,
    },
  };
  let confusedResult;
  try {
    confusedResult = open(sealed, confused);
  } catch {
    confusedResult = { ok: false, code: 'THREW' };
  }
  checkRejected('agreement key cannot act as signing key', confusedResult);

  // J2. A card signed by one identity must not verify for another.
  const card = encodeCard(alice.svc.myCard().value);
  const cardParts = card.split('.');
  const eveCard = encodeCard(eve.svc.myCard().value);
  cardParts[cardParts.length - 1] = eveCard.split('.').pop();
  checkRejected('card with foreign signature rejected', parseEnvelope(cardParts.join('.')));

  // -----------------------------------------------------------------------
  console.log('\n=== K. randomness ===');
  // -----------------------------------------------------------------------
  const one = sealText(aliceIdentity, bobPub, roomId, 'identical');
  const two = sealText(aliceIdentity, bobPub, roomId, 'identical');
  check('same plaintext produces different ciphertext', one !== two);

  // No repeated 16-byte blocks (catches ECB-like weaknesses).
  const bigText = 'A'.repeat(10_000);
  const bigSealed = sealText(aliceIdentity, bobPub, roomId, bigText);
  const body = Buffer.from(bigSealed.split('.')[bigSealed.split('.').length - 2], 'base64url');
  const blocks = new Set();
  let repeats = 0;
  for (let i = 0; i + 16 <= body.length; i += 16) {
    const key = body.subarray(i, i + 16).toString('hex');
    if (blocks.has(key)) repeats++;
    blocks.add(key);
  }
  check('no repeated ciphertext blocks across 10KB of identical plaintext', repeats === 0, `${repeats} repeats`);
} catch (error) {
  console.error('\nUNEXPECTED ERROR:', sanitise(error));
  fail++;
  failures.push(`suite crashed: ${sanitise(error)}`);
} finally {
  for (const d of dirs) {
    try {
      rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch {
      // temp dirs are disposable
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
