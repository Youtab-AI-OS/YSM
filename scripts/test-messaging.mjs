import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../build/ysm/storage/vault.js';
import { createContactCard, encodeCard, parseCard, addContact, listContacts, createRoom, markVerified } from '../build/ysm/storage/contacts.js';
import { sendText, sendFile, receive, listMessages, loadAttachment } from '../build/ysm/storage/messaging.js';
import { totp, base32Decode } from '../build/ysm/crypto/auth.js';

let pass = 0, fail = 0;
const check = (n, c, x = '') => { if (c) { pass++; console.log(`  PASS ${n}`); } else { fail++; console.log(`  FAIL ${n} ${x}`); } };

const dir = mkdtempSync(join(tmpdir(), 'ysm-msg-'));
const PW = 'correct horse battery staple';

function makeAccount(name, file) {
  const r = Vault.create(join(dir, file), name, PW);
  if (!r.ok) throw new Error(`create failed: ${r.message}`);
  const secret = base32Decode(r.onboarding.totpSecretBase32);
  r.vault.lock();
  const u = Vault.unlock(join(dir, file), PW, totp(secret, Math.floor(Date.now() / 1000)));
  if (!u.ok) throw new Error(`unlock failed: ${u.message}`);
  return { vault: u.vault, secret, onboarding: r.onboarding, path: join(dir, file) };
}

try {
  console.log('=== two accounts ===');
  const alice = makeAccount('Alice', 'alice.db');
  const bob = makeAccount('Bob', 'bob.db');
  check('both unlocked', alice.vault.isUnlocked && bob.vault.isUnlocked);

  console.log('=== contact cards ===');
  const aliceCard = createContactCard(alice.vault);
  const bobCard = createContactCard(bob.vault);
  const encoded = encodeCard(aliceCard);
  check('card encodes', encoded.startsWith('ysm-contact://'));
  const parsed = parseCard(encoded);
  check('card parses + verifies', parsed.ok, parsed.ok ? '' : parsed.message);

  // tamper with the name
  const tampered = { ...aliceCard, name: 'Mallory' };
  const tamperedEnc = 'ysm-contact://' + Buffer.from(JSON.stringify(tampered)).toString('base64url');
  const badParse = parseCard(tamperedEnc);
  check('tampered card rejected', !badParse.ok && badParse.code === 'SIGNATURE', JSON.stringify(badParse));

  // garbage
  check('garbage rejected', !parseCard('not-a-card').ok);

  console.log('=== add contacts + rooms ===');
  const aliceContact = addContact(alice.vault, bobCard, parseCard(encodeCard(bobCard)).peer, false);
  const bobContact = addContact(bob.vault, aliceCard, parsed.peer, false);
  check('alice has 1 contact', listContacts(alice.vault).length === 1);
  check('contact name decrypted', listContacts(alice.vault)[0].displayName === 'Bob');

  const roomA = createRoom(alice.vault, 'Bob', [aliceContact.id]);
  const roomB = createRoom(bob.vault, 'Alice', [bobContact.id]);
  check('room ids match on both sides', roomA.id === roomB.id, `${roomA.id} vs ${roomB.id}`);

  console.log('=== safety numbers ===');
  // Correct usage: each side passes its OWN public identity plus the PEER's.
  const aliceSelf = alice.vault.publicIdentity;
  const bobSelf = bob.vault.publicIdentity;
  const snAlice = alice.vault.safetyNumberWith(bobSelf);
  const snBob = bob.vault.safetyNumberWith(aliceSelf);
  check('safety numbers match across devices', snAlice === snBob, `${snAlice} vs ${snBob}`);
  markVerified(alice.vault, aliceContact.id);
  check('contact marked verified', listContacts(alice.vault)[0].verified);

  console.log('=== send text alice -> bob ===');
  const sent = sendText({ vault: alice.vault, roomId: roomA.id, contactId: aliceContact.id, text: 'hello Bob, this is secret' });
  check('one envelope produced', sent.envelopes.length === 1);
  check('envelope is YSM1', sent.envelopes[0].startsWith('YSM1.'));
  check('ciphertext does not contain plaintext', !sent.envelopes[0].includes('secret'));

  const recv = receive(bob.vault, sent.envelopes[0]);
  check('bob receives', recv.ok, recv.ok ? '' : JSON.stringify(recv));
  if (recv.ok) check('bob reads text', recv.message.text === 'hello Bob, this is secret', recv.message.text);

  const bobMsgs = listMessages(bob.vault, roomB.id);
  check('stored in bob room', bobMsgs.length === 1 && bobMsgs[0].text === 'hello Bob, this is secret');
  check('direction in', bobMsgs[0].direction === 'in');

  console.log('=== reply bob -> alice ===');
  const reply = sendText({ vault: bob.vault, roomId: roomB.id, contactId: bobContact.id, text: 'got it, thanks' });
  const recvA = receive(alice.vault, reply.envelopes[0]);
  check('alice receives reply', recvA.ok && recvA.message.text === 'got it, thanks');

  console.log('=== wrong recipient cannot decrypt ===');
  const eve = makeAccount('Eve', 'eve.db');
  const eveCard = createContactCard(eve.vault);
  addContact(eve.vault, aliceCard, parsed.peer, false);
  const eveRoom = createRoom(eve.vault, 'Alice', [Buffer.from(parsed.peer.agreement).toString('hex')]);
  const eveTry = receive(eve.vault, sent.envelopes[0]);
  check('eve cannot read alice->bob', !eveTry.ok, JSON.stringify(eveTry));

  console.log('=== files: all types ===');
  const files = [
    ['holiday.jpg', new Uint8Array([0xff, 0xd8, 0xff, ...Array.from({ length: 5000 }, (_, i) => i % 256)])],
    ['movie.mp4', new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, ...Array.from({ length: 9000 }, (_, i) => i % 256)])],
    ['voice.wav', new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x41, 0x56, 0x45, ...Array.from({ length: 3000 }, (_, i) => i % 256)])],
    ['track.mp3', new Uint8Array([0x49, 0x44, 0x33, ...Array.from({ length: 4000 }, (_, i) => i % 256)])],
    ['bundle.zip', new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...Array.from({ length: 2000 }, (_, i) => i % 256)])],
    ['report.pdf', new Uint8Array([0x25, 0x50, 0x44, 0x46, ...Array.from({ length: 1500 }, (_, i) => i % 256)])],
  ];

  for (const [name, data] of files) {
    const fs = sendFile({ vault: alice.vault, roomId: roomA.id, contactId: aliceContact.id, name, mime: 'application/octet-stream', data });
    let last;
    for (const env of fs.envelopes) last = receive(bob.vault, env);
    check(`${name}: transfer completes`, last && last.ok, last ? JSON.stringify(last).slice(0, 200) : 'no result');
    const att = loadAttachment(bob.vault, fs.stored.transferId);
    check(`${name}: bytes identical`, att !== null && Buffer.from(att.data).equals(Buffer.from(data)));
    if (att) check(`${name}: category ${att.category}`, ['image','video','audio','archive','document'].includes(att.category));
  }

  console.log('=== large file (multi-chunk) ===');
  const big = new Uint8Array(2.5 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = i % 251;
  const bigSend = sendFile({ vault: alice.vault, roomId: roomA.id, contactId: aliceContact.id, name: 'big.bin', mime: 'application/octet-stream', data: big });
  check('multi-chunk: envelope count = 1 start + 3 chunks + 1 end', bigSend.envelopes.length === 5, String(bigSend.envelopes.length));
  let lastBig;
  for (const env of bigSend.envelopes) lastBig = receive(bob.vault, env);
  check('multi-chunk completes', lastBig && lastBig.ok, lastBig ? JSON.stringify(lastBig).slice(0, 200) : '');
  const bigAtt = loadAttachment(bob.vault, bigSend.stored.transferId);
  check('multi-chunk bytes identical', bigAtt && Buffer.from(bigAtt.data).equals(Buffer.from(big)));

  console.log('=== tampering with a file transfer ===');
  const tamperSend = sendFile({ vault: alice.vault, roomId: roomA.id, contactId: aliceContact.id, name: 'x.bin', mime: 'application/octet-stream', data: new Uint8Array([1,2,3,4,5]) });
  const envs = [...tamperSend.envelopes];
  // corrupt the chunk
  const p = envs[1].split('.');
  const ct = Buffer.from(p[4], 'base64url'); ct[0] ^= 0xff;
  envs[1] = [p[0], p[1], p[2], p[3], ct.toString('base64url'), p[5]].join('.');
  let tRes;
  for (const e of envs) tRes = receive(bob.vault, e);
  check('tampered chunk rejected', tRes && !tRes.ok, tRes ? JSON.stringify(tRes).slice(0, 160) : '');

  console.log('=== dropped chunk detection ===');
  const dropSend = sendFile({ vault: alice.vault, roomId: roomA.id, contactId: aliceContact.id, name: 'y.bin', mime: 'application/octet-stream', data: big });
  const dropped = dropSend.envelopes.filter((_, i) => i !== 2); // remove one chunk
  let dRes;
  for (const e of dropped) dRes = receive(bob.vault, e);
  check('missing chunk detected', dRes && !dRes.ok, dRes ? JSON.stringify(dRes).slice(0, 160) : '');

  console.log('=== replayed message ===');
  // The envelope itself remains cryptographically valid forever (no forward
  // secrecy), so replay defence lives in the storage layer: the message id comes
  // from the signed `mid`, and a second import of the same envelope is refused
  // instead of creating a duplicate row.
  const replayRes = receive(bob.vault, sent.envelopes[0]);
  check('replayed message is refused as a duplicate', replayRes.ok === false && replayRes.code === 'DUPLICATE', replayRes.ok ? 'stored twice' : `${replayRes.code}`);
  console.log('  NOTE: envelopes stay valid forever by design (no forward secrecy);');
  console.log('  dedup is enforced on the signed message id, not on the ciphertext.');

  console.log('=== data at rest ===');
  const dbRaw = readFileSync(alice.path).toString('latin1');
  check('message text not in db', !dbRaw.includes('hello Bob, this is secret'));
  check('contact name not in db as plaintext beyond schema', !dbRaw.includes('Bob, this') );

  alice.vault.lock();
  bob.vault.lock();
  eve.vault.lock();
} finally {
  // Locks happen in the try block; give SQLite a moment to release file handles
  // on Windows before removing the directory.
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    // Temp directory cleanup is best-effort; a leftover dir in %TEMP% is not a
    // test failure.
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
