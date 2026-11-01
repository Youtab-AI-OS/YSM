import { generateIdentity, publicIdentityOf, safetyNumber } from '../build/ysm/crypto/identity.js';
import { seal, open } from '../build/ysm/crypto/envelope.js';
import { sealFile, FileReceiver, sanitizeFilename, resolveCategory } from '../build/ysm/crypto/attachment.js';

const utf8 = new TextEncoder();
let pass = 0;
let fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

console.log('=== identity ===');
const alice = generateIdentity();
const bob = generateIdentity();
const alicePub = publicIdentityOf(alice);
const bobPub = publicIdentityOf(bob);
check('safety number symmetric',
  safetyNumber(alicePub, bobPub) === safetyNumber(bobPub, alicePub));
check('safety number 8 groups of 5',
  /^\d{5} \d{5} \d{5} \d{5} \d{5} \d{5} \d{5} \d{5}$/.test(safetyNumber(alicePub, bobPub)),
  safetyNumber(alicePub, bobPub));
const mallory = generateIdentity();
check('safety number differs for different peer',
  safetyNumber(alicePub, bobPub) !== safetyNumber(alicePub, publicIdentityOf(mallory)));

console.log('=== text envelope ===');
const env = seal({ identity: alice, peer: bobPub, room: 'room1', kind: 'text', body: utf8.encode('hello bob') });
check('starts with YSM1', env.startsWith('YSM1.'));
const opened = open(env, bob);
check('bob decrypts', opened.ok && new TextDecoder().decode(opened.body) === 'hello bob',
  opened.ok ? '' : JSON.stringify(opened));
check('alice cannot open her own sent message (wrong recipient)',
  open(env, alice).code === 'WRONG_RECIPIENT');
check('mallory cannot open', open(env, mallory).code === 'WRONG_RECIPIENT');

console.log('=== tamper detection ===');
const parts = env.split('.');
// flip a ciphertext byte
const ct = Buffer.from(parts[4], 'base64url'); ct[0] ^= 1;
const forgedCt = [parts[0], parts[1], parts[2], parts[3], ct.toString('base64url'), parts[5]].join('.');
check('modified ciphertext rejected', open(forgedCt, bob).code === 'BAD_SIGNATURE');

// modify header (change timestamp)
const hdr = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
hdr.ts = 1;
const forgedHdr = [parts[0], Buffer.from(JSON.stringify(hdr)).toString('base64url'), parts[2], parts[3], parts[4], parts[5]].join('.');
check('modified header rejected', open(forgedHdr, bob).code === 'BAD_SIGNATURE');

// swap signature from another message
const env2 = seal({ identity: alice, peer: bobPub, room: 'room1', kind: 'text', body: utf8.encode('other') });
const p2 = env2.split('.');
const swapped = [parts[0], parts[1], parts[2], parts[3], parts[4], p2[5]].join('.');
check('signature swap rejected', open(swapped, bob).code === 'BAD_SIGNATURE');

// mallory signs a message claiming to be alice
const mEnv = seal({ identity: mallory, peer: bobPub, room: 'r', kind: 'text', body: utf8.encode('I am alice') });
const mp = mEnv.split('.');
const mHdr = JSON.parse(Buffer.from(mp[1], 'base64url').toString());
mHdr.from = parts[1] ? Buffer.from(alicePub.agreement).toString('base64url') : '';
mHdr.fromSign = Buffer.from(alicePub.signing).toString('base64url');
const impersonate = [mp[0], Buffer.from(JSON.stringify(mHdr)).toString('base64url'), mp[2], mp[3], mp[4], mp[5]].join('.');
check('impersonation rejected', open(impersonate, bob).code === 'BAD_SIGNATURE');

console.log('=== same plaintext, different ciphertext ===');
const e1 = seal({ identity: alice, peer: bobPub, room: 'r', kind: 'text', body: utf8.encode('same') });
const e2 = seal({ identity: alice, peer: bobPub, room: 'r', kind: 'text', body: utf8.encode('same') });
check('randomized (no fixed IV leak)', e1 !== e2);

console.log('=== files ===');
const files = [
  ['photo.jpg', new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...new Array(500).fill(7)])],
  ['video.mp4', new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, ...new Array(300).fill(1)])],
  ['voice.wav', new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x41, 0x56, 0x45, ...new Array(200).fill(2)])],
  ['song.mp3', new Uint8Array([0x49, 0x44, 0x33, ...new Array(100).fill(3)])],
  ['archive.zip', new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(1000).fill(4)])],
  ['doc.pdf', new Uint8Array([0x25, 0x50, 0x44, 0x46, ...new Array(100).fill(5)])],
];
for (const [name, data] of files) {
  const t = sealFile({ identity: alice, peer: bobPub, room: 'r', name, mime: 'application/octet-stream', data });
  // bob receives
  const start = open(t.envelopes[0], bob);
  const meta = JSON.parse(new TextDecoder().decode(start.body));
  const recv = new FileReceiver(meta, meta.size === 0 ? 1 : start.header.chunks);
  for (let i = 1; i < t.envelopes.length - 1; i++) {
    const o = open(t.envelopes[i], bob);
    recv.add(o.header.idx, o.body);
  }
  const end = open(t.envelopes[t.envelopes.length - 1], bob);
  recv.markEnded();
  const asm = recv.assemble();
  check(`${name} roundtrip`, asm.ok && Buffer.from(asm.data).equals(Buffer.from(data)), asm.ok ? '' : asm.message);
  if (asm.ok) check(`${name} category=${asm.meta.category}`, ['image','video','audio','archive','document'].includes(asm.meta.category), asm.meta.category);
}

console.log('=== filename sanitisation ===');
const nasty = [
  ['../../etc/passwd', 'passwd'],
  ['..\\..\\windows\\system32\\cmd.exe', 'cmd.exe'],
  ['file<script>.js', 'file_script_.js'],
  ['...hidden', 'hidden'],
  ['CON.txt', 'CON.txt'],
  ['trailing.  ', 'trailing'],
  ['', 'attachment'],
];
for (const [input, want] of nasty) {
  const got = sanitizeFilename(input);
  check(`sanitize ${JSON.stringify(input)} -> ${JSON.stringify(got)}`, got === want);
}

console.log('=== zip that lies about being a jpeg ===');
const liar = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(50).fill(0)]);
check('magic bytes beat extension', resolveCategory('innocent.jpg', liar) === 'archive');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
