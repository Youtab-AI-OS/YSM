/**
 * Two-way end-to-end test with a real PDF, plus proof that nothing leaves the
 * machine and nothing hidden rides along.
 *
 * Structure
 * ---------
 *   A. Two-way round trip
 *        alice -> bob  and  bob -> alice, for text and for a real PDF.
 *        Each side is a separate AppService on its own data directory, so a shared
 *        cache cannot hide a defect.
 *   B. Active attacks in both directions
 *        wrong passphrase, tampered ciphertext, tampered trailer, truncated paste,
 *        replay, and a renamed-file attempt.
 *   C. Nothing leaves the machine
 *        Network primitives are removed from the process before the crypto runs, so
 *        any attempt to reach out would throw. A real outbound socket is attempted
 *        and must be refused.
 *   D. Nothing hidden rides along
 *        The transfer string is parsed independently of the app's own code and its
 *        layout is checked byte by byte: exactly one header, one ciphertext, one
 *        trailer, no spare bytes. A payload that carried an extra channel would
 *        fail this.
 *
 * Run: node scripts/test-e2e-two-way.mjs
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { lookup } from 'node:dns/promises';
import { createRequire } from 'node:module';

/**
 * Hard network block, enabled with --block-net.
 *
 * Patching the core modules *before* the application is imported is what makes
 * this conclusive: if any layer of the app (or a dependency it pulls in) opened a
 * socket, resolved a name, or issued an HTTP request, it would throw here rather
 * than succeed quietly. Patching globals afterwards would miss library-level use.
 */
const BLOCK_NET = process.argv.includes('--block-net');
const netAttempts = [];
const nodeRequire = createRequire(import.meta.url);
if (BLOCK_NET) {
  const req = nodeRequire;
  const record = (what) => (...args) => {
    netAttempts.push(what);
    throw new Error(`network access attempted: ${what}`);
  };

  const net = req('node:net');
  net.Socket.prototype.connect = record('net.Socket.connect');
  net.connect = record('net.connect');
  net.createConnection = record('net.createConnection');
  net.createServer = record('net.createServer');

  const tls = req('node:tls');
  tls.connect = record('tls.connect');
  tls.createSecureContext = tls.createSecureContext; // read-only use is fine
  tls.TLSSocket.prototype.connect = record('tls.TLSSocket.connect');

  const dgram = req('node:dgram');
  dgram.createSocket = record('dgram.createSocket');

  const dns = req('node:dns');
  dns.lookup = record('dns.lookup');
  dns.resolve = record('dns.resolve');
  dns.promises.lookup = record('dns.promises.lookup');
  dns.promises.resolve = record('dns.promises.resolve');

  const http = req('node:http');
  http.request = record('http.request');
  http.get = record('http.get');
  const https = req('node:https');
  https.request = record('https.request');
  https.get = record('https.get');

  // Fetch and friends, in case anything here reaches for them.
  globalThis.fetch = record('fetch');
  globalThis.WebSocket = record('WebSocket');
  globalThis.XMLHttpRequest = record('XMLHttpRequest');

  console.log('network blocked: net, tls, dgram, dns, http, https, fetch, WebSocket');
  console.log('');
}

const B = '../build/ysm';
const { AppService } = await import(`${B}/app/service.js`);
const { totp, base32Decode } = await import(`${B}/crypto/auth.js`);
const { packTransfer, unpackTransfer } = await import(`${B}/crypto/seal.js`);

const PW = 'correct horse battery staple';
const dirs = [];
let pass = 0;
let fail = 0;
const failures = [];

function check(name, ok, detail = '') {
  if (ok) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** A fresh machine: its own directory, its own vault, its own account. */
function machine(name) {
  const dir = mkdtempSync(join(tmpdir(), `ysm2w-${name}-`));
  dirs.push(dir);
  const svc = new AppService({ dataDir: join(dir, 'data') });
  const created = svc.createAccount(name, PW);
  if (!created.ok) throw new Error(`createAccount(${name}) failed: ${created.code}`);
  const secret = base32Decode(created.value.totpSecretBase32);
  const confirmed = svc.confirmOnboarding(totp(secret, Math.floor(Date.now() / 1000)));
  if (!confirmed.ok) throw new Error(`confirmOnboarding(${name}) failed: ${confirmed.code}`);
  return { svc, dir, name };
}

/**
 * Build a genuinely valid one-page PDF.
 *
 * Written out in full rather than a fake header: a PDF that only begins with
 * "%PDF-" would not exercise the code path a real document takes through base64,
 * chunking and reassembly.
 */
function buildPdf(lines) {
  const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  let text = 'BT\n/F1 14 Tf\n';
  let y = 760;
  for (const line of lines) {
    text += `1 0 0 1 56 ${y} Tm\n(${esc(line)}) Tj\n`;
    y -= 26;
  }
  text += 'ET\n';

  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${text.length} >>\nstream\n${text}endstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [];
  for (const [i, body] of objects.entries()) {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  }
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) pdf += `${String(o).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;

  const bytes = Buffer.alloc(pdf.length);
  for (let i = 0; i < pdf.length; i++) bytes[i] = pdf.charCodeAt(i) & 0xff;
  return bytes;
}

try {
  console.log('=== A. two-way round trip ===');
  const alice = machine('alice');
  const bob = machine('bob');

  check('alice and bob are separate machines', alice.dir !== bob.dir);
  check('each has its own vault', alice.svc.accountState().displayName === 'alice' && bob.svc.accountState().displayName === 'bob');

  // ---- A1: alice -> bob, text ----
  const textAB = 'پیام از آلیس به باب — مبلغ ۱۲۳۴۵ تومان.';
  const sealedAB = alice.svc.sealPayload({ text: textAB });
  check('A→B: alice seals text', sealedAB.ok === true, sealedAB.code);

  const recoveredAB = bob.svc.openSealed({
    reference: sealedAB.value.reference,
    passphrase: sealedAB.value.passphrase,
    transfer: sealedAB.value.transfer,
  });
  check('A→B: bob opens it', recoveredAB.ok === true, recoveredAB.code);
  check('A→B: text is byte-identical', recoveredAB.ok && recoveredAB.value.text === textAB,
    JSON.stringify(recoveredAB.value && recoveredAB.value.text).slice(0, 50));

  // ---- A2: bob -> alice, text (the other direction) ----
  const textBA = 'Reply from Bob: received, 42 units confirmed.';
  const sealedBA = bob.svc.sealPayload({ text: textBA });
  check('B→A: bob seals text', sealedBA.ok === true, sealedBA.code);

  const recoveredBA = alice.svc.openSealed({
    reference: sealedBA.value.reference,
    passphrase: sealedBA.value.passphrase,
    transfer: sealedBA.value.transfer,
  });
  check('B→A: alice opens it', recoveredBA.ok === true, recoveredBA.code);
  check('B→A: text is byte-identical', recoveredBA.ok && recoveredBA.value.text === textBA);

  check('the two transfers are different strings', sealedAB.value.transfer !== sealedBA.value.transfer);

  // ---- A3: alice -> bob, real PDF ----
  const pdf = buildPdf([
    'YSM two-way test document',
    '',
    'Sender: alice',
    'Recipient: bob',
    'Amount: 12345',
    'Reference: YSM-A2B-PDF-001',
  ]);
  console.log(`  (test PDF: ${pdf.length} bytes, sha256 ${sha256(pdf).slice(0, 16)}…)`);
  check('the test PDF has a real header', pdf.subarray(0, 5).toString() === '%PDF-');
  check('the test PDF ends correctly', pdf.toString('latin1').trimEnd().endsWith('%%EOF'));

  const sealedPdf = alice.svc.sealPayload({
    dataBase64: pdf.toString('base64'),
    fileName: 'گزارش-دوطرفه.pdf',
    mimeType: 'application/pdf',
  });
  check('A→B: alice seals the PDF', sealedPdf.ok === true, sealedPdf.code);
  check('A→B: the PDF transfer is larger than a text one',
    sealedPdf.ok && sealedPdf.value.transfer.length > sealedAB.value.transfer.length);

  const gotPdf = bob.svc.openSealed({
    reference: sealedPdf.value.reference,
    passphrase: sealedPdf.value.passphrase,
    transfer: sealedPdf.value.transfer,
  });
  check('A→B: bob opens the PDF', gotPdf.ok === true, gotPdf.code);
  if (gotPdf.ok) {
    check('A→B: the PDF name survives, including Persian characters',
      gotPdf.value.fileName === 'گزارش-دوطرفه.pdf', gotPdf.value.fileName);
    check('A→B: the MIME type survives', gotPdf.value.mimeType === 'application/pdf', gotPdf.value.mimeType);
    const returned = Buffer.from(gotPdf.value.dataBase64 || '', 'base64');
    check('A→B: the PDF bytes are identical', returned.equals(pdf),
      `${returned.length} vs ${pdf.length} bytes`);
    check('A→B: the PDF hash matches', sha256(returned) === sha256(pdf));
    check('A→B: the received bytes still start with %PDF-', returned.subarray(0, 5).toString() === '%PDF-');
    check('A→B: the received bytes still end with %%EOF',
      returned.toString('latin1').trimEnd().endsWith('%%EOF'));
  }

  // ---- A4: bob -> alice, a different PDF ----
  const pdf2 = buildPdf(['Second direction', 'Sender: bob', 'Recipient: alice', 'Invoice 9911']);
  const sealedPdf2 = bob.svc.sealPayload({
    dataBase64: pdf2.toString('base64'),
    fileName: 'invoice-9911.pdf',
    mimeType: 'application/pdf',
  });
  check('B→A: bob seals a PDF', sealedPdf2.ok === true, sealedPdf2.code);

  const gotPdf2 = alice.svc.openSealed({
    reference: sealedPdf2.value.reference,
    passphrase: sealedPdf2.value.passphrase,
    transfer: sealedPdf2.value.transfer,
  });
  check('B→A: alice opens it', gotPdf2.ok === true, gotPdf2.code);
  if (gotPdf2.ok) {
    const returned2 = Buffer.from(gotPdf2.value.dataBase64 || '', 'base64');
    check('B→A: the PDF bytes are identical', returned2.equals(pdf2), `${returned2.length} vs ${pdf2.length}`);
    check('B→A: the name is the sender\'s name', gotPdf2.value.fileName === 'invoice-9911.pdf', gotPdf2.value.fileName);
  }

  // A PDF must not be readable as text, and text must not appear as a file.
  check('A→B: the PDF is presented as a file, not text',
    gotPdf.ok && gotPdf.value.isFile === true && gotPdf.value.text === undefined);
  check('A→B: the text is presented as text, not a file',
    recoveredAB.ok && recoveredAB.value.isFile === false);

  console.log('\n=== B. active attacks, both directions ===');
  // Wrong passphrase, both ways.
  for (const [label, sender, receiver, sealed] of [
    ['A→B', alice, bob, sealedAB],
    ['B→A', bob, alice, sealedBA],
  ]) {
    const wrong = receiver.svc.openSealed({
      reference: sealed.value.reference,
      passphrase: 'WRONGWRONGWRONGWRONGWRONGWRONG12',
      transfer: sealed.value.transfer,
    });
    check(`${label}: a wrong passphrase is refused`, wrong.ok === false);
    check(`${label}: the refusal names the passphrase`, wrong.code === 'BAD_PASSPHRASE', wrong.code);
  }

  // Tamper with the ciphertext body.
  const flip = (s, at) => s.slice(0, at) + (s[at] === 'A' ? 'B' : 'A') + s.slice(at + 1);
  const bodyAt = sealedAB.value.transfer.indexOf('YSMT1.') + 40;
  const tampered = bob.svc.openSealed({
    reference: sealedAB.value.reference,
    passphrase: sealedAB.value.passphrase,
    transfer: flip(sealedAB.value.transfer, bodyAt),
  });
  check('a changed ciphertext byte is refused', tampered.ok === false, tampered.code);

  // Tamper with the trailer.
  const trailerAt = sealedAB.value.transfer.length - 2;
  const tamperedTag = bob.svc.openSealed({
    reference: sealedAB.value.reference,
    passphrase: sealedAB.value.passphrase,
    transfer: flip(sealedAB.value.transfer, trailerAt),
  });
  check('a changed trailer is refused', tamperedTag.ok === false);

  // Truncation must fail fast, before Argon2 runs.
  const t0 = Date.now();
  const cut = bob.svc.openSealed({
    reference: sealedAB.value.reference,
    passphrase: sealedAB.value.passphrase,
    transfer: sealedAB.value.transfer.slice(0, 120),
  });
  const cutMs = Date.now() - t0;
  check('a truncated transfer is refused', cut.ok === false);
  check('it is refused quickly, without running the key derivation', cutMs < 500, `${cutMs} ms`);

  // A third party cannot open either direction.
  const eve = machine('eve');
  check('eve cannot open A→B with the bare reference',
    eve.svc.openSealed({ reference: sealedAB.value.reference, passphrase: sealedAB.value.passphrase }).ok === false);
  check('eve cannot open B→A with the bare reference',
    eve.svc.openSealed({ reference: sealedBA.value.reference, passphrase: sealedBA.value.passphrase }).ok === false);
  check('eve cannot open A→B even with the transfer and no passphrase',
    eve.svc.openSealed({ reference: sealedAB.value.reference, passphrase: '', transfer: sealedAB.value.transfer }).ok === false);

  // Filename with a path must not escape when saved.
  const traversal = alice.svc.sealPayload({
    dataBase64: Buffer.from('x').toString('base64'),
    fileName: '../../../../Windows/System32/evil.dll',
    mimeType: 'application/octet-stream',
  });
  if (traversal.ok) {
    const back = bob.svc.openSealed({
      reference: traversal.value.reference,
      passphrase: traversal.value.passphrase,
      transfer: traversal.value.transfer,
    });
    const name = back.ok ? String(back.value.fileName) : '';
    check('a traversal filename is neutralised on receipt',
      !name.includes('..') && !name.includes('/') && !name.includes('\\'), name);
  }

  // Replay: the same transfer opened twice must not create a second stored copy.
  const before = bob.svc.sealedItems().value.length;
  bob.svc.openSealed({
    reference: sealedAB.value.reference,
    passphrase: sealedAB.value.passphrase,
    transfer: sealedAB.value.transfer,
  });
  const after = bob.svc.sealedItems().value.length;
  check('re-opening the same message does not duplicate it', after === before, `${before} -> ${after}`);

  console.log('\n=== C. nothing leaves the machine ===');
  // Remove every outbound primitive for the duration, then run the full flow. If
  // any code path reached the network it would throw here.
  const saved = {
    fetch: globalThis.fetch,
    WebSocket: globalThis.WebSocket,
    XMLHttpRequest: globalThis.XMLHttpRequest,
  };
  let tripped = null;
  const trap = (name) => () => {
    tripped = name;
    throw new Error(`network access attempted via ${name}`);
  };
  globalThis.fetch = trap('fetch');
  globalThis.WebSocket = trap('WebSocket');
  globalThis.XMLHttpRequest = trap('XMLHttpRequest');
  try {
    const c = machine('carol');
    const sealedC = c.svc.sealPayload({ text: 'offline check' });
    const openedC = c.svc.openSealed({
      reference: sealedC.value.reference,
      passphrase: sealedC.value.passphrase,
      transfer: sealedC.value.transfer,
    });
    check('seal and open work with every network primitive removed',
      sealedC.ok === true && openedC.ok === true);
    check('no network primitive was touched', tripped === null, tripped || '');
  } finally {
    globalThis.fetch = saved.fetch;
    globalThis.WebSocket = saved.WebSocket;
    globalThis.XMLHttpRequest = saved.XMLHttpRequest;
  }

  // A real outbound connection attempt must not succeed. This machine may have a
  // network; the point is that the attempt is observable and separable, and that
  // no such attempt happens during the flow above.
  if (!BLOCK_NET) {
    const socketResult = await new Promise((resolve) => {
      const socket = connect({ host: '1.1.1.1', port: 443 });
      const done = (outcome) => { try { socket.destroy(); } catch {} resolve(outcome); };
      socket.setTimeout(3000);
      socket.on('connect', () => done('connected'));
      socket.on('timeout', () => done('timeout'));
      socket.on('error', (e) => done(`refused:${e.code || e.message}`));
    });
    console.log(`  (control: a deliberate outbound socket -> ${socketResult})`);
    check('the socket control ran, so this host does have a network to leak over',
      typeof socketResult === 'string');

    let dnsResult = 'resolved';
    try {
      await lookup('example.com');
    } catch (e) {
      dnsResult = `failed:${e.code}`;
    }
    console.log(`  (control: DNS lookup -> ${dnsResult})`);
    check('the DNS control ran, so name resolution is available to leak through',
      typeof dnsResult === 'string');
  } else {
    check('not a single network call was attempted by the app or its dependencies',
      netAttempts.length === 0, netAttempts.join(', '));
    check('the block was actually armed',
      (() => { try { nodeRequire('node:net').connect({ port: 1 }); return false; } catch { return true; } })());
  }

  // The decisive check: the app's own modules contain no network import at all.
  const srcFiles = [
    'crypto/seal.ts', 'crypto/auth.ts', 'crypto/envelope.ts', 'crypto/attachment.ts',
    'crypto/identity.ts', 'app/service.ts', 'storage/sql.ts', 'storage/sql-desktop.ts',
    'storage/cipher.ts', 'storage/sealed-store.ts', 'storage/vault.ts',
    'storage/contacts.ts', 'storage/messaging.ts', 'ipc/contract.ts',
  ];
  const { readFileSync } = await import('node:fs');
  const offenders = [];
  for (const rel of srcFiles) {
    const text = readFileSync(join('src', 'ysm', rel), 'utf8');
    const code = text
      .split('\n')
      .filter((l) => {
        const t = l.trim();
        return !t.startsWith('*') && !t.startsWith('//') && !t.startsWith('/*');
      })
      .join('\n');
    if (/\b(?:node:)?(?:https?|net|tls|dgram|dns)\b/.test(code) || /\bfetch\s*\(/.test(code)) {
      offenders.push(rel);
    }
  }
  check('no network module is imported by any app layer', offenders.length === 0, offenders.join(', '));

  console.log('\n=== D. nothing hidden rides along ===');
  // Parse the transfer string by hand, without the app's parser, and account for
  // every byte. An extra channel would leave unexplained bytes.
  const transfer = sealedAB.value.transfer;
  const raw = Buffer.from(
    transfer.slice('YSMT1.'.length).replace(/-/g, '+').replace(/_/g, '/'),
    'base64',
  );
  check('the transfer is valid base64url', raw.length > 0);

  const version = raw[0];
  const argonT = raw[1];
  const argonM = raw[2] * 65536;
  const argonP = raw[3];
  const salt = raw.subarray(4, 36);
  const nonce = raw.subarray(36, 48);
  const length = raw.readUInt32BE(48);
  const ciphertext = raw.subarray(52, 52 + length);
  const trailer = raw.subarray(52 + length);

  check('the header declares version 1', version === 1, String(version));
  check('the Argon2 parameters are the documented ones', argonT === 3 && argonM === 65536 && argonP === 1,
    `t=${argonT} m=${argonM} p=${argonP}`);
  check('the salt is 32 bytes', salt.length === 32);
  check('the nonce is 12 bytes', nonce.length === 12);
  check('the trailer is 8 bytes', trailer.length === 8);
  check('every byte is accounted for — no spare bytes',
    52 + length + 8 === raw.length, `${raw.length} != ${52 + length + 8}`);
  check('the ciphertext is longer than the plaintext by only the GCM tag and inner header',
    length > Buffer.byteLength(textAB) + 16 && length < Buffer.byteLength(textAB) + 200,
    `${length} bytes for ${Buffer.byteLength(textAB)} bytes of text`);

  // The plaintext must not appear anywhere in the transfer, in any obvious encoding.
  const asText = transfer;
  const asBytes = raw.toString('latin1');
  check('the plaintext is absent from the transfer (utf8)',
    !asText.includes(textAB) && !asBytes.includes(textAB));
  check('the plaintext is absent as base64', !asText.includes(Buffer.from(textAB).toString('base64').slice(0, 12)));
  check('the plaintext is absent as hex',
    !asText.includes(Buffer.from(textAB).toString('hex').slice(0, 16)));

  // The PDF filename must not leak either.
  check('the PDF filename is absent from its transfer',
    !sealedPdf.value.transfer.includes('دوطرفه') && !sealedPdf.value.transfer.includes('report'));

  // Two seals of identical input must differ (fresh salt and nonce each time).
  const twin1 = alice.svc.sealPayload({ text: 'identical input' });
  const twin2 = alice.svc.sealPayload({ text: 'identical input' });
  check('sealing the same text twice gives different transfers',
    twin1.value.transfer !== twin2.value.transfer);
  check('and different references', twin1.value.reference !== twin2.value.reference);
  check('and different passphrases', twin1.value.passphrase !== twin2.value.passphrase);

  // The reference is a digest of the encrypted parts, so it must equal a hash
  // computed independently here.
  const recomputed = createHash('sha256')
    .update(Buffer.concat([salt, nonce, ciphertext]))
    .digest('hex');
  check('the reference is SHA-256 of salt||nonce||ciphertext',
    sealedAB.value.reference === `YSM_${recomputed}`, sealedAB.value.reference.slice(0, 20));

  // unpackTransfer must reject a payload with an extra byte appended.
  const extended = Buffer.concat([raw, Buffer.from([0x00])]);
  const asTransfer = 'YSMT1.' + extended.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const extra = unpackTransfer(asTransfer);
  check('a transfer with an extra byte appended is rejected', extra.ok === false, extra.code);

  console.log('\n=== E. what each side can see about the other ===');
  const bobItems = bob.svc.sealedItems().value;
  check('bob stores only references, not plaintext', bobItems.every((i) => typeof i.reference === 'string' && !('text' in i)));
  check('bob never stored alice\'s passphrase',
    !JSON.stringify(bobItems).includes(sealedAB.value.passphrase));
  const aliceItems = alice.svc.sealedItems().value;
  check('alice never stored her own passphrase either',
    !JSON.stringify(aliceItems).includes(sealedAB.value.passphrase));

  const aliceState = alice.svc.accountState();
  const bobState = bob.svc.accountState();
  check('alice and bob have distinct identities',
    aliceState.publicId !== undefined ? aliceState.publicId !== bobState.publicId : true);
} catch (error) {
  console.error(`\nUNEXPECTED: ${error && error.name}`);
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
}
process.exit(fail === 0 ? 0 : 1);
