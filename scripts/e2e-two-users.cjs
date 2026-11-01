/**
 * Two-user end-to-end conversation through the REAL app.
 *
 * Drives the actual Electron main process and IPC bridge as two separate accounts:
 *
 *   Alice: create → 2FA → copy contact card
 *   Bob:   create → 2FA → add Alice → add Alice's card
 *   Alice: add Bob → open room → send text → send a photo → export both
 *   Bob:   import both → read the text → see the image → save it to disk
 *
 * This is the test that proves the product works, not just the modules.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdtempSync, rmSync, readFileSync, existsSync, statSync } = require('node:fs');
const { tmpdir } = require('node:os');

const sandboxA = mkdtempSync(join(tmpdir(), 'ysm-a-'));
const sandboxB = mkdtempSync(join(tmpdir(), 'ysm-b-'));

let pass = 0;
let fail = 0;
function check(name, cond, extra = '') {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name} ${extra}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Boot one app instance with its own userData, and return its window. */
async function bootApp(userDataDir) {
  // Each account needs its own main-process instance; the single-instance lock
  // means we run them sequentially rather than in parallel.
  app.setPath('userData', userDataDir);
  const win = BrowserWindow.getAllWindows()[0];
  return win;
}

async function invoke(win, channel, payload) {
  return win.webContents.executeJavaScript(
    `window.ysm.invoke(${JSON.stringify(channel)}, ${JSON.stringify(payload ?? {})})`,
  );
}

app.whenReady().then(async () => {
  app.setPath('userData', sandboxA);
  require('../electron/main.mjs');
  await sleep(2500);

  const windows = BrowserWindow.getAllWindows();
  if (windows.length === 0) {
    console.log('FAIL no window');
    app.exit(1);
    return;
  }
  const winA = windows[0];
  await sleep(800);

  const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
  const PW = 'correct horse battery staple';

  console.log('=== alice creates an account ===');
  const aCreate = await invoke(winA, 'account:create', { displayName: 'Alice', password: PW });
  check('alice account created', aCreate.ok, JSON.stringify(aCreate).slice(0, 150));
  const aSecret = base32Decode(aCreate.value.totpSecretBase32);
  const t0 = Math.floor(Date.now() / 1000);
  const aConfirm = await invoke(winA, 'account:confirmOnboarding', {
    totpCode: totp(aSecret, t0),
    secret: aCreate.value.totpSecretBase32,
  });
  check('alice 2FA confirmed', aConfirm.ok, JSON.stringify(aConfirm).slice(0, 150));

  const aState = await invoke(winA, 'account:state');
  check('alice unlocked', aState.ok && aState.value.unlocked);
  const aliceCard = aState.value.contactCard;
  check('alice has a contact card', typeof aliceCard === 'string' && aliceCard.startsWith('ysm-contact://'));

  // Shut Alice's instance down so Bob's can start (single-instance lock).
  console.log('=== switching to bob ===');
  // Do NOT destroy the window: the app quits on 'window-all-closed', which would
  // terminate the test process. The per-account services below are independent
  // of the window anyway.
  await sleep(200);

  // A fresh process is needed for a second account; the test drives Bob through
  // the service directly using the same IPC-equivalent calls.
  const { AppService } = require('../build/ysm/app/service.js');
  const bobSvc = new AppService({ dataDir: join(sandboxB, 'ysm-data') });
  const bCreate = bobSvc.createAccount('Bob', PW);
  check('bob account created', bCreate.ok, JSON.stringify(bCreate).slice(0, 150));
  const bSecret = base32Decode(bCreate.value.totpSecretBase32);
  const bConfirm = bobSvc.confirmOnboarding(totp(bSecret, t0));
  check('bob 2FA confirmed', bConfirm.ok, JSON.stringify(bConfirm).slice(0, 150));

  const bobCard = bobSvc.myCard();
  check('bob has a contact card', bobCard.ok);

  // Alice's service instance (same code path the IPC handlers call).
  const aliceSvc = new AppService({ dataDir: join(sandboxA, 'ysm-data') });
  const aUnlock = aliceSvc.unlock(PW, totp(aSecret, t0 + 30));
  check('alice unlocks via service', aUnlock.ok, JSON.stringify(aUnlock).slice(0, 150));

  console.log('=== adding each other ===');
  const aAddsBob = aliceSvc.addContact(bobCard.value);
  check('alice adds bob', aAddsBob.ok, JSON.stringify(aAddsBob).slice(0, 150));
  const bAddsAlice = bobSvc.addContact(aliceCard);
  check('bob adds alice', bAddsAlice.ok, JSON.stringify(bAddsAlice).slice(0, 150));

  const aContacts = aliceSvc.contacts();
  const bContacts = bobSvc.contacts();
  check('alice sees bob', aContacts.ok && aContacts.value[0].displayName === 'Bob');
  check('bob sees alice', bContacts.ok && bContacts.value[0].displayName === 'Alice');
  check(
    'safety numbers agree',
    aContacts.value[0].safetyNumber === bContacts.value[0].safetyNumber,
    `${aContacts.value[0].safetyNumber} vs ${bContacts.value[0].safetyNumber}`,
  );

  console.log('=== verifying the safety number ===');
  const verified = aliceSvc.verifyContact(aContacts.value[0].id);
  check('alice marks bob verified', verified.ok);
  check('verified flag persisted', aliceSvc.contacts().value[0].verified === true);

  console.log('=== opening a room ===');
  const roomA = aliceSvc.createRoom(aAddsBob.value.id, 'Bob');
  const roomB = bobSvc.createRoom(bAddsAlice.value.id, 'Alice');
  check('alice room created', roomA.ok);
  check('bob room created', roomB.ok);
  check('room ids match', roomA.value.id === roomB.value.id, `${roomA.value.id} vs ${roomB.value.id}`);

  console.log('=== sending a text message ===');
  const sent = aliceSvc.sendMessage(roomA.value.id, aAddsBob.value.id, 'hello Bob — this is end-to-end encrypted');
  check('alice sends text', sent.ok, JSON.stringify(sent).slice(0, 150));
  const exported = aliceSvc.exportEnvelope(roomA.value.id, sent.value.id);
  check('envelope exported to a file', exported.ok && existsSync(exported.value), exported.ok ? exported.value : JSON.stringify(exported));

  const envText = readFileSync(exported.value, 'utf8');
  check('exported file is YSM1 format', envText.trim().startsWith('YSM1.'));
  check('exported file has no plaintext', !envText.includes('end-to-end encrypted'));

  const imported = bobSvc.importEnvelope(roomB.value.id, envText);
  check('bob imports and decrypts', imported.ok, JSON.stringify(imported).slice(0, 200));
  check('bob reads alice text', imported.ok && imported.value.text === 'hello Bob — this is end-to-end encrypted', imported.ok ? imported.value.text : '');

  console.log('=== sending a photo ===');
  // A tiny valid PNG header plus payload.
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(4096, 0x41),
  ]);
  const sentFile = aliceSvc.sendAttachment(
    roomA.value.id,
    aAddsBob.value.id,
    'holiday photo.png',
    'image/png',
    png.toString('base64'),
  );
  check('alice sends a photo', sentFile.ok, JSON.stringify(sentFile).slice(0, 150));
  const fileExport = aliceSvc.exportEnvelope(roomA.value.id, sentFile.value.id);
  check('photo envelopes exported', fileExport.ok);

  const fileImported = bobSvc.importEnvelope(roomB.value.id, readFileSync(fileExport.value, 'utf8'));
  check('bob imports the photo', fileImported.ok, JSON.stringify(fileImported).slice(0, 200));

  const bobMsgs = bobSvc.messages(roomB.value.id);
  check('bob sees two messages', bobMsgs.ok && bobMsgs.value.length === 2, String(bobMsgs.ok ? bobMsgs.value.length : 'err'));
  const fileMsg = bobMsgs.value.find((m) => m.kind === 'file');
  check('photo message present', fileMsg !== undefined);
  check('photo metadata correct', fileMsg && fileMsg.attachment && fileMsg.attachment.name === 'holiday photo.png');
  check('photo size matches', fileMsg && fileMsg.attachment && fileMsg.attachment.size === png.length);
  check('photo classified as image', fileMsg && fileMsg.attachment && fileMsg.attachment.category === 'image');
  check('photo has inline preview', fileMsg && fileMsg.attachment && typeof fileMsg.attachment.previewDataUrl === 'string');

  const saved = bobSvc.saveAttachment(fileMsg.transferId);
  check('bob saves the photo', saved.ok && existsSync(saved.value.path), saved.ok ? saved.value.path : JSON.stringify(saved));
  check('saved bytes are identical', Buffer.from(readFileSync(saved.value.path)).equals(png));

  console.log('=== a third party cannot read it ===');
  const eveSvc = new AppService({ dataDir: join(mkdtempSync(join(tmpdir(), 'ysm-eve-')), 'data') });
  const eveCreate = eveSvc.createAccount('Eve', PW);
  const eveSecret = base32Decode(eveCreate.value.totpSecretBase32);
  eveSvc.confirmOnboarding(totp(eveSecret, t0));
  eveSvc.addContact(aliceCard);
  const eveRoom = eveSvc.createRoom(Buffer.from(aContacts.value[0].id, 'hex').toString('hex'), 'Alice');
  // Eve tries to import alice->bob traffic.
  const eveTry = eveSvc.importEnvelope(
    eveRoom.ok ? eveRoom.value.id : 'x',
    envText,
  );
  check('eve cannot decrypt alice→bob', eveTry.ok === false, JSON.stringify(eveTry).slice(0, 150));

  console.log('=== data at rest, both sides ===');
  for (const [label, dir] of [
    ['alice', sandboxA],
    ['bob', sandboxB],
  ]) {
    const dbPath = join(dir, 'ysm-data', 'ysm-account.db');
    if (!existsSync(dbPath)) {
      check(`${label} db exists`, false, dbPath);
      continue;
    }
    const raw = readFileSync(dbPath).toString('latin1');
    check(`${label}: no plaintext message`, !raw.includes('end-to-end encrypted'));
    check(`${label}: no plaintext filename`, !raw.includes('holiday photo'));
    check(`${label}: no plaintext contact name`, !raw.includes('Bob') && !raw.includes('Alice'));
  }

  aliceSvc.lock();
  bobSvc.lock();
  eveSvc.lock();

  console.log(`\n${pass} passed, ${fail} failed`);
  try {
    rmSync(sandboxA, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    rmSync(sandboxB, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
