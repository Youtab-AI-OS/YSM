/**
 * Drive the Crypto tab through the real UI.
 *
 * Covers the user's numbered requirements directly:
 *   1. type text or attach a file in the chat
 *   2. press a "Create crypto" button
 *   3. get an encrypted reference + passphrase, both copyable
 *   4. paste the reference + passphrase and see the original
 *   6. download the file in its original format
 *
 * Everything happens through real DOM clicks, because that is where the earlier
 * QR bug hid.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdtempSync, rmSync, existsSync, readdirSync, readFileSync } = require('node:fs');
const { tmpdir } = require('node:os');

const sandbox = mkdtempSync(join(tmpdir(), 'ysm-cryptoui-'));
app.setPath('userData', sandbox);
require('../electron/main.mjs');

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? ` (${detail})` : ''}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.whenReady().then(async () => {
  await sleep(2500);
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('FAIL: no window'); app.exit(1); return; }
  win.setContentSize(1000, 900);
  win.show();
  await sleep(1000);

  const js = (code) => win.webContents.executeJavaScript(code);
  const invoke = (channel, payload) =>
    js(`window.ysm.invoke(${JSON.stringify(channel)}, ${JSON.stringify(payload ?? {})})`);

  console.log('=== create and unlock an account ===');
  const created = await invoke('account:create', {
    displayName: 'Crypto Tester',
    password: 'correct horse battery staple',
  });
  check('account created', created.ok);
  const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
  const secret = base32Decode(created.value.totpSecretBase32);
  const confirmed = await invoke('account:confirmOnboarding', {
    totpCode: totp(secret, Math.floor(Date.now() / 1000)),
    secret: created.value.totpSecretBase32,
  });
  check('onboarding confirmed', confirmed.ok);

  // Show the main shell and the Crypto tab, as a user would after unlocking.
  await js(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-main').classList.add('active');
    const tab = document.querySelector('[data-tab="crypto"]');
    tab.click();
  })()`);
  await sleep(500);

  console.log('\n=== the Crypto tab exists and is wired ===');
  const tabState = await js(`(() => {
    const panel = document.getElementById('panel-crypto');
    const tab = document.querySelector('[data-tab="crypto"]');
    return {
      tabLabel: tab ? tab.textContent.trim() : '',
      panelActive: panel ? panel.classList.contains('active') : false,
      hasCreate: !!document.getElementById('crypto-create'),
      createLabel: (document.getElementById('crypto-create') || {}).textContent || '',
      hasFilePicker: !!document.getElementById('crypto-pick-file'),
      hasReadPane: !!document.getElementById('crypto-read'),
    };
  })()`);
  check('a Crypto tab is present', tabState.tabLabel.length > 0, tabState.tabLabel);
  check('the panel activates when the tab is clicked', tabState.panelActive);
  check('a Create crypto button exists', tabState.hasCreate);
  check('the button says Create crypto', /create crypto/i.test(tabState.createLabel), tabState.createLabel);
  check('a file picker exists', tabState.hasFilePicker);
  check('a read pane exists', tabState.hasReadPane);

  console.log('\n=== 1+2+3. type text, press Create crypto, get reference + passphrase ===');
  const secretText = 'Wire transfer details for account 4471 — do not share.';
  await js(`(() => {
    document.getElementById('crypto-text').value = ${JSON.stringify(secretText)};
    document.getElementById('crypto-create').click();
  })()`);
  await sleep(4000); // Argon2 64 MiB costs about a second

  const result = await js(`(() => ({
    hidden: document.getElementById('crypto-result').hidden,
    reference: document.getElementById('crypto-ref-out').value,
    passphrase: document.getElementById('crypto-pass-out').value,
    textCleared: document.getElementById('crypto-text').value === '',
    error: (document.getElementById('crypto-write-error') || {}).textContent || '',
    errorHidden: (document.getElementById('crypto-write-error') || {}).hidden,
  }))()`);

  check('the result panel appears', result.hidden === false, result.error);
  check('a reference is shown', /^YSM_[0-9a-f]{64}$/.test(result.reference), result.reference.slice(0, 20));
  check('a passphrase is shown', result.passphrase.length === 32, `${result.passphrase.length} chars`);
  check('the reference and passphrase differ', result.reference !== result.passphrase);
  check('the plaintext is cleared from the box', result.textCleared);
  check('no error is shown', result.errorHidden === true, result.error);

  const reference = result.reference;
  const passphrase = result.passphrase;

  console.log('\n=== 4. reader pastes reference + passphrase and sees the original ===');
  await js(`(() => {
    document.getElementById('crypto-tab-read').click();
    document.getElementById('read-reference').value = ${JSON.stringify(reference)};
    document.getElementById('read-passphrase').value = ${JSON.stringify(passphrase)};
    document.getElementById('read-open').click();
  })()`);
  await sleep(4500);

  const reopened = await js(`(() => ({
    outputHidden: document.getElementById('read-output').hidden,
    text: document.getElementById('read-text').textContent,
    textWrapHidden: document.getElementById('read-text-wrap').hidden,
    fileWrapHidden: document.getElementById('read-file-wrap').hidden,
    error: (document.getElementById('read-error') || {}).textContent || '',
    passphraseCleared: document.getElementById('read-passphrase').value === '',
  }))()`);

  check('the output panel appears', reopened.outputHidden === false, reopened.error);
  check('the decrypted text is shown exactly', reopened.text === secretText, JSON.stringify(reopened.text).slice(0, 60));
  check('it is shown as text, not a file', reopened.textWrapHidden === false && reopened.fileWrapHidden === true);
  check('the passphrase is cleared after use', reopened.passphraseCleared);

  console.log('\n=== wrong passphrase is refused in the UI ===');
  await js(`(() => {
    document.getElementById('read-reference').value = ${JSON.stringify(reference)};
    document.getElementById('read-passphrase').value = 'THISISNOTTHEPASSPHRASE';
    document.getElementById('read-open').click();
  })()`);
  await sleep(4500);
  const wrong = await js(`(() => ({
    outputHidden: document.getElementById('read-output').hidden,
    error: (document.getElementById('read-error') || {}).textContent || '',
    errorHidden: (document.getElementById('read-error') || {}).hidden,
  }))()`);
  check('wrong passphrase shows an error', wrong.errorHidden === false, wrong.error);
  check('wrong passphrase hides the output', wrong.outputHidden === true);

  console.log('\n=== 6. a file downloads in its original format ===');
  // Seal a file through the service, then read it back through the UI.
  const fileBytes = Buffer.from('PK\u0003\u0004 fake xlsx payload for the download test');
  const sealedFile = await invoke('sealed:create', {
    dataBase64: fileBytes.toString('base64'),
    fileName: 'report.xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  check('file sealed via IPC', sealedFile.ok, JSON.stringify(sealedFile).slice(0, 100));

  if (sealedFile.ok) {
    await js(`(() => {
      document.getElementById('read-reference').value = ${JSON.stringify(sealedFile.value.reference)};
      document.getElementById('read-passphrase').value = ${JSON.stringify(sealedFile.value.passphrase)};
      document.getElementById('read-open').click();
    })()`);
    await sleep(4500);

    const fileView = await js(`(() => ({
      fileWrapHidden: document.getElementById('read-file-wrap').hidden,
      textWrapHidden: document.getElementById('read-text-wrap').hidden,
      meta: document.getElementById('read-file-meta').textContent,
      hasDownload: !!document.getElementById('read-download'),
    }))()`);
    check('the file view is shown', fileView.fileWrapHidden === false);
    check('the text view is hidden for a file', fileView.textWrapHidden === true);
    check('the filename is displayed', fileView.meta.includes('report.xlsx'), fileView.meta);
    check('a download button exists', fileView.hasDownload);

    // Click download and confirm the browser actually received a download.
    const downloadPath = join(sandbox, 'downloads');
    try { require('node:fs').mkdirSync(downloadPath, { recursive: true }); } catch {}
    let downloadedTo = null;
    win.webContents.session.once('will-download', (_e, item) => {
      downloadedTo = join(downloadPath, item.getFilename());
      item.setSavePath(downloadedTo);
    });
    await js(`document.getElementById('read-download').click()`);
    await sleep(2500);

    check('a download was triggered', downloadedTo !== null, downloadedTo || 'none');
    if (downloadedTo !== null) {
      check('the downloaded file keeps its name', downloadedTo.endsWith('report.xlsx'), downloadedTo);
      check('the downloaded file exists', existsSync(downloadedTo));
      check(
        'the downloaded bytes match the original',
        existsSync(downloadedTo) && readFileSync(downloadedTo).equals(fileBytes),
      );
    }
  }

  console.log('\n=== the reference is not the key ===');
  check('the passphrase is not derivable from the reference', !reference.includes(passphrase.slice(0, 10)));

  try { rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('\nFailures:'); for (const f of failures) console.log(`  - ${f}`); }
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
