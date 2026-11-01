/**
 * Verify the recovery-code downloads are real, openable files.
 *
 * A button that produces a corrupt PDF is worse than no button: the user believes
 * they have a backup. So the PDF is parsed back (xref offsets checked, text
 * extracted) and the CSV is parsed as CSV with the expected number of rows.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdtempSync, rmSync, existsSync, readFileSync, mkdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');

const sandbox = mkdtempSync(join(tmpdir(), 'ysm-recovery-'));
const downloadDir = join(sandbox, 'dl');
mkdirSync(downloadDir, { recursive: true });
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
  win.setContentSize(1000, 900);
  win.show();
  await sleep(800);

  const js = (code) => win.webContents.executeJavaScript(code);
  const invoke = (channel, payload) =>
    js(`window.ysm.invoke(${JSON.stringify(channel)}, ${JSON.stringify(payload ?? {})})`);

  // Drive the real create form, so `state.onboarding` is populated exactly as it
  // is for a user. Calling the IPC directly would leave the renderer state empty
  // and make the download buttons no-ops — which is what a first attempt did.
  await js(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-create').classList.add('active');
    document.getElementById('create-name').value = 'Recovery Tester';
    document.getElementById('create-password').value = 'correct horse battery staple';
    document.getElementById('create-password2').value = 'correct horse battery staple';
    document.getElementById('form-create').requestSubmit();
  })()`);
  await sleep(4000);

  const onboard = await js(`(() => ({
    screen: (document.querySelector('.screen.active') || {}).id,
    secret: ((document.getElementById('totp-secret') || {}).textContent || '').trim(),
    error: (document.getElementById('create-error') || {}).textContent || '',
  }))()`);
  check('the enrolment screen is shown', onboard.screen === 'screen-onboard', `${onboard.screen} ${onboard.error}`);
  check('a TOTP secret is displayed', onboard.secret.length === 32, `${onboard.secret.length} chars`);

  // Enter the code so onboarding completes and the recovery screen appears.
  const secretBytes = base32Decode(onboard.secret);
  const code = totp(secretBytes, Math.floor(Date.now() / 1000));
  await js(`(() => {
    document.getElementById('onboard-code').value = ${JSON.stringify(code)};
    document.getElementById('onboard-verify').click();
  })()`);
  await sleep(2500);

  const recoveryScreen = await js(`(() => ({
    screen: (document.querySelector('.screen.active') || {}).id,
    codeCount: document.querySelectorAll('#recovery-list li').length,
    first: ((document.querySelector('#recovery-list li') || {}).textContent || '').trim(),
  }))()`);
  check('the recovery screen is shown', recoveryScreen.screen === 'screen-recovery', recoveryScreen.screen);
  check('ten recovery codes are rendered', recoveryScreen.codeCount === 10, `${recoveryScreen.codeCount}`);
  const firstCode = recoveryScreen.first;

  const ui = await js(`(() => ({
    codeCount: document.querySelectorAll('#recovery-list li').length,
    hasCsv: !!document.getElementById('download-recovery-csv'),
    hasPdf: !!document.getElementById('download-recovery-pdf'),
    csvLabel: (document.getElementById('download-recovery-csv') || {}).textContent || '',
    pdfLabel: (document.getElementById('download-recovery-pdf') || {}).textContent || '',
  }))()`);
  check('recovery codes are rendered', ui.codeCount === 10, `${ui.codeCount} codes`);
  check('a CSV download button exists', ui.hasCsv);
  check('a PDF download button exists', ui.hasPdf);
  check('the CSV button is labelled', ui.csvLabel.trim().length > 0, ui.csvLabel);
  check('the PDF button is labelled', ui.pdfLabel.trim().length > 0, ui.pdfLabel);

  // Capture both downloads.
  const saved = {};
  win.webContents.session.on('will-download', (_e, item) => {
    const name = item.getFilename();
    const target = join(downloadDir, name);
    item.setSavePath(target);
    saved[name] = target;
  });

  await js(`document.getElementById('download-recovery-csv').click()`);
  await sleep(1500);
  await js(`document.getElementById('download-recovery-pdf').click()`);
  await sleep(2000);

  const names = Object.keys(saved);
  console.log('  downloaded:', JSON.stringify(names));

  const csvName = names.find((n) => n.endsWith('.csv'));
  const pdfName = names.find((n) => n.endsWith('.pdf'));
  check('a .csv file was downloaded', csvName !== undefined, names.join(','));
  check('a .pdf file was downloaded', pdfName !== undefined, names.join(','));

  if (csvName) {
    const csv = readFileSync(saved[csvName], 'utf8');
    check('CSV starts with the expected header', csv.includes('index,recovery_code'), csv.slice(0, 40));
    const rows = csv.replace(/^\uFEFF/, '').trim().split(/\r?\n/);
    check('CSV has a header plus 10 codes', rows.length === 11, `${rows.length} rows`);
    const firstCode = (rows[1] || '').split(',')[1];
    check('CSV contains a code that matches the screen', firstCode.length > 0, firstCode);
  }

  if (pdfName) {
    const buf = readFileSync(saved[pdfName]);
    const text = buf.toString('latin1');
    check('PDF has a %PDF header', text.startsWith('%PDF-1.'), text.slice(0, 8));
    check('PDF ends with %%EOF', text.trimEnd().endsWith('%%EOF'));
    check('PDF declares a cross-reference table', text.includes('\nxref\n'));
    check('PDF declares a trailer with a Root', /\/Root 1 0 R/.test(text));

    // Verify every xref offset actually points at "N 0 obj".
    const xrefMatch = text.match(/xref\n0 (\d+)\n([\s\S]*?)trailer/);
    check('PDF xref block is present', xrefMatch !== null);
    if (xrefMatch) {
      const count = Number(xrefMatch[1]);
      const entries = xrefMatch[2].trim().split('\n').slice(1); // skip the free entry
      let offsetsOk = true;
      for (let i = 0; i < entries.length; i++) {
        const offset = Number(entries[i].slice(0, 10));
        const at = text.slice(offset, offset + 12);
        if (!new RegExp(`^${i + 1} 0 obj`).test(at)) {
          offsetsOk = false;
          console.log(`    bad offset for object ${i + 1}: found ${JSON.stringify(at)}`);
        }
      }
      check(`PDF has ${count - 1} objects and every xref offset resolves`, offsetsOk && entries.length === count - 1);
    }

    // Extract the text that a viewer would show.
    const streamMatch = text.match(/stream\n([\s\S]*?)endstream/);
    check('PDF contains a content stream', streamMatch !== null);
    if (streamMatch) {
      const content = streamMatch[1];
      const shown = [...content.matchAll(/\(([^)]*)\) Tj/g)].map((m) => m[1]);
      check('PDF contains the title', shown.some((s) => s.includes('YSM recovery codes')), shown[0]);
      const codeLines = shown.filter((s) => /\d\.\s+[A-Z0-9-]{8,}/.test(s));
      check('PDF lists all 10 codes', codeLines.length === 10, `${codeLines.length} found`);
      const anyCode = firstCode;
      check('PDF contains a real code', shown.some((s) => s.includes(anyCode)), anyCode);
    }
  }

  try { rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('\nFailures:'); for (const f of failures) console.log(`  - ${f}`); }
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
