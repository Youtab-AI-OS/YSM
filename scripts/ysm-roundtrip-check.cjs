/**
 * Round-trip proof script, to be run on a clean machine.
 *
 * This is the automated half of docs/CLEAN-MACHINE-VERIFICATION.md. It exercises
 * the installed application's own IPC surface — the same one the UI uses — so a
 * pass means the real code path works on this machine.
 *
 * It does not need an account: the sealed-reference flow is independent of the
 * vault, which is the point being tested (a reference plus passphrase must open on
 * any machine).
 *
 * Run:  node ysm-roundtrip-check.cjs .
 *
 * Reads: nothing. Writes: a report file beside itself.
 */
const { app } = require('electron');
const { join, dirname } = require('node:path');
const { writeFileSync } = require('node:fs');
const { createRequire } = require('node:module');

const APP_DIR = require('node:path').resolve(process.argv[2] || '.');
const report = [];
let pass = 0;
let fail = 0;

function check(name, ok, detail = '') {
  if (ok) {
    pass++;
    report.push(`PASS  ${name}`);
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    report.push(`FAIL  ${name}  ${detail}`);
    console.log(`  FAIL ${name}  ${detail}`);
  }
}

app.whenReady().then(async () => {
  // Load the installed app's own service implementation.
  const req = createRequire(join(APP_DIR, 'package.json'));
  const servicePath = join(APP_DIR, 'build', 'ysm', 'app', 'service.js');
  const { AppService } = req(servicePath);

  const os = require('node:os');
  const { mkdtempSync, rmSync } = require('node:fs');
  const dataDir = mkdtempSync(join(os.tmpdir(), 'ysm-proof-'));

  // The sealed flow does not need an unlocked vault, but the service requires a
  // constructed instance.
  const svc = new AppService({ dataDir });

  console.log('=== text round trip ===');
  const secretText = 'سلام، این پیام آزمایشی است. مبلغ ۱۲۳۴۵ تومان — report.xlsx';
  const sealedText = svc.sealPayload({ text: secretText });
  check('text sealed', sealedText && sealedText.ok === true, JSON.stringify(sealedText).slice(0, 120));

  if (sealedText && sealedText.ok) {
    check(
      'reference has the documented shape',
      /^YSM_[0-9a-f]{64}$/.test(sealedText.value.reference),
      sealedText.value.reference.slice(0, 20),
    );
    check('passphrase is 32 characters', sealedText.value.passphrase.length === 32, `${sealedText.value.passphrase.length}`);

    const opened = svc.openSealed({
      reference: sealedText.value.reference,
      passphrase: sealedText.value.passphrase,
    });
    check('text reopens', opened && opened.ok === true, JSON.stringify(opened).slice(0, 120));
    if (opened && opened.ok) {
      check('text is byte-identical', opened.value.text === secretText, JSON.stringify(opened.value.text || '').slice(0, 60));
      check('Persian comma survives', (opened.value.text || '').includes('،'));
      check('Persian digits survive', (opened.value.text || '').includes('۱۲۳۴۵'));
    }

    console.log('=== wrong passphrase is refused ===');
    const wrong = svc.openSealed({
      reference: sealedText.value.reference,
      passphrase: 'THISISWRONGTHISISWRONGTHISISWRON',
    });
    check('wrong passphrase refused', wrong && wrong.ok === false, JSON.stringify(wrong).slice(0, 100));

    console.log('=== tampered reference is refused ===');
    const tampered = sealedText.value.reference.slice(0, -1) + (sealedText.value.reference.endsWith('0') ? '1' : '0');
    const tamperedResult = svc.openSealed({ reference: tampered, passphrase: sealedText.value.passphrase });
    check('tampered reference refused', tamperedResult && tamperedResult.ok === false);
  }

  console.log('=== file round trip ===');
  // A small binary with a known checksum, and a filename with an extension.
  const bytes = Buffer.from([0x50, 0x4b, 0x03, 0x04, ...Array.from({ length: 4096 }, (_, i) => i & 0xff)]);
  const sealedFile = svc.sealPayload({
    dataBase64: bytes.toString('base64'),
    fileName: 'report.xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  check('file sealed', sealedFile && sealedFile.ok === true, JSON.stringify(sealedFile).slice(0, 120));

  if (sealedFile && sealedFile.ok) {
    const openedFile = svc.openSealed({
      reference: sealedFile.value.reference,
      passphrase: sealedFile.value.passphrase,
    });
    check('file reopens', openedFile && openedFile.ok === true);
    if (openedFile && openedFile.ok) {
      check('file name preserved', openedFile.value.fileName === 'report.xlsx', openedFile.value.fileName);
      check('MIME type preserved', /spreadsheetml/.test(openedFile.value.mimeType || ''), openedFile.value.mimeType);
      const returned = Buffer.from(openedFile.value.dataBase64, 'base64');
      check('file bytes identical', returned.equals(bytes), `${returned.length} vs ${bytes.length} bytes`);
    }
  }

  console.log('=== the reference alone is useless ===');
  if (sealedText && sealedText.ok) {
    const noPass = svc.openSealed({ reference: sealedText.value.reference, passphrase: '' });
    check('an empty passphrase is refused', noPass && noPass.ok === false);
    check(
      'the passphrase is not embedded in the reference',
      !sealedText.value.reference.includes(sealedText.value.passphrase.slice(0, 8)),
    );
  }

  try {
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}

  const summary = [
    'YSM clean-machine round-trip report',
    `date: ${new Date().toISOString()}`,
    `machine: ${os.hostname()}`,
    `platform: ${os.platform()} ${os.release()}`,
    `app dir: ${APP_DIR}`,
    '',
    ...report,
    '',
    `${pass} passed, ${fail} failed`,
  ].join('\r\n');

  const outPath = join(dirname(process.execPath), 'ysm-roundtrip-report.txt');
  try { writeFileSync(outPath, summary, 'utf8'); } catch {}

  console.log(`\n${pass} passed, ${fail} failed`);
  console.log(`report: ${outPath}`);
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
