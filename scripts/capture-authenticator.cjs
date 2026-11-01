/**
 * Capture the full authenticator onboarding flow as screenshots.
 *
 * The user asked how to connect an authenticator app but had never been shown
 * the enrolment screen. This drives a real account creation against the real
 * service and captures each step, so the answer is a picture rather than a claim.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdirSync, writeFileSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');

const OUT = join(__dirname, '..', 'docs', 'screenshots');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sandbox = mkdtempSync(join(tmpdir(), 'ysm-shot-'));

app.whenReady().then(async () => {
  app.setPath('userData', sandbox);
  require('../electron/main.mjs');
  await sleep(2500);

  const win = BrowserWindow.getAllWindows()[0];
  if (!win) {
    console.log('FAIL no window');
    app.exit(1);
    return;
  }
  win.setContentSize(520, 900);
  win.show();
  await sleep(800);
  mkdirSync(OUT, { recursive: true });

  async function shot(name) {
    await sleep(500);
    const img = await win.webContents.capturePage();
    writeFileSync(join(OUT, `${name}.png`), img.toPNG());
    console.log(`captured ${name}.png`);
  }

  // Step 1: create the account through the real IPC path, which is what adds the
  // QR matrix (the service alone does not produce one — the encoder lives in the
  // main process).
  await win.webContents.executeJavaScript(`document.getElementById('btn-go-create').click()`);
  await sleep(400);
  await win.webContents.executeJavaScript(`(() => {
    document.getElementById('create-name').value = 'Eiman';
    document.getElementById('create-password').value = 'correct horse battery staple';
    document.getElementById('create-password2').value = 'correct horse battery staple';
  })()`);
  await sleep(200);
  await win.webContents.executeJavaScript(`document.getElementById('form-create').requestSubmit()`);
  await sleep(2000);

  // Read back what the app actually rendered.
  const rendered = await win.webContents.executeJavaScript(`(() => {
    const screen = document.getElementById('screen-onboard');
    const canvas = document.getElementById('qr-canvas');
    const secret = document.getElementById('totp-secret');
    let painted = false;
    if (canvas && canvas.width > 0) {
      const ctx = canvas.getContext('2d');
      const d = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
      let darkPixels = 0;
      for (let i = 0; i < d.length; i += 4) if (d[i] < 128) darkPixels++;
      painted = darkPixels > 100;
    }
    return {
      active: screen && screen.classList.contains('active'),
      canvasW: canvas ? canvas.width : 0,
      secretLength: secret ? secret.textContent.trim().length : 0,
      painted,
    };
  })()`);
  console.log('onboard screen active:', rendered.active);
  console.log('qr canvas:', rendered.canvasW, 'px, painted:', rendered.painted);
  console.log('base32 secret length:', rendered.secretLength);
  await sleep(300);
  await shot('10-authenticator-qr');

  // Step 3: compute the current code the way an authenticator app would, and
  // confirm enrolment. The secret is read from the screen, which is exactly what
  // the user copies into their app.
  const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
  const secretB32 = await win.webContents.executeJavaScript(
    `document.getElementById('totp-secret').textContent.trim()`,
  );
  const secret = base32Decode(secretB32);
  const code = totp(secret, Math.floor(Date.now() / 1000));
  console.log('generated code:', code);

  await win.webContents.executeJavaScript(`(() => {
    document.getElementById('onboard-code').value = ${JSON.stringify(code)};
  })()`);
  await sleep(200);
  await win.webContents.executeJavaScript(`document.getElementById('onboard-verify').click()`);
  await sleep(2000);

  const recoveryState = await win.webContents.executeJavaScript(`(() => {
    const screen = document.getElementById('screen-recovery');
    const items = document.querySelectorAll('#recovery-list li');
    return { active: screen && screen.classList.contains('active'), codes: items.length };
  })()`);
  console.log('recovery screen active:', recoveryState.active);
  console.log('recovery codes shown:', recoveryState.codes);

  // Step 4: the recovery codes screen the app itself navigated to.
  await shot('11-recovery-codes');

  // Step 5: the unlock screen, which is where the code is entered every time.
  await win.webContents.executeJavaScript(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-unlock').classList.add('active');
  })()`);
  await shot('12-unlock-with-code');

  try {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}
  setTimeout(() => app.exit(0), 200);
});
