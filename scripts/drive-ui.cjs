/**
 * Drive the real UI and report exactly what happens at each step.
 *
 * Loads the real main process so the IPC handlers exist, then drives the actual
 * renderer controls. Prints the renderer's own error text and console output, so
 * a failure is explained rather than guessed at.
 */
const { app, BrowserWindow } = require('electron');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sandbox = mkdtempSync(join(tmpdir(), 'ysm-drive-'));
app.setPath('userData', sandbox);

// Load the real main process: it registers every IPC handler and creates the
// window. Without this the renderer loads but every call fails with
// "No handler registered".
require('../electron/main.mjs');

app.whenReady().then(async () => {
  await sleep(2500);
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) {
    console.log('FAIL: main process created no window');
    app.exit(1);
    return;
  }
  win.setContentSize(520, 900);
  win.show();
  await sleep(1000);

  win.webContents.on('preload-error', (_e, path, error) => {
    console.log(`  [preload-error] ${path}: ${error.message}`);
  });

  async function js(label, code) {
    try {
      const out = await win.webContents.executeJavaScript(code);
      console.log(`${label}: ${JSON.stringify(out)}`);
      return out;
    } catch (e) {
      console.log(`${label}: THREW — ${e.message}`);
      return null;
    }
  }

  console.log('--- initial ---');
  await js('active screen', `(document.querySelector('.screen.active')||{}).id`);

  console.log('--- navigate to create ---');
  await js('click', `(() => { document.getElementById('btn-go-create').click(); return true; })()`);
  await sleep(500);
  await js('active screen', `(document.querySelector('.screen.active')||{}).id`);

  console.log('--- fill and submit ---');
  await js('fill', `(() => {
    document.getElementById('create-name').value = 'Eiman';
    document.getElementById('create-password').value = 'correct horse battery staple';
    document.getElementById('create-password2').value = 'correct horse battery staple';
    return true;
  })()`);
  await js('submit', `(() => { document.getElementById('form-create').requestSubmit(); return true; })()`);
  await sleep(3000);

  await js('active screen', `(document.querySelector('.screen.active')||{}).id`);
  await js('create-error text', `(document.getElementById('create-error')||{}).textContent || '(none)'`);
  await js('create-error hidden', `(document.getElementById('create-error')||{}).hidden`);
  await js('qr canvas width', `(document.getElementById('qr-canvas')||{}).width`);
  await js('secret length', `((document.getElementById('totp-secret')||{}).textContent||'').trim().length`);

  // Verify the QR is actually painted, not just present.
  const painted = await js('qr dark pixels', `(() => {
    const c = document.getElementById('qr-canvas');
    if (!c || !c.width) return 0;
    const ctx = c.getContext('2d');
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    let dark = 0;
    for (let i = 0; i < d.length; i += 4) if (d[i] < 128) dark++;
    return dark;
  })()`);

  if (typeof painted === 'number' && painted > 100) {
    console.log(`RESULT: QR is painted (${painted} dark pixels)`);
  } else {
    console.log('RESULT: QR is NOT painted');
  }

  try {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}
  setTimeout(() => app.exit(0), 300);
});
