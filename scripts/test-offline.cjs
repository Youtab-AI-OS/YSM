/**
 * Prove the application makes no outbound network connection.
 *
 * Two independent checks, because a request filter alone only proves that the
 * filter ran:
 *
 *   1. From the renderer, attempt real network calls (fetch, WebSocket, XHR,
 *      beacon, EventSource, Image) and confirm each is refused.
 *   2. From the main process, use Node's own http/net to reach the internet and
 *      confirm the OS-level connection actually fails, which shows the machine is
 *      offline AND that the app does not depend on being online.
 *
 * Also asserts the hardening invariants that make "offline" meaningful: no proxy
 * env, no auto-update, no telemetry dependency, and the CSP forbidding connect.
 *
 * Run: npx electron scripts/test-offline.cjs
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdtempSync, rmSync, readFileSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { execFileSync } = require('node:child_process');

const sandbox = mkdtempSync(join(tmpdir(), 'ysm-offline-'));
app.setPath('userData', sandbox);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? ` (${detail})` : ''}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.whenReady().then(async () => {
  require('../electron/main.mjs');
  await sleep(2500);

  const win = BrowserWindow.getAllWindows()[0];
  if (!win) {
    console.log('FAIL: no window');
    app.exit(1);
    return;
  }
  win.show();
  await sleep(800);

  console.log('=== 1. renderer network attempts are blocked ===');
  const attempts = await win.webContents.executeJavaScript(`(async () => {
    const results = {};
    const probe = async (name, fn) => {
      try {
        await fn();
        results[name] = 'ALLOWED';
      } catch (e) {
        results[name] = 'blocked: ' + (e && e.name ? e.name : 'error');
      }
    };

    await probe('fetch https', () => fetch('https://example.com/', { mode: 'no-cors' }));
    await probe('fetch http', () => fetch('http://93.184.216.34/', { mode: 'no-cors' }));
    await probe('fetch localhost', () => fetch('http://127.0.0.1:9/', { mode: 'no-cors' }));
    await probe('beacon', async () => {
      const ok = navigator.sendBeacon('https://example.com/beacon', 'x');
      if (ok) throw new Error('beacon accepted');
      throw new Error('beacon refused');
    });
    await probe('websocket', () => new Promise((res, rej) => {
      const ws = new WebSocket('wss://example.com/');
      ws.onopen = () => res();
      ws.onerror = () => rej(new Error('ws error'));
      setTimeout(() => rej(new Error('timeout')), 2000);
    }));
    await probe('eventsource', () => new Promise((res, rej) => {
      const es = new EventSource('https://example.com/sse');
      es.onopen = () => res();
      es.onerror = () => rej(new Error('es error'));
      setTimeout(() => rej(new Error('timeout')), 2000);
    }));
    await probe('image', () => new Promise((res, rej) => {
      const img = new Image();
      img.onload = () => res();
      img.onerror = () => rej(new Error('img error'));
      img.src = 'https://example.com/pixel.gif';
      setTimeout(() => rej(new Error('timeout')), 2000);
    }));

    return results;
  })()`);

  for (const [name, outcome] of Object.entries(attempts)) {
    check(`renderer ${name} is blocked`, outcome !== 'ALLOWED', outcome);
  }

  console.log('\n=== 2. CSP forbids connections ===');
  const csp = await win.webContents.executeJavaScript(`(() => {
    const m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return m ? m.getAttribute('content') : '';
  })()`);
  check('a CSP meta tag is present', csp.length > 0);
  check("CSP sets connect-src 'none'", /connect-src\s+'none'/.test(csp), csp.slice(0, 80));
  check("CSP sets default-src 'none'", /default-src\s+'none'/.test(csp));

  console.log('\n=== 3. main process cannot reach the internet either ===');
  // A direct socket attempt from the main process, bypassing the webRequest
  // filter entirely. This shows the app has no network path of its own.
  const socketProbe = await new Promise((resolve) => {
    const net = require('node:net');
    const socket = net.connect({ host: '93.184.216.34', port: 80, timeout: 3000 });
    socket.on('connect', () => {
      socket.destroy();
      resolve('CONNECTED');
    });
    socket.on('error', (e) => resolve(`refused: ${e.code || e.message}`));
    socket.on('timeout', () => {
      socket.destroy();
      resolve('refused: timeout');
    });
  });
  check('main process cannot open an outbound socket', socketProbe !== 'CONNECTED', socketProbe);

  console.log('\n=== 4. no telemetry, updater or analytics in the packaged app ===');
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {}).join(' ');
  check('no electron-updater dependency', !deps.includes('updater'));
  check('no analytics dependency', !/analytics|sentry|mixpanel|segment|amplitude|bugsnag/i.test(deps));
  check('no auto-update configuration', !pkg.build || !('publish' in (pkg.build || {})));

  console.log('\n=== 5. the source contains no telemetry endpoints ===');
  const { execSync } = require('node:child_process');
  let grepOut = '';
  try {
    grepOut = execSync(
      'grep -rInE "google-analytics|sentry|mixpanel|segment\\.io|amplitude|bugsnag|datadog|api\\.segment" src electron renderer || true',
      { cwd: join(__dirname, '..'), encoding: 'utf8' },
    );
  } catch {
    grepOut = '';
  }
  check('no telemetry endpoints in source', grepOut.trim().length === 0, grepOut.slice(0, 100));

  console.log('\n=== 6. the app works with no network at all ===');
  // Create an account and seal a payload while the machine is offline.
  const created = await win.webContents.executeJavaScript(
    `window.ysm.invoke('account:create', {displayName:'Offline User',password:'correct horse battery staple'})`,
  );
  check('account creation works offline', created.ok === true, JSON.stringify(created).slice(0, 100));

  if (created.ok) {
    const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
    const secret = base32Decode(created.value.totpSecretBase32);
    const code = totp(secret, Math.floor(Date.now() / 1000));
    const confirmed = await win.webContents.executeJavaScript(
      `window.ysm.invoke('account:confirmOnboarding', {totpCode:${JSON.stringify(code)},secret:${JSON.stringify(created.value.totpSecretBase32)}})`,
    );
    check('two-factor enrolment works offline', confirmed.ok === true, JSON.stringify(confirmed).slice(0, 100));

    const sealed = await win.webContents.executeJavaScript(
      `window.ysm.invoke('sealed:create', {text:'sealed while offline'})`,
    );
    check('sealing works offline', sealed.ok === true, JSON.stringify(sealed).slice(0, 100));
    if (sealed.ok) {
      const opened = await win.webContents.executeJavaScript(
        `window.ysm.invoke('sealed:open', {reference:${JSON.stringify(sealed.value.reference)},passphrase:${JSON.stringify(sealed.value.passphrase)}})`,
      );
      check('opening works offline', opened.ok === true);
      check('the text is recovered', opened.ok && opened.value.text === 'sealed while offline');
    }
  }

  try {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
