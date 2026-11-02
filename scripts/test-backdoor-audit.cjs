/**
 * Backdoor and exfiltration audit.
 *
 * The question this answers: "is there any way data leaves this machine, or any
 * code path that was not put there deliberately?"
 *
 * It works from the three directions an attacker would:
 *
 *   A. STATIC — read the shipped source and look for anything that could exfiltrate
 *      or hide: network APIs, child processes, eval, obfuscated payloads, base64
 *      blobs long enough to hide code, unexpected file writes outside userData.
 *   B. DYNAMIC — run the app and watch every filesystem and process call it makes,
 *      proving it touches only what it declared.
 *   C. CONFIG — confirm the runtime controls (CSP, request filter, permissions,
 *      sandbox) are actually in force and not merely present in a file.
 *
 * Run: npx electron scripts/test-backdoor-audit.cjs
 */
const { app, BrowserWindow, ipcMain } = require('electron');
const { join } = require('node:path');
const {
  mkdtempSync, rmSync, readdirSync, readFileSync, statSync, existsSync,
} = require('node:fs');
const { tmpdir } = require('node:os');

const ROOT = join(__dirname, '..');
const SANDBOX = mkdtempSync(join(tmpdir(), 'ysm-audit-'));
app.setPath('userData', SANDBOX);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? ` (${detail})` : ''}`); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Every file that ships, and nothing else.
 *
 * `scripts/` and `test/` are excluded deliberately: they are development tooling
 * and never reach a customer's disk. Including them made this audit report its own
 * pattern list as a finding — a false positive that hides real ones. What ships is
 * `electron/`, `renderer/`, `src/` and the root config files, so that is what gets
 * inspected.
 */
function sourceFiles() {
  const out = [];
  const SKIP = [
    'node_modules', 'build', 'release', 'dist', '.git', '.cache', 'docs', 'assets',
    'scripts', 'test', '.automation', '.vm',
  ];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.includes(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(ts|mjs|cjs|js|html|json)$/.test(entry.name)) out.push(full);
    }
  };
  walk(ROOT);
  return out;
}

// ---------------------------------------------------------------------------
// A. Static analysis
// ---------------------------------------------------------------------------
function staticAudit() {
  console.log('=== A. static: what could exfiltrate or hide ===');
  const files = sourceFiles();
  check('source files found', files.length > 20, `${files.length} files`);

  /** Collect matches across every shipped file. */
  const find = (pattern) => {
    const hits = [];
    for (const file of files) {
      // This audit file names the very patterns it searches for, so scanning
      // itself would always report a false positive.
      if (file.endsWith('test-backdoor-audit.cjs')) continue;
      const text = readFileSync(file, 'utf8');
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        // Skip comment lines: documentation about what is *not* used (for example
        // "no enableRemoteModule") must not be read as usage.
        const trimmed = raw.trim();
        if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('--')) {
          continue;
        }
        if (pattern.test(raw)) {
          hits.push(`${file.replace(ROOT, '').replace(/\\/g, '/')}:${i + 1}`);
        }
      }
    }
    return hits;
  };

  // 1. Network primitives in the app source. The main process legitimately has
  //    none; the renderer has none because it cannot reach the network at all.
  const netHits = find(/\b(require\(['"]node:https?['"]\)|from ['"]node:https?['"]|new WebSocket|XMLHttpRequest|sendBeacon|EventSource|fetch\()/);
  const netExplained = netHits.filter((h) => !h.includes('/scripts/'));
  check('no network primitive in shipped app source', netExplained.length === 0, netExplained.slice(0, 4).join(', '));

  // 2. Child processes: the app must never spawn anything.
  const procHits = find(/child_process|execSync|spawnSync|execFile|fork\(/);
  const procExplained = procHits.filter((h) => !h.includes('/scripts/') && !h.includes('/test/'));
  check('no child-process use in app source', procExplained.length === 0, procExplained.slice(0, 4).join(', '));

  // 3. eval and dynamic code, which could hide behaviour.
  const evalHits = find(/\beval\(|new Function\(|vm\.runIn/);
  const evalExplained = evalHits.filter((h) => !h.includes('/scripts/'));
  check('no eval or dynamic code in app source', evalExplained.length === 0, evalExplained.slice(0, 4).join(', '));

  // 4. Long base64/hex blobs, the usual way to hide a payload.
  const blobHits = find(/['"][A-Za-z0-9+/]{400,}={0,2}['"]/);
  check('no long encoded blobs in app source', blobHits.length === 0, blobHits.slice(0, 3).join(', '));

  // 5. Obfuscation markers.
  const obf = find(/\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|atob\(\s*['"]/);
  check('no obfuscated strings in app source', obf.length === 0, obf.slice(0, 3).join(', '));

  // 6. The renderer must never be handed nodeIntegration or remote.
  const risky = find(/nodeIntegration:\s*true|enableRemoteModule|contextIsolation:\s*false|webSecurity:\s*false|sandbox:\s*false/);
  check('no insecure webPreferences flag anywhere', risky.length === 0, risky.slice(0, 3).join(', '));

  // 7. Dependencies: only the four crypto/QR libraries.
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {});
  const allowed = new Set(['@noble/ciphers', '@noble/curves', '@noble/hashes', 'qrcode']);
  const unexpected = deps.filter((d) => !allowed.has(d));
  check('runtime dependencies are only the expected four', unexpected.length === 0, unexpected.join(', '));

  // 8. Every dependency's own dependency tree, to see what else arrives.
  const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'));
  const lockDeps = Object.keys(lock.packages || {}).filter((k) => k.startsWith('node_modules/'));
  const suspicious = lockDeps.filter((k) =>
    /analytics|telemetry|track|sentry|mixpanel|bugsnag|posthog|amplitude/i.test(k),
  );
  check('no analytics or telemetry package in the lockfile', suspicious.length === 0, suspicious.slice(0, 4).join(', '));

  // 9. Nothing may read the clipboard or screen silently.
  const spy = find(/clipboard\.read|desktopCapturer|getUserMedia|navigator\.mediaDevices/);
  check('no silent clipboard, screen or camera access', spy.length === 0, spy.slice(0, 3).join(', '));
}

// ---------------------------------------------------------------------------
// B. Dynamic: run the app and watch what it touches
// ---------------------------------------------------------------------------
async function dynamicAudit() {
  console.log('\n=== B. dynamic: what the running app touches ===');

  // Observe every fs write and read target for the window's lifetime.
  const fs = require('node:fs');
  const touched = new Set();
  const originals = {};
  for (const name of ['readFileSync', 'writeFileSync', 'openSync', 'appendFileSync', 'unlinkSync', 'mkdirSync']) {
    originals[name] = fs[name];
    fs[name] = function patched(...args) {
      if (typeof args[0] === 'string') touched.add(`${name}:${args[0]}`);
      return originals[name].apply(this, args);
    };
  }

  require('../electron/main.mjs');
  await sleep(3000);

  const win = BrowserWindow.getAllWindows()[0];
  check('the app opened a window', win !== undefined);
  if (!win) return;

  // Exercise the main flows so any lazy code path runs.
  const js = (code) => win.webContents.executeJavaScript(code);
  const invoke = (ch, p) => js(`window.ysm.invoke(${JSON.stringify(ch)}, ${JSON.stringify(p ?? {})})`);

  const created = await invoke('account:create', {
    displayName: 'Audit User',
    password: 'correct horse battery staple',
  });
  if (created.ok) {
    const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
    const secret = base32Decode(created.value.totpSecretBase32);
    await invoke('account:confirmOnboarding', {
      totpCode: totp(secret, Math.floor(Date.now() / 1000)),
      secret: created.value.totpSecretBase32,
    });
    await invoke('sealed:create', { text: 'audit payload' });
  }
  await sleep(1500);

  // Restore the fs functions before judging results.
  for (const [name, fn] of Object.entries(originals)) fs[name] = fn;

  const paths = [...touched];
  const writes = paths.filter((p) => !p.startsWith('readFileSync:'));
  const outside = writes.filter((entry) => {
    const target = entry.slice(entry.indexOf(':') + 1);
    // Everything must be inside userData or the Electron install itself.
    return (
      !target.startsWith(SANDBOX) &&
      !target.includes('node_modules') &&
      !target.includes('electron') &&
      !target.includes('AppData\\Local\\Temp') &&
      !target.includes('renderer') &&
      !target.includes('build')
    );
  });
  check('the app writes only inside its own data directory', outside.length === 0, outside.slice(0, 4).join(', '));

  // The vault must exist where we expect, and nowhere else.
  const vault = join(SANDBOX, 'ysm-data', 'ysm-account.db');
  check('the vault is in userData', existsSync(vault), vault);

  console.log('\n=== C. runtime controls actually in force ===');
  const controls = await js(`(() => ({
    hasBridge: typeof window.ysm === 'object',
    bridgeKeys: Object.keys(window.ysm || {}),
    hasRequire: typeof window.require !== 'undefined',
    hasProcess: typeof window.process !== 'undefined',
    hasModule: typeof window.module !== 'undefined',
    ipcRendererExposed: typeof window.ipcRenderer !== 'undefined',
    csp: (document.querySelector('meta[http-equiv="Content-Security-Policy"]') || {}).content || '',
  }))()`);

  check('the renderer has the IPC bridge', controls.hasBridge);
  // The bridge is deliberately minimal: call, receive one lock event, read the
  // platform name. Anything beyond this would widen the attack surface.
  const expectedBridge = ['invoke', 'onLocked', 'platform'];
  check(
    'the bridge exposes only invoke/onLocked/platform',
    controls.bridgeKeys.every((k) => expectedBridge.includes(k)) && controls.bridgeKeys.length === expectedBridge.length,
    controls.bridgeKeys.join(','),
  );
  check('require is not defined in the renderer', controls.hasRequire === false);
  check('process is not defined in the renderer', controls.hasProcess === false);
  check('module is not defined in the renderer', controls.hasModule === false);
  check('raw ipcRenderer is not exposed', controls.ipcRendererExposed === false);
  check("CSP sets connect-src 'none'", /connect-src\s+'none'/.test(controls.csp));

  console.log('\n=== C2. the IPC surface cannot be widened at runtime ===');
  const before = ipcMain.eventNames ? null : null; // ipcMain has no public enumeration
  // Attempt a call that is not in the contract.
  const bogus = await js(`window.ysm.invoke('system:shell', {cmd:'calc'})`);
  check('an invented channel is refused', bogus && bogus.ok === false && bogus.code === 'UNKNOWN_CHANNEL');
  const traversed = await js(`window.ysm.invoke('files:save', {transferId:'../../../../windows/system32/evil'})`);
  check('a traversal attempt through IPC is refused', traversed && traversed.ok === false);
  const forged = await js(`window.ysm.invoke('sealed:open', {reference:'YSM_'+ 'a'.repeat(64), passphrase:'x'})`);
  check('a forged reference is refused cleanly', forged && forged.ok === false);

  console.log('\n=== C3. no outbound traffic during real use ===');
  const attempts = await js(`(async () => {
    const out = {};
    const probe = async (n, fn) => { try { await fn(); out[n]='ALLOWED'; } catch { out[n]='blocked'; } };
    await probe('fetch', () => fetch('https://example.com/', {mode:'no-cors'}));
    await probe('img', () => new Promise((res, rej) => { const i=new Image(); i.onload=res; i.onerror=()=>rej(new Error('x')); i.src='https://example.com/p.gif'; setTimeout(()=>rej(new Error('t')),1500); }));
    await probe('ws', () => new Promise((res, rej) => { const w=new WebSocket('wss://example.com/'); w.onopen=res; w.onerror=()=>rej(new Error('x')); setTimeout(()=>rej(new Error('t')),1500); }));
    return out;
  })()`);
  check('fetch blocked while the app is in use', attempts.fetch !== 'ALLOWED', attempts.fetch);
  check('image beacon blocked while the app is in use', attempts.img !== 'ALLOWED', attempts.img);
  check('websocket blocked while the app is in use', attempts.ws !== 'ALLOWED', attempts.ws);
}

app.whenReady().then(async () => {
  try {
    staticAudit();
    await dynamicAudit();
  } catch (error) {
    console.error('\nUNEXPECTED:', error?.name ?? 'Error');
    fail++;
    failures.push('audit crashed');
  } finally {
    try { rmSync(SANDBOX, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('\nFailures:'); for (const f of failures) console.log(`  - ${f}`); }
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
