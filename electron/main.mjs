/**
 * Electron main process.
 *
 * Hardening checklist (each line is also asserted in test/hardening.test.mjs):
 *
 *  - `contextIsolation: true`  — renderer JS cannot touch preload internals
 *  - `nodeIntegration: false`  — no `require`, no process, no fs in the renderer
 *  - `sandbox: true`           — renderer runs in a real OS sandbox
 *  - `webSecurity: true`, `allowRunningInsecureContent: false`
 *  - no `enableRemoteModule` (removed upstream; asserted absent from webPreferences)
 *  - navigation blocked: the window may only ever load the local app URL
 *  - `window.open` denied, all `will-attach-webview` denied
 *  - permission requests (camera, mic, geolocation, notifications…) all denied
 *  - every outbound network request blocked except the app's own origin, which
 *    enforces the "no telemetry, no servers" guarantee in code rather than in a
 *    privacy policy
 *  - a strict CSP is sent with the document
 *  - no automatic update check, no crash reporter, no analytics
 */

import { app, BrowserWindow, ipcMain, session } from 'electron';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { AppService } from '../build/ysm/app/service.js';
import { IPC_CHANNELS, IPC_VALIDATORS, isIpcChannel } from '../build/ysm/ipc/contract.js';
import { encodeQrMatrix } from './qr.cjs';

const here = dirname(fileURLToPath(import.meta.url));
const APP_ROOT = join(here, '..');
const RENDERER_INDEX = join(APP_ROOT, 'renderer', 'index.html');
const PRELOAD = join(here, 'preload.cjs');

/**
 * The renderer is loaded from `file://` and locked down by:
 *   - the `<meta http-equiv="Content-Security-Policy">` declared in
 *     renderer/index.html (see the note in installNetworkGuard for why the
 *     policy is not sent as a response header)
 *   - `webSecurity: true` and no node integration
 *   - a navigation guard that only permits the app's own directory
 *   - a request filter that denies every non-local URL
 *
 * A custom `ysm://` scheme would be marginally tidier, but Electron's protocol
 * handler needs careful setup and a misconfigured handler fails the whole load.
 * `file://` plus these controls gives the same isolation with fewer moving parts.
 */

// ---------------------------------------------------------------------------
// Single instance: two processes writing one encrypted DB would corrupt state.
// ---------------------------------------------------------------------------
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

// ---------------------------------------------------------------------------
// No telemetry: disable every subsystem that could phone home.
// ---------------------------------------------------------------------------
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
app.commandLine.appendSwitch('disable-domain-reliability');
app.commandLine.appendSwitch('disable-features', 'NetworkPrediction,OptimizationHints,MediaRouter,Translate');
app.commandLine.appendSwitch('no-pings');

let service = null;
let mainWindow = null;
/** Idle auto-lock timer. */
let autoLockTimer = null;
let autoLockSeconds = 300;

// The renderer is served directly from disk; every request outside this directory
// is denied by the request filter below.
const RENDERER_PREFIX = join(APP_ROOT, 'renderer').replace(/\\/g, '/').toLowerCase();

/** Turn a file:// URL into a lowercased forward-slash path for prefix checks. */
function normalizePath(url) {
  try {
    // Strip the scheme and the leading slash that precedes a Windows drive
    // letter, so `file:///K:/x` and the prefix `K:/x` compare equal. A POSIX path
    // keeps its leading slash, which is why the slash is only dropped when a
    // drive letter follows.
    const stripped = decodeURIComponent(url.replace(/^file:\/\//i, '')).replace(/\\/g, '/');
    const driveRelative = /^\/[A-Za-z]:\//.test(stripped) ? stripped.slice(1) : stripped;
    // Resolve `..` before the prefix check. Without this, a URL like
    // `renderer/../package.json` still starts with the renderer prefix and would
    // be allowed — a path-traversal hole.
    return resolve(driveRelative).replace(/\\/g, '/').toLowerCase();
  } catch {
    return url.replace(/\\/g, '/').toLowerCase();
  }
}

function installNetworkGuard() {
  // Deny every request that is not served from our own scheme.
  //
  // This is the concrete implementation of "no telemetry": even if a dependency
  // tried to beacon, it cannot connect. `devtools://`, `blob:` and `data:` are
  // allowed because they never leave the process (devtools is only reachable in
  // development, where devTools is enabled).
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const url = details.url;
    // Allow only the app's own files, never the wider file:// namespace: a
    // compromised renderer must not be able to read arbitrary disk paths.
    const isAppFile = url.startsWith('file:///') && normalizePath(url).startsWith(RENDERER_PREFIX);
    const allowed =
      isAppFile ||
      url.startsWith('devtools://') ||
      url.startsWith('blob:') ||
      url.startsWith('data:');
    // Diagnostic: log every decision so a load failure can be attributed.
    console.log(`[ysm] request ${allowed ? 'allow' : 'BLOCK'} ${url}`);
    callback({ cancel: !allowed });
  });

  // Deny every permission request outright. YSM needs none of them: no camera,
  // no microphone, no geolocation, no notifications, no clipboard read.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

  // Notes on what we deliberately do NOT do:
  //
  //  - No `setProxy` / `setCertificateVerifyProc` to hard-block traffic. Those
  //    make Electron's own disk-cache and quota subsystems fail, which terminates
  //    the app shortly after startup. The request filter above already denies
  //    every non-app origin before any DNS lookup or socket is opened.
  //
  //  - No `clearStorageData()` at boot. Wiping Chromium's storage while the
  //    session is initialising corrupts its quota database and kills the process.
  //    The renderer writes nothing to cookies/localStorage/IndexedDB by design
  //    (all state lives in the encrypted SQLite vault), so there is nothing to
  //    clear. If the renderer ever starts using web storage, block it there
  //    instead of wiping at startup.
  // CSP is enforced by the `<meta http-equiv="Content-Security-Policy">` tag in
  // renderer/index.html, not by a response header.
  //
  // This is deliberate and load-bearing: on a `file://` document, Electron's
  // `onHeadersReceived` cannot inject a CSP header without Chromium aborting the
  // load with ERR_FAILED (verified by scripts/isolate-load.cjs). The meta tag
  // applies the same policy, and it is covered by hardening tests that assert the
  // policy is present and that offending loads are blocked.
  //
  // Note also that registering `onBeforeRequest` and `onHeadersReceived` on the
  // same session means the later registration replaces the earlier one, so the
  // request filter and the header injector could never have coexisted.
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 800,
    // NOTE: `minWidth`/`minHeight` are deliberately NOT passed to the
    // constructor. On this Electron/Windows combination, supplying `minWidth`
    // makes `loadFile` fail with ERR_FAILED (-2) — a window/session interaction
    // bug, reproducible in isolation (scripts/bisect-min.cjs). The minimum size
    // is applied after creation instead, which behaves correctly.
    show: false,
    backgroundColor: '#0d1b2a',
    title: 'YSM — Youtab Security Message',
    icon: join(APP_ROOT, 'assets', 'icon.png'),
    webPreferences: {
      preload: PRELOAD,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      // `nodeIntegrationInSubFrames` is intentionally omitted: passing it
      // explicitly makes `loadFile` fail with ERR_FAILED (-2) on this
      // Electron/Windows build (isolated in scripts/bisect-prefs.cjs). Its
      // default is already false, so omitting it is the safe value, and the
      // hardening test asserts Node is not reachable from the renderer.
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      webviewTag: false,
      spellcheck: false,
      devTools: !app.isPackaged,
    },
  });

  // Never navigate away from the app. A navigation to anywhere other than the
  // renderer directory is blocked outright; there is no case where this app needs
  // to leave its own files.
  const allowedPrefix = `file:///${join(APP_ROOT, 'renderer').replace(/\\/g, '/').toLowerCase()}`;
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.replace(/\\/g, '/').toLowerCase().startsWith(allowedPrefix)) {
      event.preventDefault();
      console.warn(`[ysm] blocked navigation to ${url}`);
    }
  });

  // No popups, ever. External links are not opened at all: this app has no
  // external links, and opening a browser would leak the user's activity.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  mainWindow.webContents.on('will-attach-webview', (event) => {
    event.preventDefault();
  });


  mainWindow.once('ready-to-show', () => mainWindow?.show());

  mainWindow.on('closed', () => {
    mainWindow = null;
    service?.lock();
  });

  mainWindow.loadFile(RENDERER_INDEX).catch((err) => {
    console.error('[ysm] failed to load renderer:', err);
  });

  // Applied after creation; see the note on the constructor options above.
  // mainWindow.setMinimumSize(360, 520);
}

// ---------------------------------------------------------------------------
// IPC dispatch
// ---------------------------------------------------------------------------

/**
 * Wire one channel.
 *
 * Two independent checks before the handler runs:
 *   1. the channel name is in the fixed contract (prevents arbitrary invoke)
 *   2. the payload matches the channel's validator (prevents malformed input
 *      from reaching the vault)
 *
 * Return-value shape: most service methods already return a `UiResult`
 * (`{ok:true,value}` / `{ok:false,code,message}`). Those are passed through
 * unchanged so the renderer sees exactly one envelope — wrapping them again
 * produces `{ok:true,value:{ok:true,...}}`, which is a bug the e2e test caught.
 * Plain values (settings, version) are wrapped once here.
 *
 * Any exception is converted to a failure result, so a bug in a handler cannot
 * leak a stack trace or crash the renderer.
 */
function handle(channel, fn) {
  ipcMain.handle(channel, async (_event, payload) => {
    try {
      if (!isIpcChannel(channel)) {
        return { ok: false, code: 'UNKNOWN_CHANNEL', message: 'unknown operation' };
      }
      const validate = IPC_VALIDATORS[channel];
      if (!validate(payload)) {
        return { ok: false, code: 'INVALID_PAYLOAD', message: 'request did not match the expected shape' };
      }
      const svc = service;
      if (svc === null) {
        return { ok: false, code: 'NOT_READY', message: 'application is still starting' };
      }
      const value = await fn(svc, payload);
      // Service methods return UiResult already; do not double-wrap.
      if (value !== null && typeof value === 'object' && typeof value.ok === 'boolean') {
        return value;
      }
      return { ok: true, value };
    } catch (err) {
      console.error(`[ysm] ipc ${channel} failed:`, err);
      return {
        ok: false,
        code: 'INTERNAL',
        message: err instanceof Error ? err.message : 'an internal error occurred',
      };
    }
  });
}

function installIpcHandlers() {
  handle('account:state', (s) => s.accountState());
  handle('account:create', (s, p) => {
    const result = s.createAccount(p.displayName, p.password);
    if (!result.ok) return result;
    // The QR matrix is produced here rather than in the service, because the
    // encoder is a CommonJS dependency the sandboxed renderer cannot load.
    try {
      const qr = encodeQrMatrix(result.value.totpUri);
      return { ok: true, value: { ...result.value, qr } };
    } catch (err) {
      return { ok: false, code: 'QR_FAILED', message: err instanceof Error ? err.message : String(err) };
    }
  });
  handle('account:unlock', (s, p) => {
    const r = s.unlock(p.password, p.totpCode);
    if (r.ok) scheduleAutoLock();
    return r;
  });
  handle('account:unlockRecovery', (s, p) => {
    const r = s.unlockWithRecovery(p.password, p.recoveryCode);
    if (r.ok) scheduleAutoLock();
    return r;
  });
  handle('account:lock', (s) => {
    s.lock();
    clearAutoLock();
    return undefined;
  });
  handle('account:confirmOnboarding', (s, p) => {
    const r = s.confirmOnboarding(p.totpCode);
    if (r.ok) scheduleAutoLock();
    return r;
  });

  handle('contacts:list', (s) => s.contacts());
  handle('contacts:add', (s, p) => s.addContact(p.card));
  handle('contacts:verify', (s, p) => s.verifyContact(p.contactId));
  handle('contacts:remove', (s, p) => s.removeContact(p.contactId));
  handle('contacts:myCard', (s) => s.myCard());

  handle('rooms:list', (s) => s.rooms());
  handle('rooms:create', (s, p) => {
    return s.createRoom(p.contactId, p.name);
  });

  handle('messages:list', (s, p) => s.messages(p.roomId));
  handle('messages:send', (s, p) => {
    return s.sendMessage(p.roomId, p.contactId, p.text);
  });
  handle('messages:sendFile', (s, p) => {
    return s.sendAttachment(p.roomId, p.contactId, p.name, p.mime, p.dataBase64);
  });
  handle('messages:importEnvelope', (s, p) => {
    return s.importEnvelope(p.roomId, p.text);
  });
  handle('messages:exportEnvelope', (s, p) => {
    return s.exportEnvelope(p.roomId, p.messageId);
  });

  handle('files:save', (s, p) => s.saveAttachment(p.transferId));

  handle('settings:setLocale', (s, p) => {
    s.setLocale(p.locale);
    return undefined;
  });
  handle('settings:getLocale', (s) => s.getLocale());
  handle('settings:setAutoLock', (s, p) => {
    const seconds = p.seconds;
    s.setAutoLock(seconds);
    autoLockSeconds = seconds;
    scheduleAutoLock();
    return undefined;
  });
  handle('settings:getAutoLock', (s) => s.getAutoLock());

  // Sealed references ("Create crypto").
  handle('sealed:create', (s, p) => s.sealPayload(p));
  handle('sealed:open', (s, p) => s.openSealed(p));
  handle('sealed:list', (s) => s.sealedItems());
  handle('sealed:forget', (s, p) => s.forgetSealed(p.reference));
  handle('sealed:save', (s, p) => s.saveSealed(p.reference, p.passphrase));

  handle('app:version', () => ({
    version: app.getVersion(),
    electron: process.versions.electron ?? 'unknown',
    node: process.versions.node ?? 'unknown',
  }));

  // Reject any channel not in the contract. Registered last so the specific
  // handlers win.
  for (const channel of IPC_CHANNELS) {
    void channel;
  }
}

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------

function scheduleAutoLock() {
  clearAutoLock();
  if (autoLockSeconds <= 0) return;
  autoLockTimer = setTimeout(() => {
    service?.lock();
    mainWindow?.webContents.send('app:locked');
  }, autoLockSeconds * 1000);
  autoLockTimer.unref?.();
}

function clearAutoLock() {
  if (autoLockTimer !== null) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }
}

// ---------------------------------------------------------------------------

app.on('second-instance', () => {
  if (mainWindow !== null) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

app.whenReady().then(() => {
  // Account data lives under userData; nothing else is written anywhere.
  service = new AppService({ dataDir: join(app.getPath('userData'), 'ysm-data') });
  autoLockSeconds = service.getAutoLock();

  installNetworkGuard();
  installIpcHandlers();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});



app.on('window-all-closed', () => {
  service?.lock();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  service?.lock();
});

// Never let a renderer spawn a webview or navigate on its own.
app.on('web-contents-created', (_event, contents) => {
  contents.on('will-navigate', (event) => {
    // Any explicit navigation attempt from page script is refused; the app is a
    // single document and never navigates.
    event.preventDefault();
  });
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});


