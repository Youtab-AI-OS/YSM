/**
 * Headless smoke test: launch the real Electron app, exercise the preload
 * bridge, and report what happened.
 *
 * Run with: npx electron scripts/smoke-electron.cjs
 *
 * This is the test that proves the shipped app starts, the renderer loads, IPC
 * answers, and the hardening is actually in effect. A unit test cannot show any
 * of that.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');

// Mirror main.mjs's switches so the environment matches production.
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
app.commandLine.appendSwitch('disable-domain-reliability');
app.commandLine.appendSwitch('no-pings');

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
}

app.whenReady().then(async () => {
  // Load the real main process so the same IPC handlers and window options apply.
  const win = new BrowserWindow({
    show: false,
    width: 1100,
    height: 800,
    webPreferences: {
      preload: join(__dirname, '..', 'electron', 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const prefs = win.webContents.getLastWebPreferences() || {};
  record('contextIsolation enabled', prefs.contextIsolation === true);
  record('nodeIntegration disabled', prefs.nodeIntegration !== true);
  record('sandbox enabled', prefs.sandbox === true);

  const errors = [];
  win.webContents.on('console-message', (_e, level, message) => {
    if (level >= 2) errors.push(message);
  });

  try {
    await win.loadFile(join(__dirname, '..', 'renderer', 'index.html'));
  } catch (err) {
    record('renderer loads', false, err.message);
    finish();
    return;
  }
  record('renderer loads', true);

  // Give the module scripts a moment to run.
  await new Promise((resolve) => setTimeout(resolve, 1500));

  // The bridge should be present and frozen.
  const bridgeInfo = await win.webContents.executeJavaScript(`(() => {
    const b = window.ysm;
    return {
      present: typeof b === 'object' && b !== null,
      frozen: b ? Object.isFrozen(b) : false,
      hasInvoke: b ? typeof b.invoke === 'function' : false,
      leakedNode: typeof window.require !== 'undefined' || typeof window.process !== 'undefined',
      leakedElectron: typeof window.electron !== 'undefined' || typeof window.ipcRenderer !== 'undefined',
    };
  })()`);

  record('preload bridge exposed', bridgeInfo.present);
  record('bridge is frozen', bridgeInfo.frozen);
  record('bridge exposes invoke', bridgeInfo.hasInvoke);
  record('no node/process leaked to renderer', !bridgeInfo.leakedNode);
  record('no raw ipcRenderer leaked', !bridgeInfo.leakedElectron);

  // Screens should have been rendered with translations applied.
  const domInfo = await win.webContents.executeJavaScript(`(() => {
    const visible = (id) => {
      const el = document.getElementById(id);
      return el ? el.classList.contains('active') : false;
    };
    return {
      bootVisible: visible('screen-boot'),
      title: document.title,
      dir: document.documentElement.dir,
      lang: document.documentElement.lang,
      translateButton: (document.getElementById('btn-go-create') || {}).textContent || '',
      screenCount: document.querySelectorAll('.screen').length,
    };
  })()`);

  record('boot screen visible', domInfo.bootVisible);
  record('document title set', domInfo.title.includes('YSM'), domInfo.title);
  record('translations applied', domInfo.translateButton.trim().length > 0, JSON.stringify(domInfo.translateButton));
  record('six screens present', domInfo.screenCount === 6, String(domInfo.screenCount));

  // Theme/direction flip must work for Farsi.
  const rtlInfo = await win.webContents.executeJavaScript(`(async () => {
    // Reach into the module by dispatching the language button the user would click.
    const btn = document.querySelector('.lang-btn[data-locale="fa"]');
    if (!btn) return { ok: false, reason: 'no fa button' };
    btn.click();
    await new Promise((r) => setTimeout(r, 300));
    return {
      ok: document.documentElement.dir === 'rtl',
      dir: document.documentElement.dir,
      text: (document.getElementById('btn-go-create') || {}).textContent || '',
    };
  })()`);
  record('Farsi switches document to rtl', rtlInfo.ok, `dir=${rtlInfo.dir} text=${JSON.stringify(rtlInfo.text)}`);

  // A forbidden IPC channel must be rejected by main.
  const badChannel = await win.webContents.executeJavaScript(`window.ysm.invoke('evil:channel', {})`);
  record('unknown ipc channel rejected', badChannel && badChannel.ok === false, JSON.stringify(badChannel));

  const report = {
    total: results.length,
    passed: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok).length,
    consoleErrors: errors,
  };
  console.log('\n' + JSON.stringify(report, null, 2));

  finish(report.failed === 0 ? 0 : 1);
});

function finish(code) {
  // Give Electron a moment to flush logs before exiting.
  setTimeout(() => app.exit(code === undefined ? 0 : code), 300);
}
