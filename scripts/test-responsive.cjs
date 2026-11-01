/**
 * Responsive layout test at phone widths.
 *
 * The user asked specifically for a mobile-capable UI, so this measures the real
 * rendered layout at 360, 390, 768 and 1280 px and fails on:
 *   - horizontal overflow (the classic mobile breakage)
 *   - touch targets smaller than 44 px
 *   - text that overflows its container
 *
 * It also checks the Farsi RTL flip at phone width, since RTL is where layout
 * bugs hide.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');

const INDEX = join(__dirname, '..', 'renderer', 'index.html');
const PRELOAD = join(__dirname, '..', 'electron', 'preload.cjs');

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

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: 1280,
    height: 900,
    show: false,
    webPreferences: { preload: PRELOAD, contextIsolation: true, nodeIntegration: false, sandbox: true },
  });

  await win.loadFile(INDEX);
  await sleep(1200);

  // Show the window: a hidden window does not always apply setContentSize, which
  // would make every responsive assertion measure a 1280px viewport and pass or
  // fail for the wrong reason.
  win.show();
  await sleep(400);

  const sizes = [
    [360, 740, 'small phone'],
    [390, 844, 'iPhone-ish'],
    [768, 1024, 'tablet'],
    [1280, 900, 'desktop'],
  ];

  for (const [w, h, label] of sizes) {
    win.setContentSize(w, h);
    await sleep(400);

    const metrics = await win.webContents.executeJavaScript(`(() => {
      const doc = document.documentElement;
      const body = document.body;

      // Horizontal overflow is the main mobile failure mode.
      const overflowX = Math.max(doc.scrollWidth, body.scrollWidth) - doc.clientWidth;

      // Find any element wider than the viewport.
      const wide = [];
      for (const el of document.querySelectorAll('*')) {
        const r = el.getBoundingClientRect();
        if (r.width > doc.clientWidth + 1 && r.height > 0) {
          wide.push({ tag: el.tagName, id: el.id, cls: String(el.className).slice(0, 30), w: Math.round(r.width) });
        }
      }

      // Touch targets: every visible button must be at least 44px tall.
      const small = [];
      for (const el of document.querySelectorAll('button, input, select, textarea')) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;   // hidden
        if (r.height < 44) small.push({ tag: el.tagName, id: el.id, h: Math.round(r.height) });
      }

      return {
        viewport: doc.clientWidth,
        overflowX,
        wideCount: wide.length,
        wideSample: wide.slice(0, 4),
        smallCount: small.length,
        smallSample: small.slice(0, 6),
        activeScreen: (document.querySelector('.screen.active') || {}).id || 'none',
      };
    })()`);

    check(`${label} (${w}px): no horizontal overflow`, metrics.overflowX <= 1, `overflow=${metrics.overflowX}px`);
    check(`${label}: no element wider than viewport`, metrics.wideCount === 0, JSON.stringify(metrics.wideSample));
    check(`${label}: all touch targets >= 44px`, metrics.smallCount === 0, JSON.stringify(metrics.smallSample));
  }

  console.log('=== mobile: sidebar collapses ===');
  // The app shell is hidden until an account is unlocked, so reveal it first;
  // otherwise every measurement returns 0 and the test proves nothing.
  await win.webContents.executeJavaScript(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-main').classList.add('active');
    const panel = document.getElementById('panel-chats');
    if (panel) panel.classList.add('active');
  })()`);
  win.setContentSize(360, 740);
  await sleep(400);
  const mobileLayout = await win.webContents.executeJavaScript(`(() => {
    const sidebar = document.querySelector('.sidebar');
    const shell = document.querySelector('.app-shell');
    const s = getComputedStyle(shell);
    const sb = getComputedStyle(sidebar);
    return {
      viewportWidth: document.documentElement.clientWidth,
      innerWidth: window.innerWidth,
      flexDirection: s.flexDirection,
      sidebarWidth: Math.round(sidebar.getBoundingClientRect().width),
      tappedBrandVisible: sb.display !== 'none',
    };
  })()`);
  check('mobile: viewport really is narrow', mobileLayout.innerWidth <= 420, `innerWidth=${mobileLayout.innerWidth}`);
  check('mobile: shell stacks vertically', mobileLayout.flexDirection === 'column', mobileLayout.flexDirection);
  check('mobile: sidebar spans full width', mobileLayout.sidebarWidth >= 340, `${mobileLayout.sidebarWidth}px`);

  console.log('=== desktop: sidebar beside content ===');
  win.setContentSize(1280, 900);
  await sleep(300);
  const desktopLayout = await win.webContents.executeJavaScript(`(() => {
    const shell = document.querySelector('.app-shell');
    const sidebar = document.querySelector('.sidebar');
    return {
      flexDirection: getComputedStyle(shell).flexDirection,
      sidebarWidth: Math.round(sidebar.getBoundingClientRect().width),
    };
  })()`);
  check('desktop: shell is row', desktopLayout.flexDirection === 'row', desktopLayout.flexDirection);
  check('desktop: fixed-width sidebar', desktopLayout.sidebarWidth >= 240 && desktopLayout.sidebarWidth <= 300, `${desktopLayout.sidebarWidth}px`);

  console.log('=== composer fully visible on a phone ===');
  win.setContentSize(360, 740);
  await win.webContents.executeJavaScript(`(() => {
    for (const el of document.querySelectorAll('.panel')) el.classList.remove('active');
    document.getElementById('panel-conversation').classList.add('active');
  })()`);
  await sleep(400);
  const composer = await win.webContents.executeJavaScript(`(() => {
    const bar = document.querySelector('.composer');
    const input = document.getElementById('composer-input');
    const send = document.getElementById('btn-send');
    const attach = document.getElementById('btn-attach');
    const vh = window.innerHeight;
    const barRect = bar.getBoundingClientRect();
    const sendRect = send.getBoundingClientRect();
    return {
      viewportHeight: vh,
      barBottom: Math.round(barRect.bottom),
      sendBottom: Math.round(sendRect.bottom),
      sendHeight: Math.round(sendRect.height),
      inputHeight: Math.round(input.getBoundingClientRect().height),
      attachText: (attach.textContent || '').trim(),
    };
  })()`);
  check(
    'composer bar fits inside the viewport',
    composer.barBottom <= composer.viewportHeight + 1,
    `barBottom=${composer.barBottom} vh=${composer.viewportHeight}`,
  );
  check(
    'send button is not clipped',
    composer.sendBottom <= composer.viewportHeight + 1 && composer.sendHeight >= 40,
    `sendBottom=${composer.sendBottom} h=${composer.sendHeight}`,
  );
  check(
    'attach button shows an icon, not label text',
    composer.attachText.length <= 2,
    JSON.stringify(composer.attachText),
  );

  console.log('=== Farsi RTL at phone width ===');
  const rtl = await win.webContents.executeJavaScript(`(async () => {
    const btn = document.querySelector('.lang-btn[data-locale="fa"]');
    if (!btn) return { ok: false, reason: 'missing fa button' };
    btn.click();
    await new Promise(r => setTimeout(r, 400));
    const doc = document.documentElement;
    const overflow = Math.max(doc.scrollWidth, document.body.scrollWidth) - doc.clientWidth;
    const wide = [...document.querySelectorAll('*')].filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > doc.clientWidth + 1 && r.height > 0;
    }).length;
    return { ok: doc.dir === 'rtl', dir: doc.dir, overflow, wide, lang: doc.lang };
  })()`);
  check('Farsi sets dir=rtl', rtl.ok, JSON.stringify(rtl));
  check('Farsi: no horizontal overflow', rtl.overflow <= 1, `overflow=${rtl.overflow}px`);
  check('Farsi: no element wider than viewport', rtl.wide === 0, `wide=${rtl.wide}`);

  console.log('=== Dutch still LTR ===');
  const nl = await win.webContents.executeJavaScript(`(async () => {
    const btn = document.querySelector('.lang-btn[data-locale="nl"]');
    btn.click();
    await new Promise(r => setTimeout(r, 400));
    return { dir: document.documentElement.dir, lang: document.documentElement.lang };
  })()`);
  check('Dutch sets dir=ltr', nl.dir === 'ltr', JSON.stringify(nl));

  console.log(`\n${pass} passed, ${fail} failed`);
  win.destroy();
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
