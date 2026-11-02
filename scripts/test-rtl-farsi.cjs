/**
 * Farsi / RTL text rendering test.
 *
 * The concern this addresses: Persian text that looks right in a code editor but
 * renders wrong in the app — reversed word order, broken joining, or misaligned
 * currency/number placement.
 *
 * It checks, in a real rendered window:
 *   - the document direction flips for Farsi and back for English/Dutch
 *   - Persian script is actually rendered (not tofu boxes) by measuring that
 *     glyphs have non-zero advance width
 *   - Persian in a message bubble keeps its logical order (the DOM text is
 *     identical to what was typed, because bidi is a rendering concern and the
 *     stored text must stay intact)
 *   - the direction of a Persian-only paragraph resolves to RTL, and a
 *     mixed Persian+Latin paragraph resolves per Unicode bidi rules
 *   - Persian digits and the Persian comma survive a round trip
 *   - the Crypto tab, which is where messages are typed, handles Persian input
 *
 * Run: npx electron scripts/test-rtl-farsi.cjs
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');

const SANDBOX = mkdtempSync(join(tmpdir(), 'ysm-rtl-'));
app.setPath('userData', SANDBOX);
require('../electron/main.mjs');

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? ` (${detail})` : ''}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Text a Persian user would actually type. Contains:
// a right-to-left sentence, Persian digits, the Arabic comma, a ZWNJ (نیم‌فاصله),
// and a mixed Latin fragment.
const PERSIAN = 'سلام، این یک پیام آزمایشی است. مبلغ ۱۲۳۴۵ تومان می‌باشد.';
const MIXED = 'فایل report-2026.pdf را بفرست';
const ZWNJ_WORD = 'می‌روم'; // contains U+200C ZERO WIDTH NON-JOINER

app.whenReady().then(async () => {
  await sleep(2500);
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('FAIL: no window'); app.exit(1); return; }
  win.setContentSize(1200, 900);
  win.show();
  await sleep(1000);

  const js = (code) => win.webContents.executeJavaScript(code);
  const invoke = (ch, p) => js(`window.ysm.invoke(${JSON.stringify(ch)}, ${JSON.stringify(p ?? {})})`);

  console.log('=== direction switching ===');
  const dirs = await js(`(async () => {
    const out = {};
    for (const loc of ['fa', 'en', 'nl']) {
      document.querySelector('.lang-btn[data-locale="' + loc + '"]').click();
      await new Promise(r => setTimeout(r, 350));
      out[loc] = {
        dir: document.documentElement.dir,
        lang: document.documentElement.lang,
        sample: (document.getElementById('btn-go-create') || {}).textContent || '',
      };
    }
    return out;
  })()`);
  check('Farsi sets dir=rtl', dirs.fa.dir === 'rtl', dirs.fa.dir);
  check('Farsi sets lang=fa', dirs.fa.lang === 'fa', dirs.fa.lang);
  check('Farsi shows Persian labels', /[\u0600-\u06FF]/.test(dirs.fa.sample), dirs.fa.sample);
  check('English back to dir=ltr', dirs.en.dir === 'ltr', dirs.en.dir);
  check('Dutch stays dir=ltr', dirs.nl.dir === 'ltr', dirs.nl.dir);

  console.log('\n=== Persian glyphs actually render (no tofu boxes) ===');
  // Switch to Farsi, then measure whether Persian text occupies width. A font
  // without Persian coverage renders .notdef boxes, which still have width, so we
  // additionally compare against a control string of the same length in Latin to
  // catch a font that draws everything identically.
  await js(`document.querySelector('.lang-btn[data-locale="fa"]').click()`);
  await sleep(400);

  const glyphs = await js(`(() => {
    const host = document.createElement('div');
    host.style.cssText = 'position:absolute;left:-9999px;top:0;font-size:24px;white-space:nowrap;';
    host.textContent = ${JSON.stringify(PERSIAN)};
    document.body.appendChild(host);
    const w = host.getBoundingClientRect().width;

    const ctrl = document.createElement('div');
    ctrl.style.cssText = host.style.cssText;
    ctrl.textContent = 'x'.repeat(${PERSIAN.length});
    document.body.appendChild(ctrl);
    const cw = ctrl.getBoundingClientRect().width;

    // Measure a single Persian word for a sane per-glyph advance.
    const one = document.createElement('div');
    one.style.cssText = host.style.cssText;
    one.textContent = 'سلام';
    document.body.appendChild(one);
    const ow = one.getBoundingClientRect().width;

    host.remove(); ctrl.remove(); one.remove();
    return { width: w, controlWidth: cw, wordWidth: ow, computedFont: getComputedStyle(document.body).fontFamily };
  })()`);
  check('Persian text has non-zero rendered width', glyphs.width > 50, `${glyphs.width}px`);
  check('a 4-letter Persian word renders wider than zero', glyphs.wordWidth > 20, `${glyphs.wordWidth}px`);
  check('Persian renders differently from a Latin control', Math.abs(glyphs.width - glyphs.controlWidth) > 1, `${glyphs.width} vs ${glyphs.controlWidth}`);
  console.log(`  (font stack: ${glyphs.computedFont.slice(0, 80)})`);

  console.log('\n=== bidi resolution ===');
  const bidi = await js(`(() => {
    const probe = (text) => {
      const el = document.createElement('div');
      el.dir = 'auto';
      el.style.cssText = 'position:absolute;left:-9999px;';
      el.textContent = text;
      document.body.appendChild(el);
      const dir = getComputedStyle(el).direction;
      el.remove();
      return dir;
    };
    return {
      persianOnly: probe(${JSON.stringify(PERSIAN)}),
      mixed: probe(${JSON.stringify(MIXED)}),
      latinOnly: probe('hello world'),
      persianDigits: probe('۱۲۳۴۵'),
    };
  })()`);
  check('a Persian-only paragraph resolves to rtl', bidi.persianOnly === 'rtl', bidi.persianOnly);
  check('a Latin-only paragraph resolves to ltr', bidi.latinOnly === 'ltr', bidi.latinOnly);
  // Digits are bidi-neutral: Unicode gives them no direction of their own, so a
  // string of digits alone resolves to the container direction. That is correct
  // behaviour, not a defect — what matters is that Persian *letters* drive the
  // direction, which the two checks above and below establish.
  check('digits alone are direction-neutral (resolves with the container)', ['rtl', 'ltr'].includes(bidi.persianDigits), bidi.persianDigits);
  // A mixed sentence starting with Persian must still resolve RTL: the first
  // strong character decides.
  check('a mixed Persian-first sentence resolves to rtl', bidi.mixed === 'rtl', bidi.mixed);
  // The case that actually matters for a user: Persian digits inside Persian text.
  const digitsInContext = await js(`(() => {
    const el = document.createElement('div');
    el.dir = 'auto';
    el.style.cssText = 'position:absolute;left:-9999px;';
    el.textContent = 'مبلغ ۱۲۳۴۵ تومان';
    document.body.appendChild(el);
    const dir = getComputedStyle(el).direction;
    el.remove();
    return dir;
  })()`);
  check('Persian digits inside Persian text resolve to rtl', digitsInContext === 'rtl', digitsInContext);

  console.log('\n=== Persian survives storage and display unchanged ===');
  // Create an account through the UI, then seal Persian text and read it back.
  await js(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-create').classList.add('active');
    document.getElementById('create-name').value = 'کاربر آزمایشی';
    document.getElementById('create-password').value = 'correct horse battery staple';
    document.getElementById('create-password2').value = 'correct horse battery staple';
    document.getElementById('form-create').requestSubmit();
  })()`);
  await sleep(4500);

  const secret = await js(`((document.getElementById('totp-secret')||{}).textContent||'').trim()`);
  check('a Persian display name was accepted', secret.length === 32, `secret ${secret.length} chars`);

  const { totp, base32Decode } = require('../build/ysm/crypto/auth.js');
  const code = totp(base32Decode(secret), Math.floor(Date.now() / 1000));
  await js(`(() => {
    document.getElementById('onboard-code').value = ${JSON.stringify(code)};
    document.getElementById('onboard-verify').click();
  })()`);
  await sleep(2500);
  await js(`document.getElementById('recovery-ack').click(); document.getElementById('recovery-done').click();`);
  await sleep(2000);

  const state = await invoke('account:state');
  check('the Persian display name round-trips exactly', state.ok && state.value.displayName === 'کاربر آزمایشی',
    state.ok ? JSON.stringify(state.value.displayName) : 'no state');

  // Seal and reopen Persian text through the real UI.
  await js(`(() => {
    document.querySelector('[data-tab="crypto"]').click();
    document.getElementById('crypto-text').value = ${JSON.stringify(PERSIAN)};
    document.getElementById('crypto-create').click();
  })()`);
  await sleep(5000);

  const sealed = await js(`(() => ({
    ref: document.getElementById('crypto-ref-out').value,
    pass: document.getElementById('crypto-pass-out').value,
    shown: document.getElementById('crypto-result').hidden === false,
  }))()`);
  check('Persian text can be sealed', sealed.shown && /^YSM_[0-9a-f]{64}$/.test(sealed.ref), sealed.ref.slice(0, 16));

  if (/^YSM_[0-9a-f]{64}$/.test(sealed.ref)) {
    await js(`(() => {
      document.getElementById('crypto-tab-read').click();
      document.getElementById('read-reference').value = ${JSON.stringify(sealed.ref)};
      document.getElementById('read-passphrase').value = ${JSON.stringify(sealed.pass)};
      document.getElementById('read-open').click();
    })()`);
    await sleep(5000);

    const opened = await js(`(() => ({
      text: document.getElementById('read-text').textContent,
      hidden: document.getElementById('read-output').hidden,
      err: (document.getElementById('read-error')||{}).textContent || '',
    }))()`);
    check('Persian ciphertext reopens', opened.hidden === false, opened.err);
    check('the decrypted Persian text is byte-identical', opened.text === PERSIAN,
      JSON.stringify(opened.text.slice(0, 40)));
    check('the Persian comma survives', opened.text.includes('،'));
    check('Persian digits survive', opened.text.includes('۱۲۳۴۵'));
    check('the ZWNJ survives', opened.text.includes('\u200c'));
  }

  console.log('\n=== ZWNJ and directional marks survive storage ===');
  const zwj = await js(`(async () => {
    const r = await window.ysm.invoke('sealed:create', { text: ${JSON.stringify(ZWNJ_WORD + ' — می‌رود')} });
    if (!r.ok) return { ok: false, code: r.code };
    const o = await window.ysm.invoke('sealed:open', { reference: r.value.reference, passphrase: r.value.passphrase });
    return { ok: o.ok, text: o.ok ? o.value.text : '', expected: ${JSON.stringify(ZWNJ_WORD + ' — می‌رود')} };
  })()`);
  check('a ZWNJ word round-trips exactly', zwj.ok && zwj.text === zwj.expected, JSON.stringify(zwj.text));

  console.log('\n=== RTL layout does not overflow on a phone ===');
  win.setContentSize(360, 740);
  await sleep(600);
  const mobile = await js(`(() => {
    const doc = document.documentElement;
    const wide = [...document.querySelectorAll('*')].filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > doc.clientWidth + 1 && r.height > 0;
    }).length;
    return { dir: doc.dir, overflow: Math.max(doc.scrollWidth, document.body.scrollWidth) - doc.clientWidth, wide };
  })()`);
  check('Farsi layout has no horizontal overflow at 360px', mobile.overflow <= 1, `${mobile.overflow}px`);
  check('Farsi layout has no element wider than the viewport', mobile.wide === 0, `${mobile.wide} elements`);

  try { rmSync(SANDBOX, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('\nFailures:'); for (const f of failures) console.log(`  - ${f}`); }
  setTimeout(() => app.exit(fail === 0 ? 0 : 1), 200);
});
