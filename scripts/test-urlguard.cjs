/**
 * Check the URL-normalisation used by the Electron request filter.
 *
 * Getting this wrong either breaks the app (the document cannot load) or is too
 * permissive (arbitrary file:// reads). Both failure modes are silent, so the
 * logic is pinned here.
 */
const path = require('node:path');

const APP_ROOT = path.resolve('K:/Crypto_message');
const RENDERER_PREFIX = path.join(APP_ROOT, 'renderer').replace(/\\/g, '/').toLowerCase();

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
    return path.resolve(driveRelative).replace(/\\/g, '/').toLowerCase();
  } catch {
    return url.replace(/\\/g, '/').toLowerCase();
  }
}

const cases = [
  ['file:///K:/Crypto_message/renderer/index.html', true, 'the app document'],
  ['file:///K:/Crypto_message/renderer/app.js', true, 'app script'],
  ['file:///K:/Crypto_message/renderer/styles.css', true, 'app stylesheet'],
  ['file:///K:/Crypto_message/assets/icon.png', false, 'assets are referenced relatively, resolved under renderer/'],
  ['file:///C:/Windows/System32/config/SAM', false, 'arbitrary system file'],
  ['file:///K:/Crypto_message/renderer/../package.json', false, 'path traversal out of renderer'],
  ['https://example.com/track', false, 'remote request'],
  ['http://localhost:3000/', false, 'localhost request'],
  ['data:text/html,<script>alert(1)</script>', false, 'inline data html is not a file url'],
];

let pass = 0;
let fail = 0;
for (const [url, expectApp, label] of cases) {
  const isAppFile = url.startsWith('file:///') && normalizePath(url).startsWith(RENDERER_PREFIX);
  // data:/blob:/devtools:/ are handled separately in main.mjs and are not "app files".
  const ok = isAppFile === expectApp;
  if (ok) {
    pass++;
    console.log(`PASS ${label} -> ${isAppFile ? 'allowed' : 'blocked'}`);
  } else {
    fail++;
    console.log(`FAIL ${label}: expected ${expectApp ? 'allowed' : 'blocked'}, got ${isAppFile ? 'allowed' : 'blocked'}`);
    console.log(`     url=${url} normalized=${normalizePath(url)}`);
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
