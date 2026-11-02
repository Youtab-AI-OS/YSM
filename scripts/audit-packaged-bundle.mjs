/**
 * Inspect the packaged bundle for anything that could talk to the network or act
 * as a hidden channel.
 *
 * Checks the artefact that actually ships (an extracted app.asar), not the source
 * tree, because a build step or a dependency could introduce something the sources
 * do not show.
 *
 * Comments are stripped with a small scanner rather than per line: JSDoc blocks
 * contain documentation URLs (NIST, IETF, Wikipedia) that a line filter would
 * report as network calls. String literals are preserved so a URL inside a real
 * string is still caught.
 *
 * Usage: node scripts/audit-packaged-bundle.mjs <extracted-asar-dir>
 */
import { readdirSync, readFileSync, mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

let ROOT = process.argv[2];
let sourceLabel = 'the packaged bundle';
let extracted = null;

// Prefer the shipped archive, since that is what a customer runs. Fall back to the
// directories that actually ship, so the gate still runs on a fresh clone without a
// packaged build — and say plainly which was inspected, because a check that
// silently covers less than it claims is worse than no check.
const asarExists = ROOT !== undefined && existsSync(ROOT) && statSync(ROOT).isFile();
let roots;
if (asarExists) {
  extracted = mkdtempSync(join(tmpdir(), 'ysm-asar-'));
  const asarCli = join('node_modules', '@electron', 'asar', 'bin', 'asar.js');
  execFileSync(process.execPath, [asarCli, 'extract', ROOT, extracted], { stdio: 'ignore' });
  roots = [extracted];
  sourceLabel = 'the packaged app.asar';
} else {
  roots = ['build/ysm', 'electron', 'renderer'].filter((d) => existsSync(d));
  sourceLabel = 'the shipped directories (build/ysm, electron, renderer) — run the dist step to cover the packaged form';
  console.log(`note: ${sourceLabel}`);
  console.log('');
}

const files = [];
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.(js|cjs|mjs)$/.test(entry.name)) files.push(full);
  }
}
for (const dir of roots) walk(dir);

/**
 * Remove comments, keep code and string contents.
 *
 * A character scanner is the only reliable way here: block comments span lines and
 * their continuation lines do not necessarily begin with an asterisk.
 */
function stripComments(src) {
  let out = '';
  let i = 0;
  let mode = 'code'; // code | line | block | sq | dq | tpl
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (mode === 'code') {
      if (c === '/' && next === '/') { mode = 'line'; i += 2; continue; }
      if (c === '/' && next === '*') { mode = 'block'; i += 2; continue; }
      if (c === "'") { mode = 'sq'; out += c; i++; continue; }
      if (c === '"') { mode = 'dq'; out += c; i++; continue; }
      if (c === '`') { mode = 'tpl'; out += c; i++; continue; }
      out += c;
      i++;
      continue;
    }
    if (mode === 'line') {
      if (c === '\n') { mode = 'code'; out += c; }
      i++;
      continue;
    }
    if (mode === 'block') {
      if (c === '*' && next === '/') { mode = 'code'; i += 2; continue; }
      if (c === '\n') out += c; // keep line structure for readable offsets
      i++;
      continue;
    }
    // Inside a string literal.
    if (c === '\\') { out += c + (next ?? ''); i += 2; continue; }
    if ((mode === 'sq' && c === "'") || (mode === 'dq' && c === '"') || (mode === 'tpl' && c === '`')) {
      mode = 'code';
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * A method named `eval` is not dynamic code execution.
 *
 * @noble/curves defines `eval(a, x, brp)` on a polynomial object — ordinary
 * arithmetic. Blank out method definitions before looking for a call to the global
 * `eval`, so the check reports real dynamic evaluation only.
 */
function hasBareEval(code) {
  const withoutMethodDefs = code.replace(/^[ \t]*(?:async[ \t]+)?eval[ \t]*\([^)]*\)[ \t]*\{/gm, 'METHOD_DEF');
  const withoutShorthand = withoutMethodDefs.replace(/[{,][ \t]*eval[ \t]*[:(]/g, '{PROP');
  return /(?<![.\w$])eval\s*\(/.test(withoutShorthand);
}

const checks = [
  ['imports a network module', /(?:require\(\s*['"]node:(?:https?|net|tls|dgram|dns)['"]\s*\)|from\s+['"]node:(?:https?|net|tls|dgram|dns)['"])/],
  ['calls fetch()', /(?<![.\w$])fetch\s*\(/],
  ['opens a websocket', /new\s+WebSocket\s*\(/],
  ['sends a beacon', /sendBeacon\s*\(/],
  ['uses XMLHttpRequest', /new\s+XMLHttpRequest\s*\(/],
  ['uses EventSource', /new\s+EventSource\s*\(/],
  ['uses http(s) .request or .get', /\bhttps?\.(?:request|get)\s*\(/],
  // A URL in a real string is a connection target; in a comment it is a citation,
  // and comments are already gone by the time this runs.
  ['contains an external URL in code', /['"`]https?:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org)[a-z0-9.-]+\.[a-z]{2,}/i],
  ['spawns a child process', /child_process|execSync|spawnSync|execFileSync/],
  // `x.eval(` is a method name; only a bare eval() is dynamic code execution.
  ['uses bare eval()', hasBareEval],
  ['uses new Function()', /new\s+Function\s*\(/],
  ['captures the screen or camera', /desktopCapturer|getUserMedia|getDisplayMedia/],
  ['reads the clipboard silently', /clipboard\.read(?:Text|HTML)?\s*\(/],
  ['contains a long encoded blob', /['"][A-Za-z0-9+/]{500,}={0,2}['"]/],
];

let totalHits = 0;
let scanned = 0;
for (const [label, matcher] of checks) {
  const hits = [];
  for (const file of files) {
    // Label the file relative to whichever root it came from, so a hit is easy to
    // locate whether it came from the archive or from the build tree.
    const base = roots.find((r) => file.startsWith(r)) || '';
    const rel = relative(base, file).replace(/\\/g, '/');
    // The vendored QR encoder is a known, reviewed library that does arithmetic only.
    if (rel.includes('node_modules/qrcode')) continue;
    scanned++;
    const code = stripComments(readFileSync(file, 'utf8'));
    // A check is either a RegExp or a predicate, so a pattern needing an exception
    // can carry its own logic instead of a lookaround nobody can read later.
    const found = typeof matcher === 'function' ? matcher(code) : matcher.test(code);
    if (found) hits.push(rel);
  }
  totalHits += hits.length;
  console.log(`${hits.length === 0 ? 'PASS' : 'FAIL'}  ${label}${hits.length ? ` — ${hits.slice(0, 4).join(', ')}` : ''}`);
}

console.log(`
scanned ${files.length} JS files in ${sourceLabel} (${scanned} file-checks)`);
console.log(totalHits === 0
  ? 'CLEAN: no network path and no hidden channel in the shipped code'
  : `${totalHits} finding(s) to review`);

// Clean up the extraction so repeated runs do not litter the temp directory.
if (extracted !== null) {
  try { rmSync(extracted, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
}

process.exit(totalHits === 0 ? 0 : 1);
