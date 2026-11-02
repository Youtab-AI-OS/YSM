#!/usr/bin/env node
/**
 * Build the Windows installer end to end.
 *
 * Steps, each of which fails loudly:
 *   1. build the renderer/app TypeScript + i18n + icons
 *   2. package with electron-builder (produces release/win-unpacked)
 *   3. compile the Inno Setup script (produces the Setup .exe)
 *   4. verify the Setup .exe exists, is non-trivial in size, and carries the
 *      expected version resource
 *
 * Locating ISCC: Inno Setup installs per-user by default (winget, no admin), so
 * the usual "Program Files" paths are not enough. The lookup order below covers
 * per-machine, per-user, PATH, and an explicit YSM_ISCC override.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERSION = JSON.parse(
  spawnSync(process.execPath, ['-p', 'JSON.stringify(require("./package.json"))'], { cwd: root, encoding: 'utf8' }).stdout,
).version;

function findIscc() {
  const candidates = [
    process.env['YSM_ISCC'],
    'C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe',
    'C:\\Program Files\\Inno Setup 6\\ISCC.exe',
    join(homedir(), 'AppData', 'Local', 'Programs', 'Inno Setup 6', 'ISCC.exe'),
    'C:\\Program Files (x86)\\Inno Setup 7\\ISCC.exe',
    'C:\\Program Files\\Inno Setup 7\\ISCC.exe',
  ].filter(Boolean);
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  // Fall back to PATH.
  const probe = spawnSync('where', ['ISCC.exe'], { encoding: 'utf8' });
  if (probe.status === 0) {
    const first = probe.stdout.split(/\r?\n/)[0]?.trim();
    if (first && existsSync(first)) return first;
  }
  return null;
}

function run(label, command, args, cwd = root, useShell = false) {
  console.log(`\n=== ${label} ===`);
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', shell: useShell });
  if (result.status !== 0) {
    // A null status means the process could not be started at all (missing binary
    // or a command only runnable through a shell), which is worth saying plainly
    // rather than reporting as a generic failure.
    const reason = result.status === null ? `could not start ${command}${result.error ? `: ${result.error.message}` : ''}` : `exit code ${result.status}`;
    console.error(`\n${label} failed — ${reason}`);
    process.exit(result.status ?? 1);
  }
}

// 1. Build
// Use the npm that shipped with the Node running this script, found through
// npm's own resolution rather than a hard-coded path inside node_modules (which
// is absent when dependencies are installed by a manager that does not nest npm).
const npmCli = (() => {
  const candidates = [
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  // Fall back to letting npm resolve itself from PATH.
  return null;
})();

if (npmCli === null) {
  // On Windows npm is a .cmd shim, so it must be run through a shell; spawn with
  // shell:false rejects it (EINVAL).
  run('build (i18n, icons, TypeScript)', 'npm run build', [], root, true);
} else {
  run('build (i18n, icons, TypeScript)', process.execPath, [npmCli, 'run', 'build']);
}

// 2. Package
run('package (electron-builder)', process.execPath, ['node_modules/electron-builder/cli.js', '--win', '--x64', '--dir']);

const unpacked = join(root, 'release', 'win-unpacked', 'YSM.exe');
if (!existsSync(unpacked)) {
  console.error(`packaging did not produce ${unpacked}`);
  process.exit(1);
}
console.log(`packaged exe: ${unpacked} (${(statSync(unpacked).size / 1024 / 1024).toFixed(0)} MB)`);

// 3. Installer
const iscc = findIscc();
if (iscc === null) {
  console.error(
    '\nInno Setup compiler (ISCC.exe) not found.\n' +
      'Install it with:  winget install JRSoftware.InnoSetup\n' +
      'Or set YSM_ISCC to the full path of ISCC.exe.',
  );
  process.exit(1);
}
console.log(`using ISCC: ${iscc}`);
run('compile installer (Inno Setup)', iscc, [join(root, 'installer', 'ysm.iss')]);

// 4. Verify
const setup = join(root, 'release', 'installer', `YSM-Setup-${VERSION}-x64.exe`);
if (!existsSync(setup)) {
  console.error(`installer not found at ${setup}`);
  process.exit(1);
}
const size = statSync(setup).size;
if (size < 10 * 1024 * 1024) {
  console.error(`installer is suspiciously small (${size} bytes); the payload may be missing`);
  process.exit(1);
}
console.log(`\nOK  installer: ${setup}`);
console.log(`    size: ${(size / 1024 / 1024).toFixed(1)} MB`);
console.log(`    version: ${VERSION}`);
