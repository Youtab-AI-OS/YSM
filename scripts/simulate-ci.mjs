#!/usr/bin/env node
/**
 * Simulate CI on a clean checkout.
 *
 * `npm run build` passes here on a working tree that still has local files, but
 * CI only has what git tracks. This script clones the repo into a temp directory,
 * runs `npm ci` and the full test pipeline there, and reports the result.
 *
 * It exists because CI failed on exactly this: a build step read an icon from a
 * directory that was not committed. Running the real pipeline against a pristine
 * clone is the only way to catch that class of error before pushing.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const ROOT = process.cwd();
// Use the npm that ships with the Node running this script. Referencing
// `node_modules/npm/bin/npm-cli.js` from the working tree fails, because the temp
// clone has no node_modules yet — that is the whole point of `npm ci`.
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const stages = process.argv.slice(2);
const runStages = stages.length > 0 ? stages : ['typecheck', 'build'];

function run(cwd, label, args, timeout = 900_000) {
  console.log(`\n--- ${label} ---`);
  const r = spawnSync(npmCmd, args, {
    cwd,
    stdio: 'inherit',
    timeout,
    shell: process.platform === 'win32',
    env: { ...process.env, CI: 'true' },
  });
  return r.status === 0;
}

const clone = mkdtempSync(join(tmpdir(), 'ysm-ci-'));
console.log(`clean clone: ${clone}`);

try {
  // Clone from the local git repo, which is what CI sees. A plain path works in
  // both git-bash and Windows; a file:// URL with a drive letter does not.
  let r = spawnSync('git', ['clone', '--quiet', '--depth', '1', ROOT, clone], {
    stdio: 'inherit',
  });
  if (r.status !== 0) {
    console.error('git clone failed');
    process.exit(1);
  }

  // `npm ci` requires the lockfile that is actually committed.
  if (!run(clone, 'npm ci', ['ci', '--no-audit', '--no-fund'])) {
    console.error('\nFAIL npm ci');
    process.exit(1);
  }

  for (const stage of runStages) {
    const ok =
      stage === 'test:lib' || stage === 'test:unit' || stage === 'test:tools'
        ? run(clone, `npm run ${stage}`, ['run', stage])
        : run(clone, `npm run ${stage}`, ['run', stage]);
    if (!ok) {
      console.error(`\nFAIL ${stage}`);
      process.exit(1);
    }
  }

  console.log('\nPASS clean checkout builds and tests');
} finally {
  try {
    rmSync(clone, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // Windows may hold handles briefly; the temp dir is disposable.
  }
}
