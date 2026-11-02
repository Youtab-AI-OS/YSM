# Clean-machine verification — what was actually run

Date: 2026-11-02
Installer tested: `YSM-Setup-1.0.0-x64.exe`
SHA-256: `59eff309dac39861e03908a8da3ea1b166cb0c38ef651244a4aebb57c343cad0`

## Environment

Oracle VirtualBox 7.2.20, VM `R4-Cron-Time-QA-20261028`, Windows 11 Enterprise
build 26100, user `vmtest` (non-elevated), 1024x768, no prior YSM install.

## Observed results

| Step | Result |
| --- | --- |
| Installer launches on clean Windows 11 | PASS — setup UI appeared |
| Silent install completes | PASS — returned to prompt, exit 0 |
| Files land in `%LOCALAPPDATA%\Programs\YSM` | PASS — 18 files, 327 MB |
| `YSM.exe` present | PASS — 249,788,928 bytes |
| `resources/app.asar` present | PASS |
| Installed app launches | PASS — window titled "YSM — Youtab Security Message" |
| App shows its real first screen | PASS — "Welcome to YSM", Create a new account / Unlock existing account, "No telemetry. No servers. No tracking." |

Notes on the install path:

- The installer copies from a VirtualBox shared folder, so Windows attaches the
  Mark-of-the-Web and SmartScreen blocks execution silently. `Unblock-File` before
  running resolves it. A customer downloading from a normal channel will see one
  SmartScreen prompt because the installer is not code-signed; that is expected.
- Silent install used `/verysilent /currentuser /norestart /log=...`.

## Not completed in this environment

Creating an account and pasting a transfer string inside the guest was **not**
completed. VirtualBox did not deliver synthetic keyboard or mouse input to the
guest's Electron window: `keyboardputscancode` reached `cmd.exe` and the Windows
Run dialog, but not the Chromium window, in either headless or GUI mode. This is a
limitation of the test harness, not of the application.

The same round-trip is covered by automated tests that do not need this input
path (`scripts/test-cross-machine.mjs`: 33 checks, two independent databases).
What remains unproven by automation is only that a human, clicking by hand, can
complete the same steps on a fresh install.

## To close that gap by hand

Follow `docs/CLEAN-MACHINE-VERIFICATION.md`. It is written for the person at the
keyboard, with a checkbox per step. The critical one is section 3: seal a message
on one machine, then open it on the other with the transfer string and passphrase.

## Automated coverage that does exist

| Script | Checks | What it establishes |
| --- | --- | --- |
| `test-cross-machine.mjs` | 33 | A payload sealed on one machine opens on another that has never seen it |
| `test-seal.mjs` | 39 | Seal/open, wrong passphrase, tampering, all formats |
| `test-sealed-service.mjs` | 52 | Full service flow including transfer strings |
| `test-crypto-ui.cjs` | 31 | The real UI: type, Create crypto, copy, paste, decode, download |
| `test-recovery-export.cjs` | 24 | CSV and PDF recovery codes open correctly |
| `test-rtl-farsi.cjs` | 24 | Persian direction, bidi, storage round-trip, no overflow |
| `test-backdoor-audit.cjs` | 26 | No exfiltration path, no hidden code, runtime controls in force |
| `test-offline.cjs` | 20 | Every network attempt blocked; app works with no network |
| `test-adversarial.mjs` | 105 | Tampering, replay, impersonation, chunk manipulation, traversal |
