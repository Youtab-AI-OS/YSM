# YSM — OWASP analysis

Three separate frameworks are covered:

1. **OWASP Top 10 (2021)** — web application risks
2. **OWASP Top 10 for LLM Applications** — model/prompt risks
3. **OWASP Agentic AI threats** — autonomous agent risks

For each item: what YSM does, and what residual risk remains. Items that do not
apply are marked **N/A with a reason** rather than omitted. Nothing here claims
"fully mitigated": every row with a real remaining risk says so.

---

## 1. OWASP Top 10 (2021)

### A01 — Broken Access Control

**Relevant, and central to the design.**

| Control | Implementation |
| --- | --- |
| Closed operation allowlist | The renderer can only invoke channels in `IPC_CHANNELS`; `preload.cjs` throws for anything else, and `main.mjs` re-checks with `isIpcChannel`. There is no generic `invoke(anything)` escape hatch. |
| Locked-state enforcement | Every data operation calls `requireVault()` and returns `LOCKED` if the vault is not unlocked. Verified by `e2e-electron.cjs` ("data call fails when locked"). |
| Per-message recipient binding | Envelope `open()` rejects a message whose `to` field is not the caller's own key (`WRONG_RECIPIENT`). A third party holding the ciphertext cannot decrypt it — proven in `e2e-two-users.cjs` ("eve cannot decrypt"). |
| File path containment | Received files are written only into the app's own export directory, with names passed through `sanitizeFilename` (strips path separators, control characters, leading dots). The renderer cannot specify a path. |
| Renderer file access | The network guard allows `file://` reads only under `renderer/`, and resolves `..` before comparing, so `renderer/../package.json` is blocked. Covered by `test-urlguard.cjs`. |

**Residual risk.** Low. The trust boundary is the IPC surface, which is small
and enumerated. A bug inside a service method could still act with full vault
authority, but cannot widen what the renderer may request.

### A02 — Cryptographic Failures

| Control | Implementation |
| --- | --- |
| Primitives | X25519, Ed25519, AES-256-GCM, HKDF-SHA256, Argon2id — all from audited `@noble/*` libraries. No custom constructions. |
| No fixed IVs | A fresh random 12-byte nonce and 32-byte salt per message. Tested: identical plaintexts produce different ciphertext with no repeated blocks. |
| Authenticated encryption | AES-GCM; tampering is detected. Signature verified *before* decryption, so a forger learns nothing from the decrypt path. |
| Key separation | Encryption and MAC keys derive from the ECDH secret with distinct HKDF `info` labels. |
| Password handling | Argon2id (64 MiB, t=3, p=1), per-account salt. The password is never stored; a domain-separated verifier is used only to distinguish "wrong password" from "corrupt vault". |
| Key at rest | The random 32-byte vault key is wrapped with AES-256-GCM under an Argon2id-derived KEK. The KEK exists only in memory while unlocked. |
| Data at rest | Every user-data column is separately encrypted with a context-bound subkey, so a ciphertext moved between columns fails to decrypt. |
| Field-level context binding | Prevents ciphertext relocation (e.g. an encrypted message replayed into the contact-name column). |
| Constant-time comparison | Tag and TOTP checks use non-short-circuiting comparison. |
| Randomness | `crypto.getRandomValues` / the platform CSPRNG only; no `Math.random` anywhere in crypto paths. |

**Verified against independent implementations**, not just self-consistency:
seven ciphertexts captured from the live aesencryption.net tool, a 300-case
random CBC cross-check against OpenSSL, and the official RFC 6238 TOTP vectors.

**Residual risk.** No forward secrecy (see `docs/ARCHITECTURE.md` §4): the
X25519 identity key is long-term, so compromise of a device's key decrypts
previously captured messages. This is a real gap versus Signal and is stated as
such. A nonce-reuse bug in GCM would be catastrophic, mitigated by using a fresh
random 96-bit nonce per message and keeping message counts well under the
\(2^{32}\) birthday bound.

### A03 — Injection

| Vector | Control |
| --- | --- |
| HTML/XSS in the renderer | All user-controlled text is written with `textContent`. Message bodies, contact names, filenames, safety numbers and error strings never reach `innerHTML`. |
| SQL injection | Every query uses bound parameters (`prepare(...).run(...)`); no string concatenation into SQL. |
| Command injection | The app never spawns a process. There is no `child_process` use in the main process. |
| Path traversal | `sanitizeFilename` strips separators; the file URL guard resolves `..`; key ids are validated against `[A-Za-z0-9._-]` so a keyring lookup cannot escape its directory. |
| Prototype pollution | Payloads are validated field-by-field with explicit type checks before use; `JSON.parse` output is never merged into objects wholesale. |

**Residual risk.** Low. A CSP is also enforced (`default-src 'none'`,
`script-src 'self'`, `connect-src 'none'`), so even a hypothetical injection
could not exfiltrate anything over the network.

### A04 — Insecure Design

Threat model documented in `docs/ARCHITECTURE.md`, including what is explicitly
out of scope. Design decisions that trade off deliberately:

- **Two independent factors at unlock.** The database does not open on password
  alone; TOTP is required every time. There is no "remember me" that bypasses it.
- **Onboarding cannot be skipped.** Account creation does not leave the vault
  unlocked — the user must produce a valid TOTP code first, so nobody can create
  an account without enrolling 2FA and then be locked out permanently.
- **Replay defence on TOTP.** The counter of the last accepted code is stored, so
  an observed code cannot be reused inside its window.
- **Fail closed.** Unknown envelope versions, algorithms, ciphers and KDFs are
  errors, not best-effort interpretations.
- **Bounded hostile input.** Envelope size, chunk count, chunk index, salt/IV
  length and PBKDF2 iteration count are all bounded *before* allocation or work,
  so a malicious message cannot cause OOM or a multi-year key derivation.

**Residual risk.** The design assumes the user's device is not compromised and
that they compare safety numbers. Neither can be enforced by software.

### A05 — Security Misconfiguration

| Control | Implementation |
| --- | --- |
| Electron hardening | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true`, `webviewTag: false`, `experimentalFeatures: false`. Asserted at runtime by `smoke-electron.cjs`. |
| No remote module | Not loaded anywhere; there is no `enableRemoteModule`. |
| Permissions | Every permission request and permission check returns `false` — no camera, microphone, geolocation, notifications. |
| Navigation | `will-navigate` blocked; `setWindowOpenHandler` denies all popups; `will-attach-webview` prevented. |
| Network | `onBeforeRequest` denies every non-app origin, so there is no reachable network at all from the renderer. |
| Update mechanism | **None.** No auto-updater, so no update channel to compromise. The trade-off is that security fixes must be delivered as a new installer. |
| `nosniff` / referrer | Declared in the document CSP; CSP is delivered via `<meta>` because Electron cannot inject the header on `file://` without aborting the load (documented in `main.mjs`). |

**Residual risk.** The `file://` origin is weaker than a custom protocol in
principle. It is compensated by the request filter restricting reads to the
renderer directory and by `webSecurity: true`. A future version should move to a
custom scheme once the Electron protocol handler is verified stable here.

### A06 — Vulnerable and Outdated Components

| Control | Implementation |
| --- | --- |
| Dependency count | Deliberately tiny: four runtime dependencies (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `qrcode`). No framework, no SQL driver to compile. |
| Native modules | **None.** `node:sqlite` is built into the runtime, eliminating the class of bug where a native module is compiled against the wrong ABI (this actually bit the build: `better-sqlite3` 12.x could not be rebuilt for Electron 45 and was removed). |
| Lockfile | `package-lock.json` pins exact versions. |

**Residual risk.** `node:sqlite` is still flagged experimental by Node (it emits
an `ExperimentalWarning`). It is stable in practice in Node 24/Electron 45, but an
API change in a future runtime is a real upgrade risk. Pinned via `engines` and
verified by the test suite on every build.

### A07 — Identification and Authentication Failures

| Control | Implementation |
| --- | --- |
| Password policy | Minimum 12 characters, common-password list, rejects single-character and two-symbol patterns. Deliberately does not fake an entropy meter. |
| Credential storage | Never stored. Argon2id verifier only. |
| Second factor | TOTP (RFC 6238), 6 digits, 30 s, ±1 window, secret in Base32 with an `otpauth://` URI and a QR code that is verified to decode with an independent decoder. |
| Replay | Last-used counter persisted; reused codes rejected. |
| Brute force | Exponential backoff persisted in the database: 30 s after the 5th failure, doubling to a 15-minute ceiling. Checked *before* Argon2 runs, so it cannot be used as a CPU oracle. Verified by `test-vault.mjs`. |
| Recovery | 10 single-use codes, stored only as hashes, consumed atomically on use. Password is still required. Verified that a used code cannot be replayed. |
| Account duplication | A second account cannot be created in the same database file. |

**Residual risk.** TOTP is phishable in principle, but YSM has no remote login
endpoint, so there is no phishing surface — an attacker would need local access
to the device and the password. If an attacker has the password *and* the TOTP
secret, they are the user; nothing in the design can prevent that.

### A08 — Software and Data Integrity Failures

| Control | Implementation |
| --- | --- |
| Message integrity | AEAD tag plus Ed25519 signature over header, salt, nonce and ciphertext. Any modification fails verification. |
| Contact card integrity | Self-signed; a card whose signature does not verify is refused (`parseCard`). |
| Impersonation | A message whose signing key differs from the stored contact's signing key is **refused**, not warned about (`KEY_MISMATCH`). |
| File integrity | Per-file SHA-256 plus chunk count; reassembly fails on missing chunks, size mismatch or hash mismatch. |
| Chunk reordering | Chunk index is in both the header and the per-chunk key derivation, so reorder/duplicate/drop is detected. |
| Signature ordering | Signature verified before decryption, so the decryption path is never reached for a forged message. |

**Residual risk.** None identified within the threat model.

### A09 — Security Logging and Monitoring Failures

**Deliberately minimal, and this is a privacy decision, not an oversight.**

- The app logs nothing to disk. There is no log file, no crash report upload, no
  remote telemetry.
- Console diagnostics (`[ysm] blocked outbound request`, IPC failures) go to the
  local console only and are never persisted or transmitted.
- Authentication failures are reflected in the persisted backoff counter, which
  is the only security-relevant state the app keeps.

**Trade-off, stated plainly:** there is no audit trail for a compromised
installation, and no way to detect an attack after the fact from the app itself.
For a privacy tool this is the correct default; an optional, strictly local,
encrypted activity log would be a reasonable future addition.

### A10 — Server-Side Request Forgery

**N/A.** YSM has no server component and no outbound network capability. The
request filter denies every non-app origin, `connect-src 'none'` is in the CSP,
and there is no code path that issues an HTTP request. There is no URL that a user
or an attacker could supply to make the app fetch something.

---

## 2. OWASP Top 10 for LLM Applications

**All items are N/A, for one structural reason: YSM contains no language model.**

There is no model call, no prompt construction, no embedding, no vector store, no
retrieval, no tool-calling by a model, and no AI feature of any kind. Message
content is never sent to a third party — there is no third party.

| ID | Item | Status |
| --- | --- | --- |
| LLM01 | Prompt Injection | N/A — no prompts exist. No message content reaches a model. |
| LLM02 | Insecure Output Handling | N/A — no model output exists. All UI text is written with `textContent` regardless. |
| LLM03 | Training Data Poisoning | N/A — no model is trained or fine-tuned. |
| LLM04 | Model Denial of Service | N/A — no model to exhaust. |
| LLM05 | Supply Chain Vulnerabilities | N/A for models. Supply chain for *code* is covered by A06. |
| LLM06 | Sensitive Information Disclosure | N/A — no model, so no disclosure path through one. (Data at rest is covered by A02.) |
| LLM07 | Insecure Plugin Design | N/A — no plugins, no model-invoked tools. |
| LLM08 | Excessive Agency | N/A — no agent acts on the user's behalf. |
| LLM09 | Overreliance | N/A — no model output for a user to over-trust. |
| LLM10 | Model Theft | N/A — no model is hosted or bundled. |

This is worth stating explicitly because a messenger that *did* add an AI
assistant would acquire all ten of these at once, including the worst one:
LLM01 plus LLM06 together mean an attacker's message could instruct the model to
summarise other conversations. YSM avoids that entire class by not having the
feature.

---

## 3. OWASP Agentic AI threats (agentic security)

**All items are N/A, for the same structural reason: YSM has no agent.**

No autonomous loop, no planner, no delegated tool use, no memory that an agent
writes to, no multi-agent coordination, no self-modification.

| Threat class | Status |
| --- | --- |
| Goal hijacking / prompt injection into an agent | N/A — no agent |
| Tool misuse via model-driven selection | N/A — tool selection is static code, never model-chosen |
| Excessive autonomy / unbounded action loops | N/A — every action is a user click |
| Memory poisoning | N/A — nothing writes to agent memory |
| Privilege escalation through delegated credentials | N/A — no delegation |
| Confused-deputy through agent mediation | N/A — the IPC allowlist is a fixed table, not a planner |
| Multi-agent collusion / emergent behaviour | N/A — single-process, no agents |
| Supply-chain compromise of agent plugins | N/A — no plugin system |

Where an agentic control *would* map onto something real here, it is already
handled structurally:

- **Static tool selection.** The IPC channel table is code, not inference. Nothing
  can persuade the app to call a different operation (A01).
- **Bounded actions.** Every operation has fixed inputs validated by a per-channel
  validator; there is no free-form command channel.
- **No ambient credentials.** The app holds no API keys, no tokens, no cloud
  credentials. There is nothing for an agent — or an attacker — to steal and
  replay elsewhere.

---

## 4. Summary of real, remaining risks

Ranked by what would actually hurt a user:

1. **No forward secrecy.** A stolen device key decrypts past messages. Needs a
   Double Ratchet to fix.
2. **Safety numbers require user action.** If two users never compare them, a
   man-in-the-middle is undetectable. The UI surfaces this prominently but cannot
   enforce it.
3. **No auto-update.** Security fixes require manual reinstall; users may run an
   outdated build.
4. **`node:sqlite` is experimental.** An API change would require a rebuild.
5. **No multi-device support.** Adding a second device is not implemented.
6. **Transport is out of scope.** If envelopes travel by email, the mail provider
   learns who talks to whom and when.

Everything above is a deliberate scope decision or an honestly-unfinished area,
not a hidden gap.
