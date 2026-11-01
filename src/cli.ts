#!/usr/bin/env node
/**
 * cmsg — message encryption CLI.
 *
 * v2 (default, authenticated):
 *   cmsg keygen --out alice.key [--hex] [--kid alice] [--keyring DIR]
 *   cmsg encrypt --key-file alice.key [--in msg.txt] [--out msg.cmsg] [--aad-file a.txt] [--kid alice]
 *   cmsg decrypt --key-file alice.key [--in msg.cmsg] [--out plain.txt]
 *
 * passphrase mode (PBKDF2, no key file needed):
 *   cmsg encrypt --passphrase-file pw.txt ...
 *   cmsg decrypt --passphrase-file pw.txt ...
 *
 * legacy aesencryption.net compatible:
 *   cmsg legacy-encrypt --key "text" [--bits 256] [--in t.txt]
 *   cmsg legacy-decrypt --key "text" [--bits 256] [--in b64.txt]
 *
 * inspection:
 *   cmsg inspect [--in msg.cmsg]
 *   cmsg fingerprint --key-file alice.key
 *
 * Text comes from stdin when neither --in nor a text argument is given, so
 * `echo hi | cmsg encrypt --key-file k` works. Binary input is supported with
 * --raw on decrypt (writes raw bytes instead of requiring valid UTF-8).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  CryptoMessageError,
  DEFAULT_PBKDF2_ITERATIONS,
  generateKey,
  inspect,
  keyFingerprint,
  legacyDecrypt,
  legacyDecryptDiagnostic,
  legacyEncrypt,
  listKeyring,
  readKeyFile,
  readKeyFromRing,
  seal,
  unseal,
  unwrap,
  writeKeyFile,
  writeKeyToRing,
  type CipherName,
} from './index.js';

const USAGE = `cmsg — AES message encryption

USAGE
  cmsg <command> [options]

COMMANDS
  encrypt           Encrypt to an authenticated CMSG1 envelope (recommended)
  decrypt           Verify and decrypt a CMSG1 envelope
  inspect           Show an envelope's parameters without decrypting
  keygen            Create a new random key file
  fingerprint       Print a key's short public fingerprint
  keyring-list      List keys in a keyring directory
  legacy-encrypt    Encrypt exactly like aesencryption.net (no integrity)
  legacy-decrypt    Decrypt aesencryption.net ciphertext
  help              Show this text

COMMON OPTIONS
  --in PATH              Read input from PATH (default: stdin)
  --out PATH             Write output to PATH (default: stdout)
  --key-file PATH        Raw 16/24/32-byte key file (or hex key file)
  --keyring DIR          Keyring directory, used with --kid
  --kid ID               Key identifier inside --keyring
  --passphrase-file PATH Read a passphrase from a file (first line)
  --cipher NAME          AES-128-CBC | AES-192-CBC | AES-256-CBC (default AES-256-CBC)

ENCRYPT OPTIONS
  --aad-file PATH        Bind this extra data into the authentication tag
  --timestamp            Authenticate the creation time into the header
  --iterations N         PBKDF2 rounds for passphrase mode (default ${DEFAULT_PBKDF2_ITERATIONS})

DECRYPT OPTIONS
  --aad-file PATH        Require this associated data to match
  --max-age SECONDS      Reject messages older than this (needs --timestamp)

KEYGEN OPTIONS
  --out PATH             Where to write the key (required)
  --key-bits N           128 | 192 | 256 (default 256)
  --hex                  Write as a hex string instead of raw bytes

LEGACY OPTIONS
  --key TEXT             The password exactly as typed on the website
  --key-file PATH        Alternative to --key
  --bits N               128 | 192 | 256 (default 256)

EXAMPLES
  cmsg keygen --out alice.key
  echo "meet at 9" | cmsg encrypt --key-file alice.key > m.cmsg
  cmsg decrypt --key-file alice.key --in m.cmsg
  cmsg legacy-encrypt --key "encryptor key" <<< "My text to encrypt."
  cmsg inspect --in m.cmsg

NOTES
  v2 (encrypt/decrypt) is authenticated: tampering, a wrong key, and truncated
  messages are all rejected. It uses a random IV per message and separate
  encryption/MAC keys derived with HKDF.
  legacy-* reproduces the website byte for byte. It has a fixed IV, no key
  stretching and no integrity check — use it only to interoperate or recover.
`;

interface Args {
  readonly command: string;
  readonly flags: Map<string, string | true>;
  readonly positional: string[];
}

const VALUE_FLAGS = new Set([
  'in',
  'out',
  'key-file',
  'keyring',
  'kid',
  'passphrase-file',
  'cipher',
  'aad-file',
  'iterations',
  'max-age',
  'key-bits',
  'key-bits-out',
  'bits',
  'key',
  'text',
]);

const BOOLEAN_FLAGS = new Set(['hex', 'timestamp', 'raw', 'verbose', 'strict']);

function parseArgs(argv: readonly string[]): Args {
  const flags = new Map<string, string | true>();
  const positional: string[] = [];
  let command = 'help';

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--help' || a === '-h') {
      flags.set('help', true);
      continue;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      if (eq !== -1) {
        flags.set(name, a.slice(eq + 1));
        continue;
      }
      if (BOOLEAN_FLAGS.has(name)) {
        flags.set(name, true);
        continue;
      }
      if (VALUE_FLAGS.has(name)) {
        const next = argv[i + 1];
        if (next === undefined) throw new CryptoMessageError('MALFORMED_PARAMETER', `--${name} needs a value`);
        flags.set(name, next);
        i++;
        continue;
      }
      throw new CryptoMessageError('MALFORMED_PARAMETER', `unknown option --${name}`);
    }
    if (command === 'help' && positional.length === 0) {
      command = a;
    } else {
      positional.push(a);
    }
  }
  return { command, flags, positional };
}

function str(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === 'string' ? v : undefined;
}

function num(args: Args, name: string): number | undefined {
  const v = str(args, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new CryptoMessageError('MALFORMED_PARAMETER', `--${name} must be an integer (got ${v})`);
  }
  return n;
}

function has(args: Args, name: string): boolean {
  return args.flags.get(name) === true;
}

function readInput(args: Args, extraTextFlag?: string): Buffer {
  const extra = extraTextFlag ? str(args, extraTextFlag) : undefined;
  if (extra !== undefined) return Buffer.from(extra, 'utf8');
  const p = str(args, 'in');
  if (p !== undefined) return readFileSync(resolve(p));
  const pos = args.positional[0];
  if (pos !== undefined && args.command !== 'help') return Buffer.from(pos, 'utf8');
  return readFileSync(0);
}

function emit(args: Args, data: string | Uint8Array, binary = false): void {
  const out = str(args, 'out');
  if (out === undefined) {
    if (binary) process.stdout.write(Buffer.from(data as Uint8Array));
    else process.stdout.write(typeof data === 'string' ? (data.endsWith('\n') ? data : `${data}\n`) : data);
    return;
  }
  const abs = resolve(out);
  writeFileSync(abs, binary ? Buffer.from(data as Uint8Array) : data, { mode: 0o600 });
  process.stderr.write(`wrote ${binary ? (data as Uint8Array).length : String(data).length} bytes to ${abs}\n`);
}

function readPassphrase(args: Args): string | undefined {
  const p = str(args, 'passphrase-file');
  if (p === undefined) return undefined;
  const raw = readFileSync(resolve(p), 'utf8');
  const first = raw.split(/\r?\n/, 1)[0] ?? '';
  if (first.length === 0) {
    throw new CryptoMessageError('BAD_PASSWORD', `passphrase file ${p} is empty`);
  }
  return first;
}

/** Load key material from --key-file, or --kid inside --keyring. */
function loadKey(args: Args): Uint8Array | undefined {
  const keyFile = str(args, 'key-file');
  const kid = str(args, 'kid');
  const ring = str(args, 'keyring');

  if (keyFile !== undefined && kid !== undefined) {
    throw new CryptoMessageError('MALFORMED_PARAMETER', 'use either --key-file or --kid with --keyring, not both');
  }
  if (kid !== undefined) {
    if (ring === undefined) throw new CryptoMessageError('MALFORMED_PARAMETER', '--kid requires --keyring DIR');
    return unwrap(readKeyFromRing(ring, kid));
  }
  if (keyFile !== undefined) return unwrap(readKeyFile(keyFile));

  const envKey = process.env['CMSG_KEY'];
  if (envKey !== undefined && envKey.length > 0) {
    if (/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{48}$|^[0-9a-fA-F]{64}$/.test(envKey)) {
      return new Uint8Array(Buffer.from(envKey, 'hex'));
    }
    throw new CryptoMessageError(
      'BAD_KEY_LENGTH',
      'CMSG_KEY must be hex (32, 48 or 64 characters). Prefer --key-file: environment variables leak.',
    );
  }

  // Fall back to the keyring default location.
  if (ring !== undefined) {
    const keys = unwrap(listKeyring(ring));
    if (keys.length === 1) return unwrap(readKeyFromRing(ring, keys[0]!));
    throw new CryptoMessageError(
      'UNKNOWN_RECIPIENT',
      keys.length === 0 ? `no keys in ${resolve(ring)}` : `several keys in ${resolve(ring)}; pass --kid`,
    );
  }
  return undefined;
}

function keyOrPassphrase(args: Args): { key?: Uint8Array; passphrase?: string } {
  const key = loadKey(args);
  const passphrase = readPassphrase(args);
  if (key !== undefined && passphrase !== undefined) {
    throw new CryptoMessageError('MALFORMED_PARAMETER', 'use either a key or a passphrase, not both');
  }
  if (key === undefined && passphrase === undefined) {
    throw new CryptoMessageError(
      'BAD_PASSWORD',
      'no key material: pass --key-file PATH, or --kid with --keyring, or --passphrase-file PATH',
    );
  }
  return key !== undefined ? { key } : { passphrase: passphrase! };
}

function cmdEncrypt(args: Args): number {
  const plaintext = readInput(args);
  const material = keyOrPassphrase(args);
  const aadFile = str(args, 'aad-file');
  const aad = aadFile === undefined ? undefined : new Uint8Array(readFileSync(resolve(aadFile)));

  const env = unwrap(
    seal(plaintext, {
      ...material,
      cipher: (str(args, 'cipher') as CipherName | undefined) ?? 'AES-256-CBC',
      ...(aad === undefined ? {} : { aad }),
      ...(str(args, 'kid') === undefined ? {} : { kid: str(args, 'kid')! }),
      ...(has(args, 'timestamp') ? { includeTimestamp: true } : {}),
      ...(num(args, 'iterations') === undefined ? {} : { iterations: num(args, 'iterations')! }),
    }),
  );
  emit(args, env);
  return 0;
}

function cmdDecrypt(args: Args): number {
  const input = readInput(args).toString('utf8');
  const material = keyOrPassphrase(args);
  const aadFile = str(args, 'aad-file');
  const aad = aadFile === undefined ? undefined : new Uint8Array(readFileSync(resolve(aadFile)));
  const maxAge = num(args, 'max-age');

  const opened = unwrap(
    unseal(input, {
      ...material,
      ...(aad === undefined ? {} : { expectAad: aad }),
      ...(maxAge === undefined ? {} : { maxAgeSeconds: maxAge }),
    }),
  );

  if (has(args, 'verbose')) {
    process.stderr.write(
      [
        `cipher     : ${opened.info.cipher}`,
        `kdf        : ${opened.info.kdf}`,
        ...(opened.info.iterations === undefined ? [] : [`iterations : ${opened.info.iterations}`]),
        ...(opened.info.kid === undefined ? [] : [`key id     : ${opened.info.kid}`]),
        ...(opened.info.createdAt === undefined
          ? []
          : [`created    : ${new Date(opened.info.createdAt * 1000).toISOString()}`]),
        `aad bytes  : ${opened.aad.length}`,
        '',
      ].join('\n'),
    );
  }

  emit(args, has(args, 'raw') ? opened.plaintext : opened.text, has(args, 'raw'));
  return 0;
}

function cmdInspect(args: Args): number {
  const input = readInput(args).toString('utf8');
  const info = unwrap(inspect(input));
  const lines = [
    `version     : ${info.version}`,
    `algorithm   : ${info.algorithm}`,
    `cipher      : ${info.cipher} (${info.keyBits}-bit)`,
    `kdf         : ${info.kdf}`,
    ...(info.iterations === undefined ? [] : [`iterations  : ${info.iterations}`]),
    `salt bytes  : ${info.saltBytes}`,
    `ciphertext  : ${info.ciphertextBytes} bytes`,
    `tag         : ${info.tagBytes} bytes (HMAC-SHA256)`,
    ...(info.kid === undefined ? [] : [`key id      : ${info.kid}`]),
    ...(info.createdAt === undefined
      ? []
      : [`created     : ${new Date(info.createdAt * 1000).toISOString()}`]),
    '',
    'structure verified; NOT authenticated (no key supplied).',
  ];
  emit(args, lines.join('\n'));
  return 0;
}

function cmdKeygen(args: Args): number {
  const out = str(args, 'out');
  if (out === undefined) throw new CryptoMessageError('MALFORMED_PARAMETER', 'keygen requires --out PATH');
  const bits = num(args, 'key-bits') ?? 256;
  const key = unwrap(generateKey(bits));
  const kid = str(args, 'kid');
  const ring = str(args, 'keyring');

  const written = kid !== undefined && ring !== undefined
    ? unwrap(writeKeyToRing(ring, kid, key, has(args, 'hex')))
    : unwrap(writeKeyFile(out, key, has(args, 'hex')));

  process.stderr.write(
    [
      `key written : ${written}`,
      `key size    : ${bits} bit`,
      `fingerprint : ${keyFingerprint(key)}`,
      '',
      'Share the fingerprint out of band and compare it with your recipient.',
      'Never send the key file itself over the same channel as the message.',
      '',
    ].join('\n'),
  );
  return 0;
}

function cmdFingerprint(args: Args): number {
  const key = loadKey(args);
  if (key === undefined) throw new CryptoMessageError('BAD_PASSWORD', 'fingerprint needs --key-file or --kid/--keyring');
  emit(args, keyFingerprint(key));
  return 0;
}

function cmdKeyringList(args: Args): number {
  const ring = str(args, 'keyring');
  if (ring === undefined) throw new CryptoMessageError('MALFORMED_PARAMETER', 'keyring-list needs --keyring DIR');
  const keys = unwrap(listKeyring(ring));
  emit(args, keys.length === 0 ? '(empty keyring)' : keys.join('\n'));
  return 0;
}

function legacyMaterial(args: Args): string {
  const direct = str(args, 'key');
  if (direct !== undefined) return direct;
  const file = str(args, 'key-file');
  if (file !== undefined) return readFileSync(resolve(file), 'utf8').replace(/\r?\n$/, '');
  const pass = str(args, 'passphrase-file');
  if (pass !== undefined) return readPassphrase(args)!;
  throw new CryptoMessageError('BAD_PASSWORD', 'legacy mode needs --key TEXT (or --key-file)');
}

function legacyBits(args: Args): 128 | 192 | 256 {
  const bits = num(args, 'bits') ?? 256;
  if (bits !== 128 && bits !== 192 && bits !== 256) {
    throw new CryptoMessageError('BAD_KEY_LENGTH', `--bits must be 128, 192 or 256 (got ${bits})`);
  }
  return bits;
}

function cmdLegacyEncrypt(args: Args): number {
  const text = readInput(args, 'text').toString('utf8');
  const password = legacyMaterial(args);
  emit(args, legacyEncrypt(text, password, legacyBits(args)));
  return 0;
}

function cmdLegacyDecrypt(args: Args): number {
  const input = readInput(args).toString('utf8');
  const password = legacyMaterial(args);
  const bits = legacyBits(args);

  const diag = legacyDecryptDiagnostic(input, password, bits);
  if (!diag.paddingValid && !has(args, 'strict')) {
    // Report the likely cause instead of emitting mojibake silently.
    throw new CryptoMessageError(
      'INTEGRITY_FAILURE',
      'decryption failed the padding check: wrong key, wrong key size, or corrupted ciphertext. ' +
        'The legacy format has no integrity check, so a failure here is only a heuristic.',
    );
  }
  if (process.env['CMSG_LEGACY_STRICT'] === '1' || has(args, 'strict')) {
    emit(args, legacyDecrypt(input, password, bits));
    return 0;
  }
  emit(args, diag.text);
  return 0;
}

function main(argv: readonly string[]): number {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n\n${USAGE}`);
    return 2;
  }

  if (has(args, 'help') || args.command === 'help' || args.command === '--help') {
    process.stdout.write(USAGE);
    return 0;
  }

  try {
    switch (args.command) {
      case 'encrypt':
        return cmdEncrypt(args);
      case 'decrypt':
        return cmdDecrypt(args);
      case 'inspect':
        return cmdInspect(args);
      case 'keygen':
        return cmdKeygen(args);
      case 'fingerprint':
        return cmdFingerprint(args);
      case 'keyring-list':
        return cmdKeyringList(args);
      case 'legacy-encrypt':
        return cmdLegacyEncrypt(args);
      case 'legacy-decrypt':
        return cmdLegacyDecrypt(args);
      default:
        process.stderr.write(`error: unknown command ${JSON.stringify(args.command)}\n\n${USAGE}`);
        return 2;
    }
  } catch (err) {
    if (err instanceof CryptoMessageError) {
      process.stderr.write(`error [${err.code}]: ${err.message}\n`);
      return 1;
    }
    if (err instanceof Error) {
      process.stderr.write(`error: ${err.message}\n`);
      if (has(args, 'verbose')) process.stderr.write(`${err.stack ?? ''}\n`);
      return 1;
    }
    process.stderr.write(`error: ${String(err)}\n`);
    return 1;
  }
}

process.exitCode = main(process.argv.slice(2));
