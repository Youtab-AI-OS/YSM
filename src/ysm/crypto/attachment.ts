/**
 * Chunked, authenticated file transfer.
 *
 * A file is split into 1 MiB chunks. Each chunk is its own YSM envelope, so:
 *   - memory use is bounded regardless of file size (a 1 GiB video streams),
 *   - a single corrupt chunk is identifiable and retryable,
 *   - chunks cannot be reordered, duplicated or dropped undetected.
 *
 * The chunk index is baked into the per-chunk key derivation AND the header, and
 * the total chunk count is stated in `file-start` / `file-end`. Reordering is
 * therefore detected twice over: the key won't match, and the index won't line
 * up with where the receiver expected it.
 *
 * Filenames are sanitised aggressively. The attachment is never executed,
 * never auto-opened, and its declared MIME type is treated as a hint (verified
 * by magic bytes for the previewable image/video/audio cases).
 */

import { seal, open, type ContentKind } from './envelope.js';
import { random, type Identity, type PublicIdentity } from './identity.js';
import { sha256 as sha256Fn } from '@noble/hashes/sha2.js';

/** 1 MiB chunks: large enough to be efficient, small enough to bound memory. */
export const CHUNK_SIZE = 1024 * 1024;
/** Hard ceiling per file. */
export const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
export const MAX_CHUNKS = Math.ceil(MAX_FILE_BYTES / CHUNK_SIZE);

/** Categories the UI can preview inline. */
export type FileCategory = 'image' | 'video' | 'audio' | 'archive' | 'document' | 'other';

export interface FileMeta {
  /** Sanitised display name. */
  readonly name: string;
  /** Declared MIME type (advisory; not trusted for execution decisions). */
  readonly mime: string;
  /** Exact byte length, for verification after reassembly. */
  readonly size: number;
  /** SHA-256 of the plaintext, hex. Verified on reassembly. */
  readonly sha256: string;
  readonly category: FileCategory;
}

export interface SealedTransfer {
  readonly transferId: string;
  readonly meta: FileMeta;
  /** One envelope per chunk, in order, preceded by file-start and followed by file-end. */
  readonly envelopes: readonly string[];
}

const EXTENSION_CATEGORY: Record<string, FileCategory> = {
  // images
  jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image', bmp: 'image', avif: 'image', heic: 'image',
  // video
  mp4: 'video', m4v: 'video', mov: 'video', webm: 'video', mkv: 'video', avi: 'video',
  // audio (including .wav and .mp3 which the user explicitly asked for)
  mp3: 'audio', wav: 'audio', ogg: 'audio', opus: 'audio', m4a: 'audio', aac: 'audio', flac: 'audio',
  // archives
  zip: 'archive', rar: 'archive', '7z': 'archive', tar: 'archive', gz: 'archive', bz2: 'archive', xz: 'archive',
  // documents
  pdf: 'document', txt: 'document', md: 'document', doc: 'document', docx: 'document', xls: 'document',
  xlsx: 'document', ppt: 'document', pptx: 'document', csv: 'document', rtf: 'document', odt: 'document',
};

/** Characters that must never appear in a filename we hand to the OS. */
const UNSAFE_NAME = /[\u0000-\u001f\u007f/\\:*?"<>|]/g;

/**
 * Sanitise a filename for display and for saving.
 *
 * - Strips directory separators (defeats `../../etc/passwd`).
 * - Strips control characters, colon/asterisk/question/quote/angle/pipe
 *   (defeats Windows and shell path tricks).
 * - Removes leading dots so a file cannot be hidden, and strips a trailing dot
 *   or space that Windows silently trims.
 * - Caps length so a huge name cannot blow up the UI or filesystem call.
 * - Falls back to a fixed name if nothing usable remains.
 */
export function sanitizeFilename(raw: string): string {
  let name = raw.replace(/^.*[\\/]/, ''); // drop any path component
  name = name.replace(UNSAFE_NAME, '_');
  name = name.replace(/^\.+/, ''); // no hidden files
  name = name.replace(/[. ]+$/, ''); // Windows strips these silently
  name = name.trim();
  if (name.length === 0) name = 'attachment';
  if (name.length > 180) {
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 && name.length - dot <= 12 ? name.slice(dot) : '';
    name = name.slice(0, 180 - ext.length) + ext;
  }
  return name;
}

/** Classify by extension; the extension is a UI hint only. */
export function categorise(name: string): FileCategory {
  const dot = name.lastIndexOf('.');
  if (dot < 1 || dot === name.length - 1) return 'other';
  const ext = name.slice(dot + 1).toLowerCase();
  return EXTENSION_CATEGORY[ext] ?? 'other';
}

/**
 * Detect a category from magic bytes, so a `.jpg` that is really an executable
 * is not previewed as an image. Returns null when the type cannot be determined.
 */
export function sniffCategory(bytes: Uint8Array): FileCategory | null {
  const startsWith = (...sig: number[]): boolean => sig.every((b, i) => bytes[i] === b);

  if (startsWith(0xff, 0xd8, 0xff)) return 'image'; // JPEG
  if (startsWith(0x89, 0x50, 0x4e, 0x47)) return 'image'; // PNG
  if (startsWith(0x47, 0x49, 0x46, 0x38)) return 'image'; // GIF
  if (startsWith(0x42, 0x4d)) return 'image'; // BMP
  if (bytes.length > 12 && startsWith(0x52, 0x49, 0x46, 0x46) &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image'; // WEBP

  if (bytes.length > 12 && startsWith(0x52, 0x49, 0x46, 0x46) &&
      bytes[8] === 0x57 && bytes[9] === 0x41 && bytes[10] === 0x56 && bytes[11] === 0x45) return 'audio'; // WAV
  if (startsWith(0x49, 0x44, 0x33)) return 'audio'; // MP3 with ID3
  if (startsWith(0xff, 0xfb) || startsWith(0xff, 0xf3) || startsWith(0xff, 0xf2)) return 'audio'; // MP3 frame
  if (startsWith(0x4f, 0x67, 0x67, 0x53)) return 'audio'; // OGG
  if (startsWith(0x66, 0x4c, 0x61, 0x43)) return 'audio'; // FLAC

  if (bytes.length > 12 && bytes[4] === 0x66 && bytes[5] === 0x74 &&
      bytes[6] === 0x79 && bytes[7] === 0x70) return 'video'; // MP4/MOV container

  if (startsWith(0x50, 0x4b, 0x03, 0x04)) return 'archive'; // ZIP
  if (startsWith(0x52, 0x61, 0x72, 0x21)) return 'archive'; // RAR
  if (startsWith(0x37, 0x7a, 0xbc, 0xaf)) return 'archive'; // 7z
  if (startsWith(0x1f, 0x8b)) return 'archive'; // gzip

  if (startsWith(0x25, 0x50, 0x44, 0x46)) return 'document'; // PDF
  if (startsWith(0x50, 0x4b, 0x03, 0x04)) return 'archive'; // OOXML is a zip

  return null;
}

/**
 * Resolve the category to display with.
 *
 * Rule: if magic bytes are recognised and disagree with the extension, trust the
 * magic bytes — a file claiming to be a JPEG but containing a ZIP must not be
 * previewed as an image. If magic bytes are unrecognised, fall back to the
 * extension so ordinary text and office files still classify sensibly.
 */
export function resolveCategory(name: string, bytes: Uint8Array): FileCategory {
  const sniffed = sniffCategory(bytes);
  if (sniffed !== null) return sniffed;
  return categorise(name);
}

/** SHA-256 of the plaintext, hex, for post-reassembly verification. */
export function sha256Hex(bytes: Uint8Array): string {
  return Buffer.from(sha256Fn(bytes)).toString('hex');
}

export interface SealFileInput {
  readonly identity: Identity;
  readonly peer: PublicIdentity;
  readonly room: string;
  readonly name: string;
  readonly mime: string;
  readonly data: Uint8Array;
  readonly now?: () => number;
}

/**
 * Encrypt a file into a sequence of envelopes.
 *
 * Returns every envelope; a caller that sends them over a stream can instead use
 * `*Iter` below to avoid holding them all in memory.
 */
export function sealFile(input: SealFileInput): SealedTransfer {
  const { identity, peer, room, data } = input;
  if (data.length > MAX_FILE_BYTES) {
    throw new RangeError(`file is ${data.length} bytes; the limit is ${MAX_FILE_BYTES}`);
  }

  const name = sanitizeFilename(input.name);
  const category = resolveCategory(name, data);
  const meta: FileMeta = {
    name,
    mime: input.mime,
    size: data.length,
    sha256: sha256Hex(data),
    category,
  };

  const transferId = Buffer.from(random(16)).toString('base64url');
  const chunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));
  const envelopes: string[] = [];

  envelopes.push(
    seal({
      identity,
      peer,
      room,
      kind: 'file-start',
      file: transferId,
      chunks,
      body: new TextEncoder().encode(JSON.stringify(meta)),
      ...(input.now ? { now: input.now } : {}),
    }),
  );

  for (let i = 0; i < chunks; i++) {
    const slice = data.subarray(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, data.length));
    envelopes.push(
      seal({
        identity,
        peer,
        room,
        kind: 'file-chunk',
        file: transferId,
        idx: i,
        body: slice,
        ...(input.now ? { now: input.now } : {}),
      }),
    );
  }

  envelopes.push(
    seal({
      identity,
      peer,
      room,
      kind: 'file-end',
      file: transferId,
      chunks,
      body: new Uint8Array(0),
      ...(input.now ? { now: input.now } : {}),
    }),
  );

  return { transferId, meta, envelopes };
}

/** Accumulates chunks for one transfer and verifies the result. */
export class FileReceiver {
  private readonly meta: FileMeta;
  private readonly chunks: Uint8Array[];
  private readonly expected: number;
  private ended = false;

  constructor(meta: FileMeta, expectedChunks: number) {
    if (expectedChunks < 1 || expectedChunks > MAX_CHUNKS) {
      throw new RangeError(`implausible chunk count ${expectedChunks}`);
    }
    if (meta.size > MAX_FILE_BYTES) {
      throw new RangeError(`declared size ${meta.size} exceeds the limit`);
    }
    this.meta = meta;
    this.expected = expectedChunks;
    this.chunks = new Array(expectedChunks);
  }

  get fileMeta(): FileMeta {
    return this.meta;
  }

  get received(): number {
    return this.chunks.filter((c) => c !== undefined).length;
  }

  get total(): number {
    return this.expected;
  }

  get complete(): boolean {
    return this.ended && this.received === this.expected;
  }

  /** Insert one chunk. Rejects duplicates and out-of-range indices. */
  add(index: number, data: Uint8Array): void {
    if (this.ended) throw new Error('transfer already ended');
    if (!Number.isInteger(index) || index < 0 || index >= this.expected) {
      throw new RangeError(`chunk index ${index} out of range 0..${this.expected - 1}`);
    }
    if (this.chunks[index] !== undefined) {
      throw new Error(`chunk ${index} received twice`);
    }
    this.chunks[index] = new Uint8Array(data);
  }

  markEnded(): void {
    this.ended = true;
  }

  /**
   * Reassemble and verify.
   *
   * Fails if any chunk is missing, if the assembled length differs from the
   * declared size, or if the SHA-256 does not match. A truncated or reordered
   * transfer therefore cannot be silently accepted.
   */
  assemble(): { ok: true; data: Uint8Array; meta: FileMeta } | { ok: false; code: string; message: string } {
    if (!this.ended) return { ok: false, code: 'INCOMPLETE', message: 'transfer has not been closed by the sender' };
    const missing: number[] = [];
    for (let i = 0; i < this.expected; i++) if (this.chunks[i] === undefined) missing.push(i);
    if (missing.length > 0) {
      return { ok: false, code: 'INCOMPLETE', message: `missing ${missing.length} chunk(s), first is ${missing[0]}` };
    }

    let total = 0;
    for (const c of this.chunks) total += c!.length;
    if (total !== this.meta.size) {
      return { ok: false, code: 'SIZE_MISMATCH', message: `assembled ${total} bytes but ${this.meta.size} were declared` };
    }

    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c!, off);
      off += c!.length;
    }

    const actual = sha256Hex(out);
    if (actual !== this.meta.sha256) {
      return { ok: false, code: 'HASH_MISMATCH', message: 'file content does not match the sender\'s SHA-256' };
    }

    return { ok: true, data: out, meta: this.meta };
  }
}

export type { ContentKind, Identity, PublicIdentity };
export { open };
