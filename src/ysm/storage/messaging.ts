/**
 * The messaging service: send and receive, backed by the encrypted store.
 *
 * Responsibilities kept here (and nowhere else):
 *   - turning a composed message into signed, encrypted envelopes
 *   - storing the local copy encrypted, with outbound envelopes for transport
 *   - accepting inbound envelopes: verify, decrypt, store, attribute
 *
 * Attribution rules, which are the whole point of signing:
 *   - an inbound envelope must verify against the signing key in its header
 *   - that signing key must match the contact we have stored for this room
 *   - a mismatch is surfaced as a warning, never silently accepted
 */

import { open, seal, b64u, type ContentKind } from '../crypto/envelope.js';
import { FileReceiver, sealFile, type FileMeta } from '../crypto/attachment.js';
import { getContact, newId, type StoredContact } from './contacts.js';
import { withTransaction } from './sql.js';
import type { Vault } from './vault.js';

/**
 * How a message is stored locally. Deliberately distinct from the wire-level
 * `ContentKind`: a file arrives as file-start/chunk/end envelopes but is stored
 * as a single 'file' message.
 */
export type StoredKind = 'text' | 'file' | 'file-start' | 'file-chunk';

export interface StoredMessage {
  readonly id: string;
  readonly roomId: string;
  readonly senderId: string;
  readonly direction: 'in' | 'out';
  readonly sentAt: number;
  readonly text: string;
  readonly kind: StoredKind;
  /** Set when this message carries a file. */
  readonly transferId?: string;
}

export interface OutgoingMessage {
  readonly messageId: string;
  readonly roomId: string;
  /** Envelopes to hand to transport, in order. One for text, many for a file. */
  readonly envelopes: readonly string[];
  readonly stored: StoredMessage;
}

export interface SendTextInput {
  readonly vault: Vault;
  readonly roomId: string;
  readonly contactId: string;
  readonly text: string;
  readonly now?: () => number;
}

/**
 * Send a text message.
 *
 * The text is encrypted into one envelope for the peer and stored locally as
 * plaintext-in-the-vault (i.e. encrypted with the vault key) so the sender can
 * read their own history without re-deriving peer keys.
 */
export function sendText(input: SendTextInput): OutgoingMessage {
  const { vault, roomId, contactId, text } = input;
  if (text.length === 0) throw new Error('message is empty');
  if (text.length > 64 * 1024) throw new Error('message is too long; send it as a file');

  const contact = getContact(vault, contactId);
  if (contact === null) throw new Error(`unknown contact ${contactId}`);

  const now = input.now ?? Date.now;
  const envelope = seal({
    identity: vault.identity,
    peer: { agreement: contact.agreement, signing: contact.signing },
    room: roomId,
    kind: 'text',
    body: new TextEncoder().encode(text),
    now,
  });

  const messageId = newId();
  vault.database
    .prepare(
      `INSERT INTO messages (id, room_id, sender_id, direction, sent_at, body, kind)
       VALUES (?, ?, 'self', 'out', ?, ?, 'text')`,
    )
    .run(messageId, roomId, now(), vault.cipher.encryptText(text, 'messages.body'));

  return {
    messageId,
    roomId,
    envelopes: [envelope],
    stored: { id: messageId, roomId, senderId: 'self', direction: 'out', sentAt: now(), text, kind: 'text' },
  };
}

export interface SendFileInput {
  readonly vault: Vault;
  readonly roomId: string;
  readonly contactId: string;
  readonly name: string;
  readonly mime: string;
  readonly data: Uint8Array;
  readonly now?: () => number;
}

/**
 * Send a file: photo, video, audio, archive, document — anything.
 *
 * The file is chunked and each chunk is its own signed envelope, so a large
 * video streams without loading the whole thing into a single message.
 */
export function sendFile(input: SendFileInput): OutgoingMessage {
  const { vault, roomId, contactId, data } = input;
  const contact = getContact(vault, contactId);
  if (contact === null) throw new Error(`unknown contact ${contactId}`);

  const now = input.now ?? Date.now;
  const sealed = sealFile({
    identity: vault.identity,
    peer: { agreement: contact.agreement, signing: contact.signing },
    room: roomId,
    name: input.name,
    mime: input.mime,
    data,
    now,
  });

  const messageId = newId();
  const db = vault.database;

  withTransaction(db, () => {
    db.prepare(
      `INSERT INTO messages (id, room_id, sender_id, direction, sent_at, body, kind)
       VALUES (?, ?, 'self', 'out', ?, ?, 'file')`,
    ).run(messageId, roomId, now(), vault.cipher.encryptText(sealed.meta.name, 'messages.body'));

    db.prepare(
      `INSERT INTO transfers (id, message_id, name, mime, size, sha256, category, chunks, received, data, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'complete')`,
    ).run(
      sealed.transferId,
      messageId,
      vault.cipher.encryptText(sealed.meta.name, 'transfers.name'),
      sealed.meta.mime,
      sealed.meta.size,
      sealed.meta.sha256,
      sealed.meta.category,
      sealed.envelopes.length,
      sealed.envelopes.length,
      vault.cipher.encryptBytes(data, 'transfers.data'),
    );
  });

  return {
    messageId,
    roomId,
    envelopes: sealed.envelopes,
    stored: {
      id: messageId,
      roomId,
      senderId: 'self',
      direction: 'out',
      sentAt: now(),
      text: sealed.meta.name,
      kind: 'file',
      transferId: sealed.transferId,
    },
  };
}

export type ReceiveResult =
  | { ok: true; message: StoredMessage; warning?: string }
  | { ok: false; code: string; message: string };

/** Pending inbound file transfers, keyed by transfer id. */
const pendingTransfers = new Map<string, { receiver: FileReceiver; messageId: string; roomId: string; senderId: string }>();

/**
 * Receive one envelope.
 *
 * A file arrives as several envelopes; this accumulates them and emits a single
 * stored message when the transfer completes. Chunks are dropped (with an error)
 * if anything about them does not line up.
 */
export function receive(vault: Vault, envelopeText: string, now: () => number = Date.now): ReceiveResult {
  const opened = open(envelopeText, vault.identity);
  if (!opened.ok) return { ok: false, code: opened.code, message: opened.message };

  const header = opened.header;
  if (header.room.length === 0) return { ok: false, code: 'INVALID_FORMAT', message: 'envelope has no room' };

  // Attribution: does the signing key belong to a contact we know?
  const senderId = Buffer.from(opened.sender.agreement).toString('hex');
  const contact = getContact(vault, senderId);
  let warning: string | undefined;
  if (contact === null) {
    warning = 'message from an unknown sender; add them as a contact to reply';
  } else if (!Buffer.from(contact.signing).equals(Buffer.from(opened.sender.signing))) {
    // Same agreement key but a different signing key: either the sender rotated
    // their signing key, or this is an attempt to impersonate them.
    return {
      ok: false,
      code: 'KEY_MISMATCH',
      message: 'the signing key in this message does not match the stored contact — refusing until re-verified',
    };
  }

  const db = vault.database;

  if (header.kind === 'text') {
    // Replay defence: the message id comes from the signed `mid` in the header,
    // not from a fresh random value. Importing the same envelope twice must be a
    // no-op, not a second message. `mid` is covered by the signature, so it cannot
    // be changed to evade the check.
    const existing = db.prepare('SELECT id FROM messages WHERE id = ?').get(header.mid);
    if (existing !== undefined) {
      return {
        ok: false,
        code: 'DUPLICATE',
        message: 'this message has already been received',
      };
    }
    const text = new TextDecoder().decode(opened.body);
    const id = header.mid;
    db.prepare(
      `INSERT INTO messages (id, room_id, sender_id, direction, sent_at, body, kind)
       VALUES (?, ?, ?, 'in', ?, ?, 'text')`,
    ).run(id, header.room, senderId, now(), vault.cipher.encryptText(text, 'messages.body'));
    const msg: StoredMessage = {
      id, roomId: header.room, senderId, direction: 'in', sentAt: now(), text, kind: 'text',
    };
    return warning === undefined ? { ok: true, message: msg } : { ok: true, message: msg, warning };
  }

  if (header.kind === 'file-start') {
    if (header.file === undefined || header.chunks === undefined) {
      return { ok: false, code: 'INVALID_FORMAT', message: 'file-start envelope is missing transfer fields' };
    }
    let meta: FileMeta;
    try {
      meta = JSON.parse(new TextDecoder().decode(opened.body)) as FileMeta;
    } catch {
      return { ok: false, code: 'INVALID_FORMAT', message: 'file metadata is not valid JSON' };
    }
    const messageId = newId();

    // Replay defence for files: a repeated file-start must not create a second
    // receiver. Without this check, replaying [start, ...rest] silently replaced
    // the in-progress receiver and re-assembled from scratch, so a duplicated or
    // reordered transfer was accepted.
    if (pendingTransfers.has(header.file)) {
      return {
        ok: false,
        code: 'DUPLICATE',
        message: 'this transfer has already been started',
      };
    }

    let receiver: FileReceiver;
    try {
      receiver = new FileReceiver(meta, header.chunks);
    } catch (err) {
      return { ok: false, code: 'INVALID_FORMAT', message: (err as Error).message };
    }
    pendingTransfers.set(header.file, { receiver, messageId, roomId: header.room, senderId });
    return {
      ok: true,
      message: {
        id: messageId,
        roomId: header.room,
        senderId,
        direction: 'in',
        sentAt: now(),
        text: meta.name,
        kind: 'file-start',
        transferId: header.file,
      },
      ...(warning === undefined ? {} : { warning }),
    };
  }

  if (header.kind === 'file-chunk') {
    if (header.file === undefined || header.idx === undefined) {
      return { ok: false, code: 'INVALID_FORMAT', message: 'file-chunk envelope is missing transfer fields' };
    }
    const pending = pendingTransfers.get(header.file);
    if (pending === undefined) {
      return { ok: false, code: 'NO_TRANSFER', message: 'received a chunk for an unknown transfer' };
    }
    try {
      pending.receiver.add(header.idx, opened.body);
    } catch (err) {
      return { ok: false, code: 'BAD_CHUNK', message: (err as Error).message };
    }
    return {
      ok: true,
      message: {
        id: pending.messageId,
        roomId: header.room,
        senderId,
        direction: 'in',
        sentAt: now(),
        text: `${pending.receiver.received}/${pending.receiver.total}`,
        kind: 'file-chunk',
        transferId: header.file,
      },
    };
  }

  // file-end
  if (header.file === undefined) {
    return { ok: false, code: 'INVALID_FORMAT', message: 'file-end envelope is missing the transfer id' };
  }
  const pending = pendingTransfers.get(header.file);
  if (pending === undefined) {
    return { ok: false, code: 'NO_TRANSFER', message: 'received the end of an unknown transfer' };
  }
  pendingTransfers.delete(header.file);
  pending.receiver.markEnded();

  const assembled = pending.receiver.assemble();
  if (!assembled.ok) return { ok: false, code: assembled.code, message: assembled.message };

  const meta = assembled.meta;
  const id = pending.messageId;
  withTransaction(db, () => {
    db.prepare(
      `INSERT INTO messages (id, room_id, sender_id, direction, sent_at, body, kind)
       VALUES (?, ?, ?, 'in', ?, ?, 'file')`,
    ).run(id, header.room!, senderId, now(), vault.cipher.encryptText(meta.name, 'messages.body'));

    db.prepare(
      `INSERT INTO transfers (id, message_id, name, mime, size, sha256, category, chunks, received, data, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'complete')`,
    ).run(
      header.file!,
      id,
      vault.cipher.encryptText(meta.name, 'transfers.name'),
      meta.mime,
      meta.size,
      meta.sha256,
      meta.category,
      pending.receiver.total,
      pending.receiver.total,
      vault.cipher.encryptBytes(assembled.data, 'transfers.data'),
    );
  });

  const msg: StoredMessage = {
    id,
    roomId: header.room!,
    senderId,
    direction: 'in',
    sentAt: now(),
    text: meta.name,
    kind: 'file',
    transferId: header.file!,
  };
  return warning === undefined ? { ok: true, message: msg } : { ok: true, message: msg, warning };
}

/** List messages in a room, oldest first. */
export function listMessages(vault: Vault, roomId: string, limit = 500): StoredMessage[] {
  const rows = vault.database
    .prepare(
      `SELECT id, room_id, sender_id, direction, sent_at, body, kind
       FROM messages WHERE room_id = ? ORDER BY sent_at ASC, rowid ASC LIMIT ?`,
    )
    .all(roomId, limit) as Array<{
    id: string;
    room_id: string;
    sender_id: string;
    direction: 'in' | 'out';
    sent_at: number;
    body: Buffer;
    kind: StoredKind;
  }>;

  return rows.map((r) => {
    const transfer = vault.database.prepare('SELECT id FROM transfers WHERE message_id = ?').get(r.id) as
      | { id: string }
      | undefined;
    return {
      id: r.id,
      roomId: r.room_id,
      senderId: r.sender_id,
      direction: r.direction,
      sentAt: r.sent_at,
      text: vault.cipher.decryptText(r.body, 'messages.body'),
      kind: r.kind,
      ...(transfer === undefined ? {} : { transferId: transfer.id }),
    };
  });
}

export interface AttachmentRecord {
  readonly id: string;
  readonly name: string;
  readonly mime: string;
  readonly size: number;
  readonly category: FileMeta['category'];
  readonly sha256: string;
  readonly data: Uint8Array;
}

/** Load a stored attachment, decrypting it. */
export function loadAttachment(vault: Vault, transferId: string): AttachmentRecord | null {
  const row = vault.database
    .prepare('SELECT id, name, mime, size, category, sha256, data FROM transfers WHERE id = ?')
    .get(transferId) as
    | { id: string; name: Buffer; mime: string; size: number; category: FileMeta['category']; sha256: string; data: Buffer | null }
    | undefined;
  if (row === undefined || row.data === null) return null;
  return {
    id: row.id,
    name: vault.cipher.decryptText(row.name, 'transfers.name'),
    mime: row.mime,
    size: row.size,
    category: row.category,
    sha256: row.sha256,
    data: vault.cipher.decryptBytes(new Uint8Array(row.data), 'transfers.data'),
  };
}

export { b64u, type StoredContact };
