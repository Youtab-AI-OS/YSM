/**
 * The application service: implements every IPC operation.
 *
 * This module is deliberately free of Electron so it can be tested headlessly.
 * It receives plain data, returns plain data, and owns all vault state.
 *
 * Invariants enforced here:
 *   - No operation except account creation/unlock touches the vault, and every
 *     other operation fails cleanly when locked.
 *   - Secret key material never appears in a return value.
 *   - Anything the renderer sends is treated as untrusted and bounded.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, basename } from 'node:path';

import { Vault } from '../storage/vault.js';
import {
  addContact,
  createContactCard,
  createRoom,
  encodeCard,
  getContact,
  listContacts,
  listRooms,
  markVerified,
  parseCard,
  type StoredContact,
} from '../storage/contacts.js';
import {
  listMessages,
  loadAttachment,
  receive,
  sendFile,
  sendText,
  type StoredMessage,
} from '../storage/messaging.js';
import { hashRecoveryCode, base32Decode, verifyTotp } from '../crypto/auth.js';
import { sanitizeFilename } from '../crypto/attachment.js';
import {
  seal as sealPayloadBlock,
  open as openSealedBlock,
  generatePassphrase,
  looksLikeReference,
  packTransfer,
  unpackTransfer,
  packFile,
  type SealedBlob,
  unpackFile,
} from '../crypto/seal.js';
import { insertSealed, getSealed, listSealed, deleteSealed } from '../storage/sealed-store.js';
import { LOCALES, type Locale } from '../i18n/strings.js';
import type {
  UiAccountState,
  UiAttachment,
  UiContact,
  UiMessage,
  UiSealedCreated,
  UiSealedOpened,
  UiSealedSummary,
  UiOnboarding,
  UiResult,
  UiRoom,
} from '../ipc/contract.js';

export interface ServiceOptions {
  /** Directory holding the account database and exported files. */
  readonly dataDir: string;
  /** Injectable clock for tests. */
  readonly now?: () => number;
}

const DB_FILENAME = 'ysm-account.db';
const EXPORT_DIRNAME = 'exports';
/** Inline preview ceiling: previews are base64'd into the renderer, so bound them. */
const MAX_PREVIEW_BYTES = 24 * 1024 * 1024;

/** Auto-lock bounds, in seconds. See AppService.setAutoLock. */
export const MIN_AUTOLOCK_SECONDS = 30;
export const MAX_AUTOLOCK_SECONDS = 300;

/**
 * Sealed payload size limits.
 *
 * Argon2id is run over the passphrase, not the payload, so size is bounded by
 * memory and IPC bandwidth rather than by cost. 25 MB keeps a single payload
 * inside the renderer's base64 budget; larger files should be split or carried by
 * the chunked attachment path instead.
 */
const MAX_SEALED_BYTES = 25 * 1024 * 1024;
const MAX_SEALED_TEXT_BYTES = 256 * 1024;

export class AppService {
  private vault: Vault | null = null;
  private locale: Locale = 'en';
  private autoLockSeconds = 300;
  private lastActivity = 0;
  private readonly dataDir: string;
  private readonly now: () => number;

  constructor(opts: ServiceOptions) {
    this.dataDir = opts.dataDir;
    this.now = opts.now ?? Date.now;
    mkdirSync(this.dataDir, { recursive: true });
  }

  private get dbPath(): string {
    return join(this.dataDir, DB_FILENAME);
  }

  private get exportDir(): string {
    const dir = join(this.dataDir, EXPORT_DIRNAME);
    mkdirSync(dir, { recursive: true });
    return dir;
  }

  /**
   * Get the vault, or return the standard locked failure.
   *
   * Returns a result rather than throwing: every IPC handler returns a
   * `UiResult`, and an exception escaping a handler would surface to the
   * renderer as an opaque IPC error instead of a reportable code.
   */
  private requireVault(): { ok: true; vault: Vault } | { ok: false; code: string; message: string } {
    if (this.vault === null || !this.vault.isUnlocked) {
      return { ok: false, code: 'LOCKED', message: 'the vault is locked' };
    }
    this.lastActivity = this.now();
    return { ok: true, vault: this.vault };
  }

  /** Lock if the idle timeout has elapsed. Called before each operation. */
  private enforceAutoLock(): void {
    if (this.vault === null || !this.vault.isUnlocked) return;
    if (this.autoLockSeconds <= 0) return;
    if (this.lastActivity === 0) {
      this.lastActivity = this.now();
      return;
    }
    if (this.now() - this.lastActivity > this.autoLockSeconds * 1000) {
      this.vault.lock();
      this.vault = null;
    }
  }

  // -------------------------------------------------------------------
  // Account
  // -------------------------------------------------------------------

  accountState(): UiAccountState {
    this.enforceAutoLock();
    const exists = existsSync(this.dbPath);
    if (!exists || this.vault === null || !this.vault.isUnlocked) {
      return { exists, unlocked: false };
    }
    return {
      exists: true,
      unlocked: true,
      displayName: this.vault.displayName,
      contactCard: encodeCard(createContactCard(this.vault)),
      ownerPublicKey: Buffer.from(this.vault.publicIdentity.agreement).toString('hex'),
    };
  }

  /**
   * Account creation result.
   *
   * Deliberately *not* `UiOnboarding`: the QR matrix is added by the Electron main
   * process, which owns the encoder. The service stays free of that dependency so
   * it can be tested headlessly without Electron.
   */
  createAccount(displayName: string, password: string): UiResult<Omit<UiOnboarding, 'qr'>> {
    if (this.vault !== null) return err('ALREADY_UNLOCKED', 'lock the current account first');
    const result = Vault.create(this.dbPath, displayName, password);
    if (!result.ok) return err(result.code, result.message);
    // The vault is NOT kept unlocked here: the user must prove they can produce
    // a TOTP code before the account becomes usable. This prevents someone
    // creating an account, skipping 2FA enrolment, and being locked out of their
    // own data forever.
    result.vault.lock();
    this.pendingOnboarding = { secret: result.onboarding.totpSecretBase32 };
    // Held in memory only, for the short window between create and confirm. It is
    // cleared on confirm, on failure, and on lock.
    this.pendingPassword = password;
    return { ok: true, value: result.onboarding };
  }

  private pendingOnboarding: { secret: string } | null = null;
  private pendingPassword: string | null = null;

  /**
   * Confirm the authenticator works during onboarding, then unlock.
   *
   * Without this step a user could create an account, never scan the QR, and be
   * permanently locked out of their own data.
   */
  confirmOnboarding(totpCode: string): UiResult<{ displayName: string }> {
    if (this.pendingOnboarding === null) {
      return err('NO_PENDING', 'no account creation is in progress');
    }
    const secret = base32Decode(this.pendingOnboarding.secret);
    const check = verifyTotp(secret, totpCode, Math.floor(this.now() / 1000));
    if (!check.ok) {
      return err('BAD_TOTP', check.reason === 'FORMAT' ? 'code must be 6 digits' : 'incorrect authenticator code');
    }
    if (this.pendingPassword === null) {
      return err('NO_PENDING', 'account creation state was lost; unlock normally instead');
    }
    const unlock = Vault.unlock(this.dbPath, this.pendingPassword, totpCode, this.now);
    this.pendingPassword = null;
    if (!unlock.ok) return err(unlock.code, unlock.message);
    this.vault = unlock.vault;
    this.pendingOnboarding = null;
    this.lastActivity = this.now();
    return { ok: true, value: { displayName: unlock.vault.displayName } };
  }

  unlock(password: string, totpCode: string): UiResult<{ displayName: string }> {
    if (!existsSync(this.dbPath)) return err('NO_ACCOUNT', 'no account exists on this device');
    const result = Vault.unlock(this.dbPath, password, totpCode, this.now);
    if (!result.ok) {
      return {
        ok: false,
        code: result.code,
        message: result.retryAfterMs === undefined
          ? result.message
          : result.message.replace(/\d+s$/, `${Math.ceil(result.retryAfterMs / 1000)}s`),
      };
    }
    this.vault = result.vault;
    this.lastActivity = this.now();
    return { ok: true, value: { displayName: result.vault.displayName } };
  }

  /**
   * Unlock with a recovery code instead of TOTP.
   *
   * The recovery code is consumed on success: its hash is removed from the
   * stored set so it cannot be used twice.
   */
  unlockWithRecovery(password: string, recoveryCode: string): UiResult<{ displayName: string }> {
    if (!existsSync(this.dbPath)) return err('NO_ACCOUNT', 'no account exists on this device');

    // First unlock with a TOTP bypass is impossible by design, so we verify the
    // password alone, then check the recovery code against the stored set.
    const probe = Vault.unlockWithRecovery(this.dbPath, password, recoveryCode, hashRecoveryCode, this.now);
    if (!probe.ok) return err(probe.code, probe.message);
    this.vault = probe.vault;
    this.lastActivity = this.now();
    return { ok: true, value: { displayName: probe.vault.displayName } };
  }

  lock(): void {
    if (this.vault !== null) {
      this.vault.lock();
      this.vault = null;
    }
    this.pendingOnboarding = null;
    this.pendingPassword = null;
  }

  // -------------------------------------------------------------------
  // Contacts
  // -------------------------------------------------------------------

  myCard(): UiResult<string> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    return { ok: true, value: encodeCard(createContactCard(vault)) };
  }

  contacts(): UiResult<UiContact[]> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    return { ok: true, value: toUiContacts(vault, listContacts(vault)) };
  }

  addContact(cardText: string): UiResult<UiContact> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const parsed = parseCard(cardText);
    if (!parsed.ok) return err(parsed.code, parsed.message);

    // Refuse to add ourselves: it produces a room with one member and is
    // always a mistake.
    if (Buffer.from(parsed.peer.agreement).equals(Buffer.from(vault.publicIdentity.agreement))) {
      return err('SELF', 'that is your own contact card');
    }

    const stored = addContact(vault, parsed.card, parsed.peer, false);
    const [ui] = toUiContacts(vault, [stored]);
    return { ok: true, value: ui! };
  }

  verifyContact(contactId: string): UiResult<void> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    if (getContact(vault, contactId) === null) return err('NOT_FOUND', 'unknown contact');
    markVerified(vault, contactId);
    return { ok: true, value: undefined };
  }

  removeContact(contactId: string): UiResult<void> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    vault.database.prepare('DELETE FROM room_members WHERE contact_id = ?').run(contactId);
    vault.database.prepare('DELETE FROM contacts WHERE id = ?').run(contactId);
    return { ok: true, value: undefined };
  }

  // -------------------------------------------------------------------
  // Rooms
  // -------------------------------------------------------------------

  rooms(): UiResult<UiRoom[]> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const rooms = listRooms(vault);
    const contacts = new Map(listContacts(vault).map((c) => [c.id, c]));

    const out: UiRoom[] = rooms.map((r) => {
      const contactId = r.memberIds[0] ?? '';
      const contact = contacts.get(contactId);
      const messages = listMessages(vault, r.id, 1);
      const last = messages[messages.length - 1];
      return {
        id: r.id,
        name: r.name,
        kind: r.kind,
        contactId,
        verified: contact?.verified ?? false,
        ...(last === undefined ? {} : { lastMessage: last.text, lastAt: last.sentAt }),
      };
    });
    return { ok: true, value: out };
  }

  createRoom(contactId: string, name: string): UiResult<UiRoom> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    if (getContact(vault, contactId) === null) return err('NOT_FOUND', 'unknown contact');
    try {
      const room = createRoom(vault, name.trim() === '' ? 'Chat' : name.trim(), [contactId]);
      const contact = getContact(vault, contactId);
      return {
        ok: true,
        value: {
          id: room.id,
          name: room.name,
          kind: room.kind,
          contactId,
          verified: contact?.verified ?? false,
        },
      };
    } catch (e) {
      return err('ROOM_FAILED', (e as Error).message);
    }
  }

  // -------------------------------------------------------------------
  // Messages
  // -------------------------------------------------------------------

  messages(roomId: string): UiResult<UiMessage[]> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const stored = listMessages(vault, roomId);
    return { ok: true, value: stored.map((m) => this.toUiMessage(vault, m)) };
  }

  private toUiMessage(vault: Vault, m: StoredMessage): UiMessage {
    let attachment: UiAttachment | undefined;
    if (m.transferId !== undefined) {
      const att = loadAttachment(vault, m.transferId);
      if (att !== null) {
        const previewable = att.category === 'image' || att.category === 'audio' || att.category === 'video';
        const canPreview = previewable && att.data.length <= MAX_PREVIEW_BYTES;
        attachment = {
          id: att.id,
          name: att.name,
          mime: att.mime,
          size: att.size,
          category: att.category,
          ...(canPreview
            ? { previewDataUrl: `data:${att.mime};base64,${Buffer.from(att.data).toString('base64')}` }
            : {}),
        };
      }
    }
    return {
      id: m.id,
      roomId: m.roomId,
      direction: m.direction,
      sentAt: m.sentAt,
      text: m.text,
      kind: m.kind,
      ...(m.transferId === undefined ? {} : { transferId: m.transferId }),
      ...(attachment === undefined ? {} : { attachment }),
    };
  }

  sendMessage(roomId: string, contactId: string, text: string): UiResult<UiMessage> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const trimmed = text.trim();
    if (trimmed.length === 0) return err('EMPTY', 'message is empty');
    try {
      const sent = sendText({ vault, roomId, contactId, text: trimmed, now: this.now });
      // Persist the outbound route so export can find it later.
      this.recordOutbound(roomId, sent.messageId, sent.envelopes);
      return { ok: true, value: this.toUiMessage(vault, sent.stored) };
    } catch (e) {
      return err('SEND_FAILED', (e as Error).message);
    }
  }

  sendAttachment(
    roomId: string,
    contactId: string,
    name: string,
    mime: string,
    dataBase64: string,
  ): UiResult<UiMessage> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    let data: Buffer;
    try {
      data = Buffer.from(dataBase64, 'base64');
    } catch {
      return err('BAD_DATA', 'attachment data is not valid base64');
    }
    if (data.length === 0) return err('EMPTY', 'attachment is empty');

    try {
      const sent = sendFile({
        vault,
        roomId,
        contactId,
        name: sanitizeFilename(name),
        mime: mime.length === 0 ? 'application/octet-stream' : mime,
        data: new Uint8Array(data),
        now: this.now,
      });
      this.recordOutbound(roomId, sent.messageId, sent.envelopes);
      return { ok: true, value: this.toUiMessage(vault, sent.stored) };
    } catch (e) {
      return err('SEND_FAILED', (e as Error).message);
    }
  }

  /** Outbound envelopes, so the user can hand them to transport. */
  private recordOutbound(roomId: string, messageId: string, envelopes: readonly string[]): void {
    const vault = this.vault!;
    vault.database.prepare('CREATE TABLE IF NOT EXISTS outbox (message_id TEXT PRIMARY KEY, room_id TEXT, payload BLOB)').run();
    vault.database
      .prepare('INSERT OR REPLACE INTO outbox (message_id, room_id, payload) VALUES (?, ?, ?)')
      .run(messageId, roomId, vault.cipher.encryptText(JSON.stringify(envelopes), 'outbox.payload'));
  }

  /**
   * Export an outbound message's envelopes as a single text file the user can
   * send however they like (email, USB, their own relay).
   */
  exportEnvelope(roomId: string, messageId: string): UiResult<string> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const row = vault.database.prepare('SELECT payload FROM outbox WHERE message_id = ?').get(messageId) as
      | { payload: Buffer }
      | undefined;
    if (row === undefined) return err('NOT_FOUND', 'no outbound copy of this message');

    let envelopes: string[];
    try {
      envelopes = JSON.parse(vault.cipher.decryptText(row.payload, 'outbox.payload'));
    } catch {
      return err('CORRUPT', 'outbound copy is unreadable');
    }

    // Written to the app's own export directory only; the renderer never picks
    // an arbitrary path.
    const path = join(this.exportDir, `ysm-${basename(messageId)}.ysm`);
    writeFileSync(path, envelopes.join('\n'), { mode: 0o600 });
    return { ok: true, value: path };
  }

  /**
   * Import encrypted envelopes pasted or read from a `.ysm` file.
   *
   * Each line is one envelope; a file transfer spans several lines.
   */
  importEnvelope(roomId: string, text: string): UiResult<UiMessage> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) return err('EMPTY', 'no encrypted content found');

    let last: UiResult<UiMessage> | null = null;
    for (const line of lines) {
      const result = receive(vault, line, this.now);
      if (!result.ok) return err(result.code, result.message);
      last = {
        ok: true,
        value: {
          ...this.toUiMessage(vault, result.message),
          ...(result.warning === undefined ? {} : { warning: result.warning }),
        },
      };
    }
    return last!;
  }

  // -------------------------------------------------------------------
  // Files
  // -------------------------------------------------------------------

  /** Save a received attachment to the export directory. */
  saveAttachment(transferId: string): UiResult<{ saved: boolean; path?: string }> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;
    const att = loadAttachment(vault, transferId);
    if (att === null) return err('NOT_FOUND', 'attachment not found');

    const safeName = sanitizeFilename(att.name);
    const path = join(this.exportDir, safeName);
    writeFileSync(path, Buffer.from(att.data), { mode: 0o600 });
    return { ok: true, value: { saved: true, path } };
  }

  // -------------------------------------------------------------------
  // Sealed references ("Create crypto")
  // -------------------------------------------------------------------

  /**
   * Seal a text message or a file and return the two strings the user shares.
   *
   * The passphrase is generated here, returned once, and never stored. If the
   * user loses it before sending, the payload cannot be read again — including by
   * them. The UI says so before and after.
   */
  sealPayload(input: {
    text?: string;
    fileName?: string;
    mimeType?: string;
    dataBase64?: string;
  }): UiResult<UiSealedCreated> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;

    // Exactly one of text or file.
    const hasFile = typeof input.dataBase64 === 'string' && input.dataBase64.length > 0;
    const hasText = typeof input.text === 'string' && input.text.length > 0;
    if (hasFile === hasText) {
      return err('BAD_INPUT', 'provide either text or a file, not both or neither');
    }

    let data: Uint8Array;
    if (hasFile) {
      try {
        data = new Uint8Array(Buffer.from(input.dataBase64!, 'base64'));
      } catch {
        return err('BAD_INPUT', 'the file contents are not valid base64');
      }
      if (data.length === 0) return err('BAD_INPUT', 'the file is empty');
      if (data.length > MAX_SEALED_BYTES) {
        return err('TOO_LARGE', `files are limited to ${Math.floor(MAX_SEALED_BYTES / 1024 / 1024)} MB`);
      }
    } else {
      data = new TextEncoder().encode(input.text!);
      if (data.length > MAX_SEALED_TEXT_BYTES) {
        return err('TOO_LARGE', `messages are limited to ${MAX_SEALED_TEXT_BYTES} bytes`);
      }
    }

    const passphrase = generatePassphrase();
    const sealed = sealPayloadBlock({
      data,
      passphrase,
      isFile: hasFile,
      ...(hasFile ? { fileName: sanitizeFilename(input.fileName ?? 'file') } : {}),
      ...(hasFile ? { mimeType: input.mimeType ?? 'application/octet-stream' } : {}),
    });
    if (!sealed.ok) return err(sealed.code, sealed.message);

    insertSealed(vault.database, {
      reference: sealed.value.reference,
      version: sealed.value.version,
      argon: sealed.value.argon,
      salt: sealed.value.salt,
      nonce: sealed.value.nonce,
      ciphertext: sealed.value.ciphertext,
      role: 'out',
      isFile: hasFile,
      size: data.length,
      now: this.now(),
    });

    return {
      ok: true,
      value: {
        reference: sealed.value.reference,
        passphrase,
        // The transfer string is what the sender actually sends: it carries the
        // ciphertext, so the reader needs nothing but this and the passphrase.
        transfer: packTransfer(sealed.value),
        isFile: hasFile,
        fileName: hasFile ? sanitizeFilename(input.fileName ?? 'file') : undefined,
        size: data.length,
        createdAt: this.now(),
      },
    };
  }

  /**
   * Open a sealed payload with a reference and a passphrase.
   *
   * The reference must already be in the local store. A reader who was sent a
   * reference has already pasted it via `importReference`, which is what puts the
   * ciphertext here — the reference alone is not enough, by design.
   */
  openSealed(input: { reference: string; passphrase: string; transfer?: string }): UiResult<UiSealedOpened> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const vault = guard.vault;

    // The passphrase is required either way; reject early so an empty submission
    // does not cost a second of Argon2.
    if (typeof input.passphrase !== 'string' || input.passphrase.length === 0) {
      return err('BAD_PASSPHRASE', 'enter the passphrase that came with this message');
    }

    // A transfer string carries the ciphertext, so a reader with only that string
    // can open the message on a machine that has never seen it. A bare reference
    // can only be opened if this machine stored the payload earlier.
    let stored: SealedBlob | null = null;
    let sourceReference = '';

    if (typeof input.transfer === 'string' && input.transfer.trim().length > 0) {
      const unpacked = unpackTransfer(input.transfer);
      if (!unpacked.ok) return err(unpacked.code, unpacked.message);
      stored = unpacked.blob;
      sourceReference = unpacked.blob.reference;

      // Keep the imported payload locally so the reader can reopen it later
      // without pasting the whole string again.
      const already = getSealed(vault.database, sourceReference);
      if (already === null) {
        insertSealed(vault.database, {
          reference: sourceReference,
          version: stored.version,
          argon: stored.argon,
          salt: stored.salt,
          nonce: stored.nonce,
          ciphertext: stored.ciphertext,
          role: 'in',
          isFile: false,
          size: stored.ciphertext.length,
          now: this.now(),
        });
      }
    } else {
      const reference = input.reference.trim();
      if (!looksLikeReference(reference)) {
        return err('BAD_REFERENCE', 'a reference looks like YSM_ followed by 64 hex characters');
      }
      stored = getSealed(vault.database, reference);
      sourceReference = reference;
      if (stored === null) {
        return err(
          'NO_PAYLOAD',
          'this machine has no copy of that message. Paste the full transfer text (it starts with YSMT1.) or open the .ysm file that came with it.',
        );
      }
    }

    const opened = openSealedBlock({ ...stored }, input.passphrase);
    if (!opened.ok) {
      if (opened.code === 'BAD_PASSPHRASE') {
        return err('BAD_PASSPHRASE', 'wrong passphrase for this message');
      }
      return err(opened.code, opened.message);
    }

    const isFile = opened.fileName !== undefined || opened.mimeType !== undefined;
    return {
      ok: true,
      value: {
        reference: sourceReference,
        isFile,
        text: isFile ? undefined : new TextDecoder().decode(opened.data),
        fileName: opened.fileName,
        mimeType: opened.mimeType,
        size: opened.data.length,
        dataBase64: isFile ? Buffer.from(opened.data).toString('base64') : undefined,
      },
    };
  }

  /** Every sealed reference in the local store, newest first. */
  sealedItems(): UiResult<readonly UiSealedSummary[]> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    return {
      ok: true,
      value: listSealed(guard.vault.database).map((s) => ({
        reference: s.reference,
        role: s.role,
        isFile: s.isFile,
        size: s.size,
        createdAt: s.createdAt,
      })),
    };
  }

  /** Forget a sealed payload. Irreversible. */
  forgetSealed(reference: string): UiResult<{ removed: boolean }> {
    const guard = this.requireVault();
    if (!guard.ok) return guard;
    const removed = deleteSealed(guard.vault.database, reference.trim());
    return { ok: true, value: { removed } };
  }

  /**
   * Write a decrypted file to the export directory, keeping its original name and
   * extension so the reader can open it in the right application.
   */
  saveSealed(reference: string, passphrase: string): UiResult<{ path: string; fileName: string }> {
    const opened = this.openSealed({ reference, passphrase });
    if (!opened.ok) return opened;
    if (!opened.value.isFile || opened.value.dataBase64 === undefined) {
      return err('BAD_INPUT', 'this reference holds text, not a file');
    }
    const safeName = sanitizeFilename(opened.value.fileName ?? 'file');
    const path = join(this.exportDir, safeName);
    writeFileSync(path, Buffer.from(opened.value.dataBase64, 'base64'), { mode: 0o600 });
    return { ok: true, value: { path, fileName: safeName } };
  }

  // -------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------

  setLocale(locale: Locale): void {
    if (!LOCALES.includes(locale)) throw new ServiceError('BAD_LOCALE', 'unsupported locale');
    this.locale = locale;
  }

  getLocale(): Locale {
    return this.locale;
  }

  /**
   * Auto-lock delay, in seconds.
   *
   * Bounded to 30–300 s. The lower bound keeps the window short enough that
   * walking away from the machine is not an immediate compromise; the upper bound
   * stops a user (or a tampered settings file) from disabling the lock in
   * practice. 0 is not accepted: an unlocked vault with no timeout is the state
   * this setting exists to prevent.
   */
  setAutoLock(seconds: number): void {
    const whole = Math.floor(seconds);
    if (!Number.isFinite(whole) || whole < MIN_AUTOLOCK_SECONDS || whole > MAX_AUTOLOCK_SECONDS) {
      throw new ServiceError(
        'BAD_AUTOLOCK',
        `auto-lock must be between ${MIN_AUTOLOCK_SECONDS} and ${MAX_AUTOLOCK_SECONDS} seconds`,
      );
    }
    this.autoLockSeconds = whole;
  }

  getAutoLock(): number {
    return this.autoLockSeconds;
  }
}

/** Convert stored contacts to UI shapes, computing the safety number per contact. */
function toUiContacts(vault: Vault, contacts: readonly StoredContact[]): UiContact[] {
  return contacts.map((c) => ({
    id: c.id,
    displayName: c.displayName,
    verified: c.verified,
    safetyNumber: vault.safetyNumberWith({ agreement: c.agreement, signing: c.signing }),
    createdAt: c.createdAt,
  }));
}

function err(code: string, message: string): { ok: false; code: string; message: string } {
  return { ok: false, code, message };
}

/** An expected, reportable failure. Distinguished from a programming bug. */
export class ServiceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'ServiceError';
    this.code = code;
  }
}
