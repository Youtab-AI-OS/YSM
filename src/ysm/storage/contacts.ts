/**
 * Contacts and encrypted rooms.
 *
 * A contact is added by pasting their *contact card* — a signed blob containing
 * their display name and both public keys. The signature is verified against the
 * embedded signing key, which proves the card was produced by whoever holds that
 * key, but it does NOT prove who that person is. That is what the safety number
 * comparison is for, and the UI must say so.
 *
 * A room is a conversation. Direct rooms have exactly two members; group rooms
 * have many. The room id is derived deterministically from the sorted member key
 * set so both sides compute the same id without coordination.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';

import { random, verify, type PublicIdentity } from '../crypto/identity.js';
import { b64u, fromB64u } from '../crypto/envelope.js';
import type { Vault } from './vault.js';

/** A shareable, signed contact card. */
export interface ContactCard {
  readonly v: 1;
  readonly name: string;
  readonly agreement: string;
  readonly signing: string;
  /** Ed25519 signature over the canonical body. */
  readonly sig: string;
}

/** Canonical body of a card (what the signature covers). */
function cardBody(card: Omit<ContactCard, 'sig'>): string {
  return JSON.stringify({ v: card.v, name: card.name, agreement: card.agreement, signing: card.signing });
}

/** Build a signed card for this account. */
export function createContactCard(vault: Vault): ContactCard {
  const pub = vault.publicIdentity;
  const body: Omit<ContactCard, 'sig'> = {
    v: 1,
    name: vault.displayName,
    agreement: b64u(pub.agreement),
    signing: b64u(pub.signing),
  };
  const signature = ed25519.sign(new TextEncoder().encode(cardBody(body)), vault.identity.signing.secretKey);
  return { ...body, sig: b64u(signature) };
}

/** Encode a card as a paste-able string. */
export function encodeCard(card: ContactCard): string {
  return `ysm-contact://${b64u(new TextEncoder().encode(JSON.stringify(card)))}`;
}

export type ParsedCard =
  | { ok: true; card: ContactCard; peer: PublicIdentity }
  | { ok: false; code: 'FORMAT' | 'SIGNATURE' | 'KEYS' | 'NAME'; message: string };

/**
 * Parse and verify a pasted contact card.
 *
 * Everything is validated before the contact is shown to the user: the shape,
 * the key lengths, the name, and crucially the self-signature. A card whose
 * signature does not verify is rejected — a tampered card would otherwise let
 * someone substitute keys.
 */
export function parseCard(input: string): ParsedCard {
  const trimmed = input.trim();
  const body = trimmed.startsWith('ysm-contact://') ? trimmed.slice('ysm-contact://'.length) : trimmed;

  let card: ContactCard;
  try {
    const json = new TextDecoder().decode(fromB64u(body));
    card = JSON.parse(json) as ContactCard;
  } catch {
    return { ok: false, code: 'FORMAT', message: 'this is not a valid YSM contact card' };
  }

  if (
    typeof card !== 'object' || card === null ||
    card.v !== 1 ||
    typeof card.name !== 'string' ||
    typeof card.agreement !== 'string' ||
    typeof card.signing !== 'string' ||
    typeof card.sig !== 'string'
  ) {
    return { ok: false, code: 'FORMAT', message: 'contact card is missing fields' };
  }
  if (card.name.trim().length === 0 || card.name.length > 64) {
    return { ok: false, code: 'NAME', message: 'contact card has an invalid display name' };
  }

  let agreement: Uint8Array, signing: Uint8Array, sig: Uint8Array;
  try {
    agreement = fromB64u(card.agreement);
    signing = fromB64u(card.signing);
    sig = fromB64u(card.sig);
  } catch {
    return { ok: false, code: 'FORMAT', message: 'contact card contains invalid encoding' };
  }
  if (agreement.length !== 32 || signing.length !== 32) {
    return { ok: false, code: 'KEYS', message: 'contact card keys have the wrong length' };
  }

  const signed = new TextEncoder().encode(
    cardBody({ v: card.v, name: card.name, agreement: card.agreement, signing: card.signing }),
  );
  if (!verify(sig, signed, signing)) {
    return { ok: false, code: 'SIGNATURE', message: 'contact card signature is invalid — it was modified or forged' };
  }

  return { ok: true, card, peer: { agreement, signing } };
}

/** Derive a stable room id from a set of member public keys. */
export function deriveRoomId(memberKeys: readonly Uint8Array[]): string {
  const sorted = [...memberKeys].map((k) => Buffer.from(k).toString('hex')).sort();
  const material = new TextEncoder().encode(`ysm/v1/room:${sorted.join(':')}`);
  return Buffer.from(sha256(material).subarray(0, 16)).toString('hex');
}

export interface StoredContact {
  readonly id: string;
  readonly displayName: string;
  readonly agreement: Uint8Array;
  readonly signing: Uint8Array;
  readonly verified: boolean;
  readonly createdAt: number;
}

export interface StoredRoom {
  readonly id: string;
  readonly name: string;
  readonly kind: 'direct' | 'group';
  readonly memberIds: readonly string[];
  readonly createdAt: number;
}

/**
 * Store a verified contact card.
 *
 * The contact id is the hex of the agreement key, so adding the same person
 * twice updates rather than duplicates.
 */
export function addContact(vault: Vault, card: ContactCard, peer: PublicIdentity, verified = false): StoredContact {
  const cipher = vault.cipher;
  const id = Buffer.from(peer.agreement).toString('hex');
  const db = vault.database;

  db.prepare(
    `INSERT INTO contacts (id, display_name, agreement_pub, signing_pub, verified, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, verified = excluded.verified`,
  ).run(
    id,
    cipher.encryptText(card.name, 'contacts.display_name'),
    Buffer.from(peer.agreement),
    Buffer.from(peer.signing),
    verified ? 1 : 0,
    Date.now(),
  );

  return { id, displayName: card.name, agreement: peer.agreement, signing: peer.signing, verified, createdAt: Date.now() };
}

/** List contacts, decrypting names. */
export function listContacts(vault: Vault): StoredContact[] {
  const rows = vault.database
    .prepare('SELECT id, display_name, agreement_pub, signing_pub, verified, created_at FROM contacts ORDER BY created_at')
    .all() as Array<{
    id: string;
    display_name: Buffer;
    agreement_pub: Buffer;
    signing_pub: Buffer;
    verified: number;
    created_at: number;
  }>;

  return rows.map((r) => ({
    id: r.id,
    displayName: vault.cipher.decryptText(r.display_name, 'contacts.display_name'),
    agreement: new Uint8Array(r.agreement_pub),
    signing: new Uint8Array(r.signing_pub),
    verified: r.verified === 1,
    createdAt: r.created_at,
  }));
}

/** Fetch one contact by id. */
export function getContact(vault: Vault, id: string): StoredContact | null {
  const row = vault.database
    .prepare('SELECT id, display_name, agreement_pub, signing_pub, verified, created_at FROM contacts WHERE id = ?')
    .get(id) as
    | { id: string; display_name: Buffer; agreement_pub: Buffer; signing_pub: Buffer; verified: number; created_at: number }
    | undefined;
  if (row === undefined) return null;
  return {
    id: row.id,
    displayName: vault.cipher.decryptText(row.display_name, 'contacts.display_name'),
    agreement: new Uint8Array(row.agreement_pub),
    signing: new Uint8Array(row.signing_pub),
    verified: row.verified === 1,
    createdAt: row.created_at,
  };
}

/** Mark a contact as verified after comparing safety numbers out of band. */
export function markVerified(vault: Vault, contactId: string): void {
  vault.database.prepare('UPDATE contacts SET verified = 1 WHERE id = ?').run(contactId);
}

/** Create (or reuse) a room. */
export function createRoom(
  vault: Vault,
  name: string,
  contactIds: readonly string[],
  kind: 'direct' | 'group' = contactIds.length === 1 ? 'direct' : 'group',
): StoredRoom {
  const db = vault.database;

  const memberKeys: Uint8Array[] = [vault.publicIdentity.agreement];
  for (const id of contactIds) {
    const contact = getContact(vault, id);
    if (contact === null) throw new Error(`unknown contact ${id}`);
    memberKeys.push(contact.agreement);
  }
  const roomId = deriveRoomId(memberKeys);

  const existing = db.prepare('SELECT id FROM rooms WHERE id = ?').get(roomId);
  if (existing === undefined) {
    db.prepare('INSERT INTO rooms (id, name, kind, created_at) VALUES (?, ?, ?, ?)').run(
      roomId,
      vault.cipher.encryptText(name, 'rooms.name'),
      kind,
      Date.now(),
    );
  }
  for (const id of contactIds) {
    db.prepare('INSERT OR IGNORE INTO room_members (room_id, contact_id) VALUES (?, ?)').run(roomId, id);
  }

  return { id: roomId, name, kind, memberIds: contactIds, createdAt: Date.now() };
}

/** List rooms with decrypted names. */
export function listRooms(vault: Vault): StoredRoom[] {
  const rows = vault.database.prepare('SELECT id, name, kind, created_at FROM rooms ORDER BY created_at').all() as Array<{
    id: string;
    name: Buffer;
    kind: 'direct' | 'group';
    created_at: number;
  }>;
  return rows.map((r) => ({
    id: r.id,
    name: vault.cipher.decryptText(r.name, 'rooms.name'),
    kind: r.kind,
    memberIds: (
      vault.database.prepare('SELECT contact_id FROM room_members WHERE room_id = ?').all(r.id) as Array<{
        contact_id: string;
      }>
    ).map((m) => m.contact_id),
    createdAt: r.created_at,
  }));
}

/** Fresh opaque id for a local row. */
export function newId(): string {
  return Buffer.from(random(16)).toString('hex');
}
