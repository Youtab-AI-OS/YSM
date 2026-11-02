/**
 * The IPC contract.
 *
 * This is the complete, closed list of operations the renderer can request. The
 * preload script exposes exactly these and nothing else; the main process
 * validates every payload shape before dispatch.
 *
 * Security properties this design gives us:
 *
 *  - No `nodeIntegration` in the renderer, so a UI bug cannot reach the
 *    filesystem or spawn processes.
 *  - The renderer never receives secret key material. Only whitelisted,
 *    already-derived data crosses the boundary (display strings, public keys,
 *    decrypted message text the user asked to see).
 *  - Channel names are a fixed union; there is no generic `invoke(anything)`
 *    escape hatch, which is how Electron apps usually become exploitable.
 *  - Every mutating call is validated again in main; the renderer is untrusted
 *    in principle even though we wrote it.
 */

import type { Locale } from '../i18n/strings.js';

/** Account state as seen by the UI. */
export interface UiAccountState {
  readonly exists: boolean;
  readonly unlocked: boolean;
  readonly displayName?: string;
  readonly contactCard?: string;
  readonly ownerPublicKey?: string;
}

export interface UiContact {
  readonly id: string;
  readonly displayName: string;
  readonly verified: boolean;
  readonly safetyNumber: string;
  readonly createdAt: number;
}

export interface UiRoom {
  readonly id: string;
  readonly name: string;
  readonly kind: 'direct' | 'group';
  readonly contactId: string;
  readonly verified: boolean;
  readonly lastMessage?: string;
  readonly lastAt?: number;
}

export interface UiMessage {
  readonly id: string;
  readonly roomId: string;
  readonly direction: 'in' | 'out';
  readonly sentAt: number;
  readonly text: string;
  readonly kind: 'text' | 'file' | 'file-start' | 'file-chunk';
  readonly transferId?: string;
  /** Populated for file messages so the UI can render a preview. */
  readonly attachment?: UiAttachment;
  /** A non-fatal warning, e.g. an unknown sender. */
  readonly warning?: string;
}

export interface UiAttachment {
  readonly id: string;
  readonly name: string;
  readonly mime: string;
  readonly size: number;
  readonly category: 'image' | 'video' | 'audio' | 'archive' | 'document' | 'other';
  /** base64 data URL for inline previews; only present for image/audio/video. */
  readonly previewDataUrl?: string;
}

/** Result envelope. Every call returns one of these; exceptions never cross IPC. */
export type UiResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; message: string };

/**
 * A freshly sealed payload, as returned to the sender.
 *
 * `transfer` is the string the sender actually sends. `reference` identifies the
 * payload but carries none of it, so it is not enough on its own; the transfer
 * string holds the ciphertext.
 */
export interface UiSealedCreated {
  readonly reference: string;
  readonly transfer: string;
  /**
   * The one-time passphrase. Shown once and never stored.
   *
   * Send this over a *different* channel from the transfer string, so a party who
   * captures one does not have both.
   */
  readonly passphrase: string;
  readonly isFile: boolean;
  readonly fileName?: string;
  readonly size: number;
  readonly createdAt: number;
}

/** A decrypted payload, ready to display or save. */
export interface UiSealedOpened {
  readonly reference: string;
  readonly isFile: boolean;
  readonly text?: string;
  readonly fileName?: string;
  readonly mimeType?: string;
  readonly size: number;
  /** base64 bytes, when the payload is a file, so the reader can download it. */
  readonly dataBase64?: string;
}

/** One row in the user's list of sealed references. */
export interface UiSealedSummary {
  readonly reference: string;
  readonly role: 'out' | 'in';
  readonly isFile: boolean;
  readonly size: number;
  readonly createdAt: number;
}

/** Onboarding data shown exactly once. */
export interface UiOnboarding {
  readonly totpSecretBase32: string;
  readonly totpUri: string;
  readonly recoveryCodes: readonly string[];
  /**
   * QR module matrix for `totpUri`, encoded in the main process.
   *
   * The renderer paints this as rectangles and never parses it. `modules[row][col]`
   * is true for a dark module.
   */
  readonly qr: { readonly size: number; readonly modules: readonly (readonly boolean[])[] };
}

/**
 * The complete IPC surface.
 *
 * Keys are channel names; values are [request, response] types.
 */
export interface IpcContract {
  'account:state': [void, UiAccountState];
  'account:create': [{ displayName: string; password: string }, UiOnboarding];
  'account:unlock': [{ password: string; totpCode: string }, { displayName: string }];
  'account:unlockRecovery': [{ password: string; recoveryCode: string }, { displayName: string }];
  'account:lock': [void, void];
  'account:confirmOnboarding': [{ totpCode: string; secret: string }, void];

  'contacts:list': [void, UiContact[]];
  'contacts:add': [{ card: string }, UiContact];
  'contacts:verify': [{ contactId: string }, void];
  'contacts:remove': [{ contactId: string }, void];
  'contacts:myCard': [void, string];

  'rooms:list': [void, UiRoom[]];
  'rooms:create': [{ contactId: string; name: string }, UiRoom];

  'messages:list': [{ roomId: string }, UiMessage[]];
  'messages:send': [{ roomId: string; contactId: string; text: string }, UiMessage];
  'messages:sendFile': [
    { roomId: string; contactId: string; name: string; mime: string; dataBase64: string },
    UiMessage,
  ];
  'messages:importEnvelope': [{ roomId: string; text: string }, UiMessage];
  'messages:exportEnvelope': [{ roomId: string; messageId: string }, string];

  'files:save': [{ transferId: string }, { saved: boolean; path?: string }];

  'settings:setLocale': [{ locale: Locale }, void];
  'settings:getLocale': [void, Locale];
  'settings:setAutoLock': [{ seconds: number }, void];
  'settings:getAutoLock': [void, number];

  // Sealed references.
  'sealed:create': [
    { text?: string; fileName?: string; mimeType?: string; dataBase64?: string },
    UiSealedCreated,
  ];
  'sealed:open': [{ reference: string; passphrase: string; transfer?: string }, UiSealedOpened],
  'sealed:list': [void, readonly UiSealedSummary[]];
  'sealed:forget': [{ reference: string }, { removed: boolean }];
  'sealed:save': [{ reference: string; passphrase: string }, { path: string; fileName: string }];

  'app:version': [void, { version: string; electron: string; node: string }];
}

export type IpcChannel = keyof IpcContract;

/** Runtime list of allowed channels, used by preload and validated in main. */
export const IPC_CHANNELS: readonly IpcChannel[] = [
  'account:state',
  'account:create',
  'account:unlock',
  'account:unlockRecovery',
  'account:lock',
  'account:confirmOnboarding',
  'contacts:list',
  'contacts:add',
  'contacts:verify',
  'contacts:remove',
  'contacts:myCard',
  'rooms:list',
  'rooms:create',
  'messages:list',
  'messages:send',
  'messages:sendFile',
  'messages:importEnvelope',
  'messages:exportEnvelope',
  'files:save',
  'settings:setLocale',
  'settings:getLocale',
  'settings:setAutoLock',
  'settings:getAutoLock',
  'sealed:create',
  'sealed:open',
  'sealed:list',
  'sealed:forget',
  'sealed:save',
  'app:version',
];

/**
 * Payload validators.
 *
 * These run in the main process against whatever the renderer sent. The renderer
 * is ours, but treating it as untrusted is what stops a compromised renderer
 * (via any future bug) from turning IPC into a filesystem or memory primitive.
 */
type Validator = (v: unknown) => boolean;

const isString = (v: unknown): v is string => typeof v === 'string';
const isFiniteInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Length-bounded string check, so a huge payload cannot be used to exhaust memory. */
function boundedString(max: number): Validator {
  return (v) => typeof v === 'string' && v.length <= max;
}

export const IPC_VALIDATORS: Record<IpcChannel, Validator> = {
  'account:state': () => true,
  'account:create': (v) =>
    isObject(v) && isString(v['displayName']) && v['displayName'].length <= 64 &&
    isString(v['password']) && v['password'].length > 0 && v['password'].length <= 1024,
  'account:unlock': (v) =>
    isObject(v) && isString(v['password']) && v['password'].length <= 1024 &&
    isString(v['totpCode']) && v['totpCode'].length <= 16,
  'account:unlockRecovery': (v) =>
    isObject(v) && isString(v['password']) && v['password'].length <= 1024 &&
    isString(v['recoveryCode']) && v['recoveryCode'].length <= 64,
  'account:lock': () => true,
  'account:confirmOnboarding': (v) =>
    isObject(v) && isString(v['totpCode']) && v['totpCode'].length <= 16 &&
    isString(v['secret']) && v['secret'].length <= 128,

  'contacts:list': () => true,
  'contacts:add': (v) => isObject(v) && isString(v['card']) && v['card'].length <= 8192,
  'contacts:verify': (v) => isObject(v) && isString(v['contactId']) && v['contactId'].length <= 128,
  'contacts:remove': (v) => isObject(v) && isString(v['contactId']) && v['contactId'].length <= 128,
  'contacts:myCard': () => true,

  'rooms:list': () => true,
  'rooms:create': (v) =>
    isObject(v) && isString(v['contactId']) && v['contactId'].length <= 128 &&
    isString(v['name']) && v['name'].length <= 128,

  'messages:list': (v) => isObject(v) && isString(v['roomId']) && v['roomId'].length <= 128,
  'messages:send': (v) =>
    isObject(v) && boundedString(128)(v['roomId']) && boundedString(128)(v['contactId']) &&
    isString(v['text']) && v['text'].length <= 64 * 1024,
  'messages:sendFile': (v) =>
    isObject(v) && boundedString(128)(v['roomId']) && boundedString(128)(v['contactId']) &&
    isString(v['name']) && v['name'].length <= 256 &&
    isString(v['mime']) && v['mime'].length <= 128 &&
    // 2 GiB base64 ceiling, matching the attachment limit.
    isString(v['dataBase64']) && v['dataBase64'].length <= Math.ceil((2 * 1024 * 1024 * 1024 * 4) / 3) + 16,
  'messages:importEnvelope': (v) =>
    isObject(v) && boundedString(128)(v['roomId']) && isString(v['text']) && v['text'].length <= 96 * 1024 * 1024,
  'messages:exportEnvelope': (v) =>
    isObject(v) && boundedString(128)(v['roomId']) && boundedString(128)(v['messageId']),

  'files:save': (v) => isObject(v) && isString(v['transferId']) && v['transferId'].length <= 128,

  'settings:setLocale': (v) => isObject(v) && (v['locale'] === 'en' || v['locale'] === 'fa' || v['locale'] === 'nl'),
  'settings:getLocale': () => true,
  'settings:setAutoLock': (v) =>
    isObject(v) && isFiniteInt(v['seconds']) && v['seconds'] >= 30 && v['seconds'] <= 300,
  'settings:getAutoLock': () => true,

  // Sealed references.
  //
  // `sealed:create` accepts either text or a file payload. The size is bounded in
  // the service; here we only check shape and type, so a malformed call is refused
  // before any allocation.
  'sealed:create': (v) => {
    if (!isObject(v)) return false;
    const text = v['text'];
    const fileName = v['fileName'];
    const mimeType = v['mimeType'];
    const dataBase64 = v['dataBase64'];
    if (text !== undefined && !isString(text)) return false;
    if (fileName !== undefined && !isString(fileName)) return false;
    if (mimeType !== undefined && !isString(mimeType)) return false;
    if (dataBase64 !== undefined && !isString(dataBase64)) return false;
    // Exactly one of the two payload shapes.
    return (text !== undefined && text.length > 0) !== (dataBase64 !== undefined && dataBase64.length > 0);
  },
  'sealed:open': (v) =>
    isObject(v) &&
    isString(v['reference']) &&
    isString(v['passphrase']) &&
    v['passphrase'].length > 0 &&
    v['passphrase'].length <= 256 &&
    // A transfer string carries the ciphertext; it is long but bounded, so a
    // pathological paste cannot force an unbounded allocation.
    (v['transfer'] === undefined ||
      (isString(v['transfer']) && v['transfer'].length <= 64 * 1024 * 1024)),
  'sealed:list': () => true,
  'sealed:forget': (v) => isObject(v) && isString(v['reference']),
  'sealed:save': (v) =>
    isObject(v) && isString(v['reference']) && isString(v['passphrase']) && v['passphrase'].length <= 256,

  'app:version': () => true,
};

export function isIpcChannel(value: string): value is IpcChannel {
  return (IPC_CHANNELS as readonly string[]).includes(value);
}
