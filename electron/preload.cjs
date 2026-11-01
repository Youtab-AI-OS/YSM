/**
 * Preload: the only bridge between the sandboxed renderer and the main process.
 *
 * Rules:
 *  - `contextBridge.exposeInMainWorld` with a frozen object. No raw ipcRenderer.
 *  - Channel names come from the contract's allowlist; an unknown name throws
 *    before reaching IPC.
 *  - Nothing here exposes Node, `require`, `process`, or filesystem access.
 *
 * Written as CommonJS because a sandboxed preload cannot be an ES module.
 */

const { contextBridge, ipcRenderer } = require('electron');

/** Frozen mirror of the channel allowlist. Kept literal so it cannot be widened
 *  by importing a module the renderer could tamper with. */
const ALLOWED = Object.freeze([
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
]);

function invoke(channel, payload) {
  if (typeof channel !== 'string' || ALLOWED.indexOf(channel) === -1) {
    return Promise.resolve({ ok: false, code: 'UNKNOWN_CHANNEL', message: 'unknown operation' });
  }
  // Always send a defined payload; the main process validates the shape.
  return ipcRenderer.invoke(channel, payload === undefined ? {} : payload);
}

/**
 * The single object the renderer sees. Frozen so page script cannot monkey-patch
 * a method to redirect calls, and containing no references to Electron internals.
 */
contextBridge.exposeInMainWorld(
  'ysm',
  Object.freeze({
    invoke,
    /** Subscribe to forced-lock notifications. Returns an unsubscribe function. */
    onLocked(callback) {
      if (typeof callback !== 'function') return () => {};
      const handler = () => callback();
      ipcRenderer.on('app:locked', handler);
      return () => ipcRenderer.removeListener('app:locked', handler);
    },
    /** Exposed so the UI can show the platform RTL direction correctly. */
    platform: process.platform,
  }),
);
