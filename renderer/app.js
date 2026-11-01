/**
 * YSM renderer.
 *
 * Security rules this file follows without exception:
 *   - User-controlled content is written with `textContent`, never `innerHTML`.
 *     Message text, contact names and filenames are all attacker-influenced, so
 *     building DOM from strings would be an injection vector even with a CSP.
 *   - The only DOM built from a template literal is static chrome with no
 *     interpolated values; those are created with createElement instead.
 *   - No network calls. All data comes from `window.ysm.invoke` (the preload
 *     bridge), which is the only capability the page has.
 *   - No `eval`, no `new Function`, no dynamic script insertion.
 */

import { translate, isRtl, LOCALES } from './i18n.js';

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

const bridge = window.ysm;
if (!bridge) {
  // Without the preload bridge there is nothing this page can do; say so plainly
  // rather than failing silently.
  document.body.textContent = 'YSM must be run as the desktop application.';
  throw new Error('preload bridge missing');
}

/** Invoke an IPC channel and return the value, throwing on failure. */
async function call(channel, payload) {
  const result = await bridge.invoke(channel, payload);
  if (!result || typeof result !== 'object') {
    throw new AppError('BRIDGE', 'no response from the application');
  }
  if (result.ok === false) {
    throw new AppError(result.code || 'UNKNOWN', result.message || 'operation failed');
  }
  return result.value;
}

class AppError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AppError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  locale: 'en',
  accountUnlocked: false,
  contacts: [],
  rooms: [],
  activeRoom: null,
  activeContactId: null,
  onboarding: null,
  pendingVerifyContact: null,
  version: null,
};

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

/** Apply translations to every element carrying a data-i18n attribute. */
function applyTranslations() {
  const t = (key, vars) => translate(state.locale, key, vars);

  document.documentElement.lang = state.locale;
  document.documentElement.dir = isRtl(state.locale) ? 'rtl' : 'ltr';

  for (const el of document.querySelectorAll('[data-i18n]')) {
    const key = el.getAttribute('data-i18n');
    if (!key) continue;
    const text = t(key);
    // Use textContent so a translation containing markup cannot inject.
    el.textContent = text;
  }
  for (const el of document.querySelectorAll('[data-i18n-placeholder]')) {
    const key = el.getAttribute('data-i18n-placeholder');
    if (!key) continue;
    el.setAttribute('placeholder', t(key));
  }

  if (state.version) {
    const line = $('version-line');
    if (line) line.textContent = t('settings.version', { version: state.version.version });
  }
  const footer = $('boot-footer');
  if (footer) footer.textContent = t('settings.noTelemetry');

  // Re-render dynamic lists so their strings follow the locale.
  if (state.accountUnlocked) {
    renderContacts();
    renderRooms();
    if (state.activeRoom) renderMessages().catch(() => {});
  }
  markActiveLanguage();
}

function markActiveLanguage() {
  for (const btn of document.querySelectorAll('.lang-btn')) {
    btn.classList.toggle('active', btn.dataset.locale === state.locale);
  }
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

const SCREENS = [
  'screen-boot',
  'screen-create',
  'screen-onboard',
  'screen-recovery',
  'screen-unlock',
  'screen-main',
];

function show(screenId) {
  for (const id of SCREENS) {
    const el = $(id);
    if (el) el.classList.toggle('active', id === screenId);
  }
}

function showPanel(panelId) {
  for (const el of document.querySelectorAll('.panel')) {
    el.classList.toggle('active', el.id === panelId);
  }
  for (const tab of document.querySelectorAll('.tab')) {
    tab.classList.toggle('active', `panel-${tab.dataset.tab}` === panelId);
  }
}

// ---------------------------------------------------------------------------
// Toasts and errors
// ---------------------------------------------------------------------------

let toastTimer = null;

function toast(message) {
  const el = $('toast');
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 2600);
}

function setError(id, message) {
  const el = $(id);
  if (!el) return;
  if (message) {
    el.textContent = message;
    el.hidden = false;
  } else {
    el.textContent = '';
    el.hidden = true;
  }
}

/** Map an error to a translated message where we have one. */
function describe(error) {
  const t = (key, vars) => translate(state.locale, key, vars);
  switch (error.code) {
    case 'BAD_PASSWORD':
      return t('unlock.badPassword');
    case 'BAD_TOTP':
      return t('unlock.badTotp');
    case 'TOTP_REPLAY':
      return t('unlock.replay');
    case 'LOCKED_OUT':
      return t('unlock.lockedOut', { seconds: extractSeconds(error.message) });
    case 'LOCKED':
      return t('error.locked');
    case 'WEAK_PASSWORD':
      return t('create.weak');
    default:
      return error.message || t('error.generic');
  }
}

function extractSeconds(message) {
  const match = /(\d+)\s*s/.exec(String(message));
  return match ? match[1] : '30';
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot() {
  try {
    state.version = await call('app:version');
  } catch {
    state.version = { version: '1.0.0' };
  }
  try {
    state.locale = await call('settings:getLocale');
  } catch {
    state.locale = 'en';
  }
  if (!LOCALES.includes(state.locale)) state.locale = 'en';

  applyTranslations();
  await refreshAccountState();
}

async function refreshAccountState() {
  let info;
  try {
    info = await call('account:state');
  } catch {
    info = { exists: false, unlocked: false };
  }

  state.accountUnlocked = Boolean(info.unlocked);
  if (info.unlocked) {
    $('me').textContent = info.displayName || '';
    show('screen-main');
    await loadWorkspace();
    return;
  }

  if (info.exists) {
    show('screen-unlock');
    $('unlock-password').focus();
  } else {
    show('screen-boot');
  }
}

// ---------------------------------------------------------------------------
// Create account
// ---------------------------------------------------------------------------

async function handleCreate(event) {
  event.preventDefault();
  setError('create-error', '');

  const name = $('create-name').value.trim();
  const pw = $('create-password').value;
  const pw2 = $('create-password2').value;

  if (pw !== pw2) {
    setError('create-error', translate(state.locale, 'create.mismatch'));
    return;
  }

  const submit = $('create-submit');
  submit.disabled = true;
  const original = submit.textContent;
  submit.textContent = translate(state.locale, 'create.working');

  try {
    const onboarding = await call('account:create', { displayName: name, password: pw });
    state.onboarding = onboarding;
    // Clear the password fields as soon as they are no longer needed.
    $('create-password').value = '';
    $('create-password2').value = '';

    $('totp-secret').textContent = onboarding.totpSecretBase32;
    drawQr(onboarding.qr);
    show('screen-onboard');
    $('onboard-code').focus();
  } catch (error) {
    setError('create-error', describe(error));
  } finally {
    submit.disabled = false;
    submit.textContent = original;
  }
}

/** Paint the QR matrix the main process produced. */
function drawQr(matrix) {
  const canvas = $('qr-canvas');
  if (!canvas || !matrix || !Array.isArray(matrix.modules)) return;

  const size = matrix.size;
  const quiet = 4;
  const scale = Math.max(1, Math.floor(200 / (size + quiet * 2)));
  const full = (size + quiet * 2) * scale;

  canvas.width = full;
  canvas.height = full;
  canvas.style.width = `${full}px`;
  canvas.style.height = `${full}px`;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, full, full);
  ctx.fillStyle = '#000000';
  for (let row = 0; row < size; row++) {
    const line = matrix.modules[row];
    if (!Array.isArray(line)) continue;
    for (let col = 0; col < size; col++) {
      if (!line[col]) continue;
      ctx.fillRect((col + quiet) * scale, (row + quiet) * scale, scale, scale);
    }
  }
}

async function handleOnboardVerify() {
  setError('onboard-error', '');
  const code = $('onboard-code').value.replace(/\s+/g, '');
  const btn = $('onboard-verify');
  btn.disabled = true;

  try {
    await call('account:confirmOnboarding', { totpCode: code, secret: state.onboarding.totpSecretBase32 });
    renderRecoveryCodes(state.onboarding.recoveryCodes);
    show('screen-recovery');
  } catch (error) {
    setError('onboard-error', describe(error));
  } finally {
    btn.disabled = false;
  }
}

function renderRecoveryCodes(codes) {
  const list = $('recovery-list');
  list.textContent = '';
  for (const code of codes) {
    const li = document.createElement('li');
    li.textContent = code;
    list.appendChild(li);
  }
  $('recovery-ack').checked = false;
  $('recovery-done').disabled = true;
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

async function handleUnlock(event) {
  event.preventDefault();
  setError('unlock-error', '');

  const password = $('unlock-password').value;
  const code = $('unlock-code').value.replace(/\s+/g, '');
  const submit = $('unlock-submit');
  submit.disabled = true;
  const original = submit.textContent;
  submit.textContent = translate(state.locale, 'unlock.working');

  try {
    await call('account:unlock', { password, totpCode: code });
    $('unlock-password').value = '';
    $('unlock-code').value = '';
    await refreshAccountState();
  } catch (error) {
    setError('unlock-error', describe(error));
    $('unlock-code').value = '';
    $('unlock-code').focus();
  } finally {
    submit.disabled = false;
    submit.textContent = original;
  }
}

async function handleRecoveryUnlock() {
  setError('unlock-error', '');
  const password = $('unlock-password').value;
  const code = $('unlock-recovery').value.trim();
  try {
    await call('account:unlockRecovery', { password, recoveryCode: code });
    $('unlock-password').value = '';
    $('unlock-recovery').value = '';
    await refreshAccountState();
  } catch (error) {
    setError('unlock-error', describe(error));
  }
}

async function lockNow() {
  try {
    await call('account:lock');
  } catch {
    // Locking must never depend on the main process acknowledging it: the UI
    // hides everything regardless, so a failed call still removes data from view.
  }
  state.accountUnlocked = false;
  state.activeRoom = null;
  state.contacts = [];
  state.rooms = [];
  $('message-list').textContent = '';
  // Wipe any plaintext, passphrase or decrypted file left in the Crypto panes, so
  // locking really does remove secrets from the screen.
  clearCryptoOnLock();
  show('screen-unlock');
  $('unlock-password').focus();
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

async function loadWorkspace() {
  try {
    const [contacts, rooms, card] = await Promise.all([
      call('contacts:list'),
      call('rooms:list'),
      call('contacts:myCard'),
    ]);
    state.contacts = contacts;
    state.rooms = rooms;
    $('my-card').value = card;
    renderContacts();
    renderRooms();
    showPanel('panel-chats');
  } catch (error) {
    toast(describe(error));
  }
}

function initials(name) {
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function formatTime(ms) {
  try {
    return new Date(ms).toLocaleTimeString(state.locale, { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function renderRooms() {
  const list = $('room-list');
  const empty = $('room-empty');
  list.textContent = '';

  if (state.rooms.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  for (const room of state.rooms) {
    const row = document.createElement('div');
    row.className = 'room-item';
    row.tabIndex = 0;
    row.setAttribute('role', 'button');

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = initials(room.name);

    const body = document.createElement('div');
    body.className = 'item-body';

    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = room.name;

    const sub = document.createElement('div');
    sub.className = 'item-sub';
    sub.textContent = room.lastMessage || translate(state.locale, 'chats.noMessages');

    body.append(title, sub);

    if (room.verified) {
      const badge = document.createElement('span');
      badge.className = 'badge ok';
      badge.textContent = translate(state.locale, 'chats.verified');
      row.append(avatar, body, badge);
    } else {
      row.append(avatar, body);
    }

    const open = () => openRoom(room);
    row.addEventListener('click', open);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open();
      }
    });

    list.appendChild(row);
  }
}

function renderContacts() {
  const list = $('contact-list');
  list.textContent = '';

  if (state.contacts.length === 0) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.style.padding = '1rem';
    p.textContent = translate(state.locale, 'contacts.empty');
    list.appendChild(p);
    return;
  }

  for (const contact of state.contacts) {
    const row = document.createElement('div');
    row.className = 'contact-item';

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = initials(contact.displayName);

    const body = document.createElement('div');
    body.className = 'item-body';

    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = contact.displayName;

    const sub = document.createElement('div');
    sub.className = 'item-sub mono';
    sub.textContent = contact.safetyNumber;

    body.append(title, sub);

    const badge = document.createElement('span');
    badge.className = contact.verified ? 'badge ok' : 'badge';
    badge.textContent = contact.verified
      ? translate(state.locale, 'contacts.verifiedBadge')
      : translate(state.locale, 'chats.unverified');
    badge.style.cursor = 'pointer';
    badge.addEventListener('click', () => openSafety(contact));

    const chatBtn = document.createElement('button');
    chatBtn.className = 'btn btn-ghost';
    chatBtn.textContent = translate(state.locale, 'chats.newChat');
    chatBtn.addEventListener('click', () => startChat(contact));

    row.append(avatar, body, badge, chatBtn);
    list.appendChild(row);
  }
}

async function startChat(contact) {
  const existing = state.rooms.find((r) => r.contactId === contact.id);
  if (existing) {
    await openRoom(existing);
    return;
  }
  try {
    const room = await call('rooms:create', { contactId: contact.id, name: contact.displayName });
    state.rooms = await call('rooms:list');
    renderRooms();
    await openRoom(room);
  } catch (error) {
    toast(describe(error));
  }
}

async function openRoom(room) {
  state.activeRoom = room;
  state.activeContactId = room.contactId;
  $('conv-title').textContent = room.name;

  const badge = $('conv-badge');
  badge.className = room.verified ? 'badge ok' : 'badge';
  badge.textContent = room.verified
    ? translate(state.locale, 'chats.verified')
    : translate(state.locale, 'chats.unverified');

  showPanel('panel-conversation');
  await renderMessages();
  $('composer-input').focus();
}

async function renderMessages() {
  if (!state.activeRoom) return;
  const list = $('message-list');
  let messages;
  try {
    messages = await call('messages:list', { roomId: state.activeRoom.id });
  } catch (error) {
    toast(describe(error));
    return;
  }

  list.textContent = '';

  if (messages.length === 0) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.style.textAlign = 'center';
    p.style.margin = '2rem 0';
    p.textContent = translate(state.locale, 'chats.noMessages');
    list.appendChild(p);
    return;
  }

  for (const message of messages) {
    list.appendChild(buildBubble(message));
  }
  // Jump to the newest message.
  list.scrollTop = list.scrollHeight;
}

/** Build one message bubble. Every user-controlled value goes through textContent. */
function buildBubble(message) {
  const bubble = document.createElement('div');
  bubble.className = message.direction === 'out' ? 'bubble out' : 'bubble';

  if (message.attachment) {
    bubble.appendChild(buildAttachment(message.attachment));
  } else if (message.kind === 'text') {
    const text = document.createElement('span');
    text.textContent = message.text;
    bubble.appendChild(text);
  } else {
    // Transfer progress or a non-previewable file: show the name as text.
    const text = document.createElement('span');
    text.textContent = message.text;
    bubble.appendChild(text);
  }

  if (message.warning) {
    bubble.classList.add('warn');
    const warn = document.createElement('span');
    warn.className = 'meta';
    warn.textContent = translate(state.locale, 'error.unknownSender');
    bubble.appendChild(warn);
  }

  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = formatTime(message.sentAt);
  bubble.appendChild(meta);

  return bubble;
}

/**
 * Render an attachment.
 *
 * Images/audio/video preview inline from a data URL the service built. Everything
 * else shows a file chip with a Save button. Nothing is ever auto-opened, and the
 * only action available is "save to the app's export folder" — the app never
 * launches an external program for a received file.
 */
function buildAttachment(attachment) {
  const wrap = document.createElement('div');

  if (attachment.previewDataUrl) {
    if (attachment.category === 'image') {
      const img = document.createElement('img');
      img.src = attachment.previewDataUrl;
      img.alt = attachment.name;
      img.loading = 'lazy';
      wrap.appendChild(img);
    } else if (attachment.category === 'video') {
      const video = document.createElement('video');
      video.src = attachment.previewDataUrl;
      video.controls = true;
      video.preload = 'metadata';
      wrap.appendChild(video);
    } else if (attachment.category === 'audio') {
      const audio = document.createElement('audio');
      audio.src = attachment.previewDataUrl;
      audio.controls = true;
      audio.preload = 'metadata';
      wrap.appendChild(audio);
    }
  }

  const chip = document.createElement('div');
  chip.className = 'file-chip';

  const icon = document.createElement('span');
  icon.className = 'file-icon';
  icon.textContent = iconFor(attachment.category);

  const info = document.createElement('div');
  info.className = 'item-body';

  const name = document.createElement('div');
  name.className = 'item-title';
  name.textContent = attachment.name;

  const size = document.createElement('div');
  size.className = 'item-sub';
  size.textContent = formatBytes(attachment.size);

  info.append(name, size);
  chip.append(icon, info);
  wrap.appendChild(chip);

  if (attachment.id) {
    const actions = document.createElement('div');
    actions.className = 'file-actions';
    const save = document.createElement('button');
    save.className = 'btn btn-ghost';
    save.textContent = translate(state.locale, 'file.save');
    save.addEventListener('click', async () => {
      try {
        const result = await call('files:save', { transferId: attachment.id });
        if (result && result.saved) {
          toast(translate(state.locale, 'file.saved'));
        }
      } catch (error) {
        toast(describe(error));
      }
    });
    actions.appendChild(save);
    wrap.appendChild(actions);
  }

  return wrap;
}

function iconFor(category) {
  switch (category) {
    case 'image':
      return '🖼️';
    case 'video':
      return '🎬';
    case 'audio':
      return '🎵';
    case 'archive':
      return '🗜️';
    case 'document':
      return '📄';
    default:
      return '📎';
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

async function sendMessage() {
  if (!state.activeRoom || !state.activeContactId) return;
  const input = $('composer-input');
  const text = input.value.trim();
  if (text.length === 0) return;

  input.value = '';
  try {
    await call('messages:send', {
      roomId: state.activeRoom.id,
      contactId: state.activeContactId,
      text,
    });
    await renderMessages();
    state.rooms = await call('rooms:list');
    renderRooms();
  } catch (error) {
    toast(describe(error));
    input.value = text; // do not lose the user's text
  }
}

async function handleFileChosen(event) {
  const file = event.target.files && event.target.files[0];
  event.target.value = '';
  if (!file || !state.activeRoom || !state.activeContactId) return;

  try {
    const buffer = await file.arrayBuffer();
    // Convert to base64 in chunks: `btoa` on a huge string would blow the stack.
    const base64 = await toBase64(new Uint8Array(buffer));

    toast(translate(state.locale, 'file.sending', { name: file.name }));
    await call('messages:sendFile', {
      roomId: state.activeRoom.id,
      contactId: state.activeContactId,
      name: file.name,
      mime: file.type || 'application/octet-stream',
      dataBase64: base64,
    });
    await renderMessages();
    state.rooms = await call('rooms:list');
    renderRooms();
  } catch (error) {
    toast(describe(error));
  }
}

/** Base64-encode bytes without exceeding argument limits. */
function toBase64(bytes) {
  const CHUNK = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

function openAddContact() {
  $('contact-card-input').value = '';
  setError('contact-error', '');
  $('modal-contact').hidden = false;
  $('contact-card-input').focus();
}

async function submitContact() {
  setError('contact-error', '');
  const card = $('contact-card-input').value.trim();
  if (card.length === 0) {
    setError('contact-error', translate(state.locale, 'contacts.invalid'));
    return;
  }
  try {
    await call('contacts:add', { card });
    $('modal-contact').hidden = true;
    state.contacts = await call('contacts:list');
    renderContacts();
    toast(translate(state.locale, 'toast.contactAdded'));
  } catch (error) {
    if (error.code === 'SIGNATURE') {
      setError('contact-error', translate(state.locale, 'contacts.badSignature'));
    } else if (error.code === 'SELF') {
      setError('contact-error', translate(state.locale, 'contacts.invalid'));
    } else {
      setError('contact-error', translate(state.locale, 'contacts.invalid'));
    }
  }
}

function openSafety(contact) {
  state.pendingVerifyContact = contact;
  $('safety-intro').textContent = translate(state.locale, 'contacts.safetyIntro', { name: contact.displayName });
  $('safety-number').textContent = contact.safetyNumber;
  $('modal-safety').hidden = false;
}

async function verifyContact() {
  const contact = state.pendingVerifyContact;
  if (!contact) return;
  try {
    await call('contacts:verify', { contactId: contact.id });
    state.contacts = await call('contacts:list');
    state.rooms = await call('rooms:list');
    renderContacts();
    renderRooms();
    $('modal-safety').hidden = true;
    toast(translate(state.locale, 'toast.contactVerified'));
  } catch (error) {
    toast(describe(error));
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

async function setLocale(locale) {
  if (!LOCALES.includes(locale)) return;
  state.locale = locale;
  try {
    await call('settings:setLocale', { locale });
  } catch {
    // Keep the UI consistent even if persistence failed.
  }
  applyTranslations();
}

async function handleAutoLockChange(event) {
  // The select carries seconds. The service rejects anything outside 30..300, so
  // a tampered DOM value surfaces as a toast rather than a silent change.
  const seconds = Number(event.target.value);
  try {
    await call('settings:setAutoLock', { seconds });
    toast(translate(state.locale, 'settings.autoLockSaved'));
  } catch (error) {
    toast(describe(error));
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wire() {
  $('btn-go-create').addEventListener('click', () => {
    setError('create-error', '');
    show('screen-create');
    $('create-name').focus();
  });
  $('btn-go-unlock').addEventListener('click', () => {
    show('screen-unlock');
    $('unlock-password').focus();
  });
  $('create-back').addEventListener('click', () => show('screen-boot'));
  $('form-create').addEventListener('submit', handleCreate);

  $('toggle-create-pw').addEventListener('click', () => {
    const input = $('create-password');
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  $('copy-secret').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('totp-secret').textContent || '');
      toast(translate(state.locale, 'common.copied'));
    } catch {
      // Clipboard can be unavailable; selecting the text is a fine fallback.
    }
  });
  $('onboard-verify').addEventListener('click', handleOnboardVerify);
  $('onboard-code').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleOnboardVerify();
    }
  });

  $('recovery-ack').addEventListener('change', (e) => {
    $('recovery-done').disabled = !e.target.checked;
  });
  $('copy-recovery').addEventListener('click', async () => {
    const codes = (state.onboarding && state.onboarding.recoveryCodes) || [];
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      toast(translate(state.locale, 'common.copied'));
    } catch {
      /* ignore */
    }
  });

  $('download-recovery-csv').addEventListener('click', () => {
    downloadRecoveryCsv();
  });
  $('download-recovery-pdf').addEventListener('click', () => {
    downloadRecoveryPdf();
  });
  $('recovery-done').addEventListener('click', async () => {
    // Onboarding secrets are shown exactly once; drop them from memory now.
    state.onboarding = null;
    $('qr-canvas').width = 0;
    $('qr-canvas').height = 0;
    $('totp-secret').textContent = '';
    renderRecoveryCodes([]);
    await refreshAccountState();
  });

  $('form-unlock').addEventListener('submit', handleUnlock);
  $('use-recovery').addEventListener('click', () => {
    const box = $('recovery-fallback');
    box.hidden = !box.hidden;
    if (!box.hidden) $('unlock-recovery').focus();
  });
  $('unlock-recovery-submit').addEventListener('click', handleRecoveryUnlock);

  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => showPanel(`panel-${tab.dataset.tab}`));
  }

  $('btn-lock').addEventListener('click', lockNow);
  $('btn-lock-settings').addEventListener('click', lockNow);
  $('btn-send').addEventListener('click', sendMessage);
  $('conv-back').addEventListener('click', () => showPanel('panel-chats'));

  $('composer-input').addEventListener('keydown', (e) => {
    // Enter sends; Shift+Enter inserts a newline. This is the standard messenger
    // behaviour and avoids accidental sends on mobile multi-line input.
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  $('btn-attach').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', handleFileChosen);

  $('btn-add-contact').addEventListener('click', openAddContact);
  $('contact-cancel').addEventListener('click', () => {
    $('modal-contact').hidden = true;
  });
  $('contact-submit').addEventListener('click', submitContact);

  $('copy-my-card').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('my-card').value);
      toast(translate(state.locale, 'common.copied'));
    } catch {
      /* ignore */
    }
  });

  $('safety-close').addEventListener('click', () => {
    $('modal-safety').hidden = true;
  });
  $('safety-verify').addEventListener('click', verifyContact);

  for (const btn of document.querySelectorAll('.lang-btn')) {
    btn.addEventListener('click', () => setLocale(btn.dataset.locale));
  }

  $('autolock-select').addEventListener('change', handleAutoLockChange);

  // Close modals on backdrop click and Escape.
  for (const modal of document.querySelectorAll('.modal')) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.hidden = true;
    });
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      for (const modal of document.querySelectorAll('.modal')) modal.hidden = true;
    }
  });

  // Forced lock from the main process (idle timeout).
  bridge.onLocked(() => {
    lockNow();
  });
}


// ---------------------------------------------------------------------------
// Crypto tab: seal a message or file, or open someone else's reference.
//
// Security rules followed here:
//   - every value written into the DOM uses textContent or .value, never
//     innerHTML, so decrypted text cannot inject markup
//   - the passphrase lives in an <input> the user copies, and is cleared as soon
//     as the user starts over or the vault locks
//   - a file is handed to the reader as a Blob download, preserving its name and
//     type so the operating system opens it in the right application
// ---------------------------------------------------------------------------

/** State for the compose side. Deliberately holds no passphrase after use. */
const cryptoState = {
  file: null, // { name, mime, base64 }
  lastResult: null,
};

let pendingDownload = null;

function setCryptoMode(mode) {
  $('crypto-tab-write').classList.toggle('active', mode === 'write');
  $('crypto-tab-read').classList.toggle('active', mode === 'read');
  $('crypto-write').classList.toggle('active', mode === 'write');
  $('crypto-read').classList.toggle('active', mode === 'read');
}

function clearCryptoCompose() {
  $('crypto-text').value = '';
  cryptoState.file = null;
  cryptoState.lastResult = null;
  $('crypto-file-name').hidden = true;
  $('crypto-file-name').textContent = '';
  $('crypto-clear-file').hidden = true;
  $('crypto-file-input').value = '';
  $('crypto-result').hidden = true;
  $('crypto-ref-out').value = '';
  $('crypto-pass-out').value = '';
  setError('crypto-write-error', '');
}

function clearReadPane() {
  $('read-reference').value = '';
  $('read-passphrase').value = '';
  $('read-output').hidden = true;
  $('read-text').textContent = '';
  $('read-file-meta').textContent = '';
  $('read-text-wrap').hidden = false;
  $('read-file-wrap').hidden = true;
  pendingDownload = null;
  setError('read-error', '');
}

/** Read a picked file into base64, with a size guard before allocating. */
async function readPickedFile(file) {
  const MAX = 25 * 1024 * 1024;
  if (file.size > MAX) {
    throw new AppError('TOO_LARGE', `files are limited to ${Math.floor(MAX / 1024 / 1024)} MB`);
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return {
    name: file.name,
    mime: file.type || 'application/octet-stream',
    base64: btoa(binary),
  };
}

/**
 * Download the decrypted file.
 *
 * Blob + object URL keeps the original filename and MIME type, so the operating
 * system opens it in the right application instead of a generic download. The URL
 * is revoked after the click so the bytes do not linger.
 */
function downloadBase64(base64, fileName, mimeType) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const blob = new Blob([bytes], { type: mimeType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName || 'file';
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Give the download a moment to start before releasing the object.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Copy text to the clipboard, reporting failure rather than failing silently. */
async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = '✓';
    setTimeout(() => {
      button.textContent = original;
    }, 1200);
  } catch {
    // Clipboard can be blocked; fall back to selecting the adjacent input so the
    // user can copy manually.
    const row = button.previousElementSibling;
    if (row && typeof row.select === 'function') {
      row.select();
    }
  }
}

function wireCrypto() {
  $('crypto-tab-write').addEventListener('click', () => setCryptoMode('write'));
  $('crypto-tab-read').addEventListener('click', () => setCryptoMode('read'));

  // --- compose ---
  $('crypto-pick-file').addEventListener('click', () => $('crypto-file-input').click());

  $('crypto-file-input').addEventListener('change', async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    try {
      setError('crypto-write-error', '');
      cryptoState.file = await readPickedFile(file);
      $('crypto-file-name').textContent = file.name;
      $('crypto-file-name').hidden = false;
      $('crypto-clear-file').hidden = false;
    } catch (error) {
      setError('crypto-write-error', describe(error));
      cryptoState.file = null;
      $('crypto-file-name').hidden = true;
      $('crypto-clear-file').hidden = true;
    }
  });

  $('crypto-clear-file').addEventListener('click', () => {
    cryptoState.file = null;
    $('crypto-file-name').hidden = true;
    $('crypto-file-name').textContent = '';
    $('crypto-clear-file').hidden = true;
    $('crypto-file-input').value = '';
  });

  $('crypto-create').addEventListener('click', async () => {
    const button = $('crypto-create');
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '…';
    try {
      setError('crypto-write-error', '');
      const text = $('crypto-text').value;

      // A file wins if one is picked; text is ignored in that case, which is what
      // the user expects after choosing a file.
      const payload = cryptoState.file
        ? { dataBase64: cryptoState.file.base64, fileName: cryptoState.file.name, mimeType: cryptoState.file.mime }
        : { text };

      if (!cryptoState.file && text.trim().length === 0) {
        throw new AppError('BAD_INPUT', 'type a message or choose a file first');
      }

      const result = await call('sealed:create', payload);
      cryptoState.lastResult = result;

      $('crypto-ref-out').value = result.reference;
      $('crypto-pass-out').value = result.passphrase;
      $('crypto-result').hidden = false;

      // The plaintext leaves the box as soon as it is sealed: keeping it there
      // would leave the readable version on screen next to its ciphertext.
      $('crypto-text').value = '';
      cryptoState.file = null;
      $('crypto-file-name').hidden = true;
      $('crypto-clear-file').hidden = true;
      $('crypto-file-input').value = '';

      $('crypto-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (error) {
      setError('crypto-write-error', describe(error));
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  });

  $('crypto-copy-ref').addEventListener('click', (e) => {
    copyToClipboard($('crypto-ref-out').value, e.currentTarget);
  });
  $('crypto-copy-pass').addEventListener('click', (e) => {
    copyToClipboard($('crypto-pass-out').value, e.currentTarget);
  });

  $('crypto-save-block').addEventListener('click', () => {
    const result = cryptoState.lastResult;
    if (!result) return;
    // A small text file holding both strings, for the user who wants to keep them
    // together until they send them. It is plain text and contains the passphrase,
    // so the UI warns before this button.
    const body = [
      'YSM sealed reference',
      '',
      `Reference:  ${result.reference}`,
      `Passphrase: ${result.passphrase}`,
      '',
      `Created:    ${new Date(result.createdAt).toISOString()}`,
      `Type:       ${result.isFile ? 'file' : 'text'}`,
      ...(result.fileName ? [`File name:  ${result.fileName}`] : []),
      `Size:       ${result.size} bytes`,
      '',
      'Send the reference and the passphrase through different channels.',
      'Anyone who has both can read the content.',
    ].join('\n');
    const blob = new Blob([body], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ysm-${result.reference.slice(4, 16)}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  });

  $('crypto-new').addEventListener('click', () => {
    clearCryptoCompose();
    $('crypto-text').focus();
  });

  // --- read ---
  $('read-open').addEventListener('click', async () => {
    const button = $('read-open');
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '…';
    try {
      setError('read-error', '');
      const reference = $('read-reference').value.trim();
      const passphrase = $('read-passphrase').value.trim();
      if (reference.length === 0) throw new AppError('BAD_REFERENCE', 'paste a reference first');
      if (passphrase.length === 0) throw new AppError('BAD_PASSPHRASE', 'type the passphrase');

      const opened = await call('sealed:open', { reference, passphrase });

      $('read-output').hidden = false;

      if (opened.isFile) {
        $('read-text-wrap').hidden = true;
        $('read-file-wrap').hidden = false;
        const sizeKb = (opened.size / 1024).toFixed(1);
        $('read-file-meta').textContent = `${opened.fileName || 'file'} — ${sizeKb} KB`;
        pendingDownload = {
          base64: opened.dataBase64,
          fileName: opened.fileName,
          mimeType: opened.mimeType,
        };
      } else {
        $('read-text-wrap').hidden = false;
        $('read-file-wrap').hidden = true;
        // textContent, never innerHTML: the decrypted text is untrusted input.
        $('read-text').textContent = opened.text || '';
        pendingDownload = null;
      }

      // The passphrase is no longer needed once the content is on screen.
      $('read-passphrase').value = '';
    } catch (error) {
      setError('read-error', describe(error));
      $('read-output').hidden = true;
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  });

  $('read-copy-text').addEventListener('click', (e) => {
    copyToClipboard($('read-text').textContent || '', e.currentTarget);
  });

  $('read-download').addEventListener('click', () => {
    if (!pendingDownload || !pendingDownload.base64) return;
    downloadBase64(pendingDownload.base64, pendingDownload.fileName, pendingDownload.mimeType);
  });

  $('read-clear').addEventListener('click', clearReadPane);
}

// Clear secrets from the crypto panes whenever the vault locks, so an unattended
// screen does not keep a passphrase or decrypted text visible.
function clearCryptoOnLock() {
  clearCryptoCompose();
  clearReadPane();
}

// ---------------------------------------------------------------------------
// Recovery code export
//
// The codes are shown once. Offering a download is what makes "save these
// offline" actionable rather than a nag. Both formats contain the same secret
// material, so the file is plain text/PDF the user is expected to store safely;
// the UI says so.
// ---------------------------------------------------------------------------

/** Trigger a browser download from a Blob. */
function downloadBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function recoveryCodes() {
  return (state.onboarding && state.onboarding.recoveryCodes) || [];
}

/** Escape a value for a CSV field (RFC 4180). */
function csvField(value) {
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function downloadRecoveryCsv() {
  const codes = recoveryCodes();
  if (codes.length === 0) return;
  const when = new Date().toISOString();
  const rows = [
    ['index', 'recovery_code', 'created_at'].map(csvField).join(','),
    ...codes.map((code, i) => [String(i + 1), code, when].map(csvField).join(',')),
  ];
  // A BOM so spreadsheet applications detect UTF-8; the codes are ASCII, but the
  // header text may be localised later.
  const blob = new Blob(['\uFEFF' + rows.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
  downloadBlob(blob, `ysm-recovery-codes-${when.slice(0, 10)}.csv`);
}

/**
 * Produce a minimal but valid PDF containing the recovery codes.
 *
 * Written by hand rather than pulling a PDF library: the document is a single
 * page of fixed-width text, and a dependency here would add a large attack
 * surface to an offline, high-consequence application for one button.
 *
 * Structure: catalog -> pages -> page -> contents stream + Helvetica font. Offsets
 * are recorded as the objects are emitted so the xref table is correct; without
 * that a viewer rejects the file.
 */
function buildRecoveryPdf(title, subtitle, codes) {
  const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  const lines = [title, '', subtitle, ''];
  for (const [i, code] of codes.entries()) lines.push(`${String(i + 1).padStart(2, ' ')}.  ${code}`);

  // 18 pt title, 11 pt body.
  let text = 'BT\n';
  text += '/F1 18 Tf\n1 0 0 1 56 760 Tm\n';
  text += `(${esc(lines[0])}) Tj\n`;
  text += '/F1 11 Tf\n';
  let y = 726;
  for (const line of lines.slice(1)) {
    text += `1 0 0 1 56 ${y} Tm\n(${esc(line)}) Tj\n`;
    y -= 18;
  }
  text += 'ET\n';

  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${text.length} >>\nstream\n${text}endstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [];
  for (const [i, body] of objects.entries()) {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  }
  const xrefStart = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;

  // Latin-1 keeps the byte offsets above identical to the string lengths; a
  // multi-byte encoding would invalidate the xref table.
  const bytes = new Uint8Array(pdf.length);
  for (let i = 0; i < pdf.length; i++) bytes[i] = pdf.charCodeAt(i) & 0xff;
  return new Blob([bytes], { type: 'application/pdf' });
}

function downloadRecoveryPdf() {
  const codes = recoveryCodes();
  if (codes.length === 0) return;
  const when = new Date().toISOString().slice(0, 10);
  const pdf = buildRecoveryPdf(
    'YSM recovery codes',
    `Created ${when}. Each code works once. Keep this file offline.`,
    codes,
  );
  downloadBlob(pdf, `ysm-recovery-codes-${when}.pdf`);
}

wire();
wireCrypto();
boot();
