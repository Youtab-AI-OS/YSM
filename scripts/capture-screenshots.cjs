/**
 * Capture screenshots at phone width for visual verification.
 *
 * Produces PNG files under docs/screenshots/ so the responsive claim can be
 * checked by eye, not just by numbers.
 */
const { app, BrowserWindow } = require('electron');
const { join } = require('node:path');
const { mkdirSync, writeFileSync } = require('node:fs');

const INDEX = join(__dirname, '..', 'renderer', 'index.html');
const PRELOAD = join(__dirname, '..', 'electron', 'preload.cjs');
const OUT = join(__dirname, '..', 'docs', 'screenshots');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.whenReady().then(async () => {
  mkdirSync(OUT, { recursive: true });

  const win = new BrowserWindow({
    width: 390,
    height: 844,
    show: false,
    webPreferences: { preload: PRELOAD, contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  await win.loadFile(INDEX);

  await sleep(1200);
  win.show();
  await sleep(500);

  async function shot(name) {
    const image = await win.webContents.capturePage();
    writeFileSync(join(OUT, `${name}.png`), image.toPNG());
    console.log(`captured ${name}.png (${image.getSize().width}x${image.getSize().height})`);
  }

  await shot('01-boot-mobile');

  // Show the create form.
  await win.webContents.executeJavaScript(`document.getElementById('btn-go-create').click()`);
  await sleep(400);
  await shot('02-create-mobile');

  // Show the main shell with sample conversations so the responsive layout is visible.
  await win.webContents.executeJavaScript(`(() => {
    for (const el of document.querySelectorAll('.screen')) el.classList.remove('active');
    document.getElementById('screen-main').classList.add('active');
    for (const el of document.querySelectorAll('.panel')) el.classList.remove('active');
    document.getElementById('panel-chats').classList.add('active');

    const list = document.getElementById('room-list');
    const empty = document.getElementById('room-empty');
    empty.hidden = true;
    list.textContent = '';
    const samples = [
      ['Bob', 'see you at nine'],
      ['Sara', 'the photos came through'],
      ['Team', 'review meeting moved'],
    ];
    for (const [name, last] of samples) {
      const row = document.createElement('div');
      row.className = 'room-item';
      const av = document.createElement('div');
      av.className = 'avatar';
      av.textContent = name.slice(0, 2).toUpperCase();
      const body = document.createElement('div');
      body.className = 'item-body';
      const t = document.createElement('div');
      t.className = 'item-title';
      t.textContent = name;
      const s = document.createElement('div');
      s.className = 'item-sub';
      s.textContent = last;
      body.append(t, s);
      const badge = document.createElement('span');
      badge.className = 'badge ok';
      badge.textContent = 'Verified';
      row.append(av, body, badge);
      list.appendChild(row);
    }
    document.querySelector('#me').textContent = 'Alice';
  })()`);
  await sleep(400);
  await shot('03-chats-mobile');

  // A conversation with a photo message.
  await win.webContents.executeJavaScript(`(() => {
    for (const el of document.querySelectorAll('.panel')) el.classList.remove('active');
    document.getElementById('panel-conversation').classList.add('active');
    document.getElementById('conv-title').textContent = 'Bob';
    const badge = document.getElementById('conv-badge');
    badge.className = 'badge ok';
    badge.textContent = 'Verified';

    const list = document.getElementById('message-list');
    list.textContent = '';
    const mk = (text, out) => {
      const b = document.createElement('div');
      b.className = out ? 'bubble out' : 'bubble';
      const span = document.createElement('span');
      span.textContent = text;
      const meta = document.createElement('span');
      meta.className = 'meta';
      meta.textContent = '21:04';
      b.append(span, meta);
      return b;
    };
    list.append(
      mk('Did the encrypted photo arrive?', false),
      mk('Yes — decrypted fine on my side.', true),
      mk('Nice. Same safety number on both phones?', false),
      mk('Matches exactly. Verified.', true),
    );
  })()`);
  await sleep(300);
  await shot('04-conversation-mobile');

  // Farsi RTL.
  await win.webContents.executeJavaScript(`(async () => {
    const btn = document.querySelector('.lang-btn[data-locale="fa"]');
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 400));
  })()`);
  await sleep(400);
  await shot('05-conversation-farsi-mobile');

  // Contacts view.
  await win.webContents.executeJavaScript(`(() => {
    const btn = document.querySelector('.lang-btn[data-locale="en"]');
    if (btn) btn.click();
    for (const el of document.querySelectorAll('.panel')) el.classList.remove('active');
    document.getElementById('panel-contacts').classList.add('active');
    const list = document.getElementById('contact-list');
    list.textContent = '';
    const mk = (name, sn, verified) => {
      const row = document.createElement('div');
      row.className = 'contact-item';
      const av = document.createElement('div');
      av.className = 'avatar';
      av.textContent = name.slice(0, 2).toUpperCase();
      const body = document.createElement('div');
      body.className = 'item-body';
      const t = document.createElement('div');
      t.className = 'item-title';
      t.textContent = name;
      const s = document.createElement('div');
      s.className = 'item-sub mono';
      s.textContent = sn;
      body.append(t, s);
      const badge = document.createElement('span');
      badge.className = verified ? 'badge ok' : 'badge';
      badge.textContent = verified ? 'Verified' : 'Not verified';
      const chat = document.createElement('button');
      chat.className = 'btn btn-ghost';
      chat.textContent = 'Chat';
      row.append(av, body, badge, chat);
      return row;
    };
    list.append(
      mk('Bob', '27258 27853 05831 35346 14843 37531 63055 73813', true),
      mk('Sara', '54041 82839 95527 60012 85101 86987 46884 07806', false),
    );
  })()`);
  await sleep(400);
  await shot('06-contacts-mobile');

  win.destroy();
  setTimeout(() => app.exit(0), 200);
});
