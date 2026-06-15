import {
  generateKeyPair,
  publicKeyFromPrivate,
  computeSharedSecret,
  conversationSalt,
  encryptMessage,
  decryptMessage,
} from '../crypto-engine/index.js';

const tg = window.Telegram?.WebApp;
const initData = tg?.initData || '';

// ---------------------------------------------------------------------
// DOM / screen helpers
// ---------------------------------------------------------------------
const screens = {
  loading: document.getElementById('screen-loading'),
  register: document.getElementById('screen-register'),
  chats: document.getElementById('screen-chats'),
  chat: document.getElementById('screen-chat'),
};
function showScreen(name) {
  for (const k in screens) screens[k].classList.toggle('hidden', k !== name);
}

function formatId(id) {
  return '#' + String(id).padStart(6, '0');
}
function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString('az-AZ', { hour: '2-digit', minute: '2-digit' });
}
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function mediaLabel(t) {
  return { text: 'Mesaj', image: 'Şəkil', video: 'Video', audio: 'Səsli mesaj' }[t] || 'Mesaj';
}
function guessMime(mediaType) {
  return { image: 'image/jpeg', video: 'video/mp4', audio: 'audio/ogg' }[mediaType] || 'application/octet-stream';
}

// ---------------------------------------------------------------------
// base64 <-> Uint8Array
// ---------------------------------------------------------------------
function b64encode(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function b64decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------------------------------------------------------------------
// Identity (X25519 keypair) — private key lives ONLY in Telegram
// CloudStorage (synced to the user's own Telegram account, never sent to
// our server).
// ---------------------------------------------------------------------
const PRIVKEY_STORAGE_KEY = 'mh_privkey_v1';

function cloudGet(key) {
  return new Promise((resolve) => {
    if (!tg?.CloudStorage) return resolve(null);
    tg.CloudStorage.getItem(key, (err, value) => resolve(err ? null : value || null));
  });
}
function cloudSet(key, value) {
  return new Promise((resolve) => {
    if (!tg?.CloudStorage) return resolve(false);
    tg.CloudStorage.setItem(key, value, (err, ok) => resolve(!err && ok));
  });
}

async function loadOrCreateIdentity() {
  const stored = await cloudGet(PRIVKEY_STORAGE_KEY);
  if (stored) {
    const privateKey = b64decode(stored);
    return { privateKey, publicKey: publicKeyFromPrivate(privateKey) };
  }
  const kp = generateKeyPair();
  await cloudSet(PRIVKEY_STORAGE_KEY, b64encode(kp.privateKey));
  return kp;
}

let myIdentity = null; // { privateKey, publicKey } — Uint8Array(32) each
let myProfile = null; // { id, username, publicKey: base64 }

// ---------------------------------------------------------------------
// API helper — every call carries Telegram's initData for auth.
// ---------------------------------------------------------------------
async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  let res;
  if (method === 'GET') {
    const url = new URL(path, location.origin);
    url.searchParams.set('initData', initData);
    res = await fetch(url);
  } else {
    res = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...(opts.body || {}), initData }),
    });
  }
  let body = {};
  try {
    body = await res.json();
  } catch {
    /* ignore */
  }
  return { status: res.status, body };
}

// ---------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------
const registerForm = document.getElementById('register-form');
const registerError = document.getElementById('register-error');

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  registerError.classList.add('hidden');

  const name = document.getElementById('register-name').value.trim();
  if (name.length < 2) {
    showRegisterError('Ad ən azı 2 simvol olmalıdır.');
    return;
  }

  const submitBtn = registerForm.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Açar yaradılır…';

  try {
    myIdentity = await loadOrCreateIdentity();
    const pubB64 = b64encode(myIdentity.publicKey);
    const { status, body } = await api('/api/register', {
      method: 'POST',
      body: { username: name, publicKey: pubB64 },
    });

    if (status === 409) {
      showRegisterError('Bu ad artıq istifadə olunur, başqasını seç.');
      return;
    }
    if (status !== 200) {
      showRegisterError('Xəta baş verdi, yenidən cəhd et.');
      return;
    }
    myProfile = { id: body.id, username: body.username, publicKey: body.publicKey };
    enterApp();
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Açar yarat və davam et';
  }
});

function showRegisterError(text) {
  registerError.textContent = text;
  registerError.classList.remove('hidden');
}

// ---------------------------------------------------------------------
// Chat list
// ---------------------------------------------------------------------
function enterApp() {
  document.getElementById('my-id-chip').textContent = formatId(myProfile.id);
  showScreen('chats');
  loadConversations();
  connectWS();
}

async function loadConversations() {
  const { status, body } = await api('/api/conversations');
  const list = document.getElementById('conversation-list');
  const empty = document.getElementById('conv-empty');
  list.innerHTML = '';

  if (status !== 200) return;

  if (body.conversations.length === 0) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  for (const c of body.conversations) {
    const row = document.createElement('div');
    row.className = 'conv-row';
    row.innerHTML = `
      <div class="conv-row__main">
        <div class="conv-row__name">${escapeHtml(c.peerUsername)}</div>
        <div class="conv-row__preview">🔒 ${mediaLabel(c.lastMediaType)}</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;">
        <div class="id-chip id-chip--sm">${formatId(c.peerId)}</div>
        <div class="conv-row__time">${c.lastMessageAt ? formatTime(c.lastMessageAt) : ''}</div>
      </div>
    `;
    row.addEventListener('click', () =>
      openChat({ id: c.peerId, username: c.peerUsername, publicKey: c.peerPublicKey })
    );
    list.appendChild(row);
  }
}

const newChatBtn = document.getElementById('new-chat-btn');
const newChatInput = document.getElementById('new-chat-username');
const newChatError = document.getElementById('new-chat-error');

newChatBtn.addEventListener('click', async () => {
  newChatError.classList.add('hidden');
  const uname = newChatInput.value.trim();
  if (!uname) return;

  const { status, body } = await api('/api/users/' + encodeURIComponent(uname));
  if (status === 404) {
    newChatError.textContent = 'Bu adda istifadəçi tapılmadı.';
    newChatError.classList.remove('hidden');
    return;
  }
  if (status !== 200) {
    newChatError.textContent = 'Xəta baş verdi.';
    newChatError.classList.remove('hidden');
    return;
  }
  newChatInput.value = '';
  openChat(body);
});

// ---------------------------------------------------------------------
// Chat view
// ---------------------------------------------------------------------
let currentPeer = null; // { id, username, publicKey: base64 }
let currentShared = null; // Uint8Array(32)
let currentSalt = null; // Uint8Array(32)
let lastMessageId = 0;

async function openChat(peer) {
  currentPeer = peer;
  const peerPubBytes = b64decode(peer.publicKey);
  currentShared = computeSharedSecret(myIdentity.privateKey, peerPubBytes);
  currentSalt = conversationSalt(myIdentity.publicKey, peerPubBytes);
  lastMessageId = 0;

  document.getElementById('chat-peer-name').textContent = peer.username;
  document.getElementById('chat-peer-id').textContent = formatId(peer.id);
  document.getElementById('message-list').innerHTML = '';
  setStatus('');
  showScreen('chat');

  tg?.BackButton?.show();

  await loadHistory();
}

function leaveChat() {
  currentPeer = null;
  tg?.BackButton?.hide();
  showScreen('chats');
  loadConversations();
}
document.getElementById('chat-back').addEventListener('click', leaveChat);
tg?.BackButton?.onClick(leaveChat);

async function loadHistory() {
  const { status, body } = await api(`/api/messages/${currentPeer.id}?afterId=0`);
  if (status !== 200) return;
  for (const m of body.messages) {
    renderMessage(m);
    lastMessageId = Math.max(lastMessageId, m.id);
  }
  scrollToBottom();
}

function renderMessage(m) {
  let plaintext;
  try {
    plaintext = decryptMessage(b64decode(m.packet), currentShared, currentSalt);
  } catch {
    appendSystemBubble('⚠️ Mesaj doğrulanmadı (manipulyasiya aşkarlandı)');
    return;
  }
  renderPlaintext(plaintext, m.mediaType, m.senderId === myProfile.id, m.createdAt);
}

function renderPlaintext(bytes, mediaType, out, createdAtIso) {
  const bubble = document.createElement('div');
  bubble.className = 'bubble ' + (out ? 'bubble--out' : 'bubble--in');

  if (mediaType === 'text') {
    bubble.appendChild(document.createTextNode(new TextDecoder().decode(bytes)));
  } else {
    const blob = new Blob([bytes], { type: guessMime(mediaType) });
    const url = URL.createObjectURL(blob);
    let el;
    if (mediaType === 'image') {
      el = document.createElement('img');
      el.src = url;
    } else if (mediaType === 'video') {
      el = document.createElement('video');
      el.src = url;
      el.controls = true;
    } else {
      el = document.createElement('audio');
      el.src = url;
      el.controls = true;
    }
    bubble.appendChild(el);
  }

  const time = document.createElement('span');
  time.className = 'bubble__time';
  time.textContent = formatTime(createdAtIso || new Date().toISOString());
  bubble.appendChild(time);

  document.getElementById('message-list').appendChild(bubble);
  scrollToBottom();
}

function appendSystemBubble(text) {
  const b = document.createElement('div');
  b.className = 'bubble bubble--system';
  b.textContent = text;
  document.getElementById('message-list').appendChild(b);
  scrollToBottom();
}

function scrollToBottom() {
  const list = document.getElementById('message-list');
  list.scrollTop = list.scrollHeight;
}

function setStatus(text) {
  const el = document.getElementById('chat-status');
  if (!text) {
    el.classList.add('hidden');
    el.textContent = '';
    return;
  }
  el.textContent = text;
  el.classList.remove('hidden');
}

// ---------------------------------------------------------------------
// Sending — text & media (image/video/audio) share the same path: every
// payload is just bytes through encryptMessage().
// ---------------------------------------------------------------------
async function sendBytes(bytes, mediaType) {
  const packet = encryptMessage(bytes, currentShared, currentSalt);
  if (mediaType !== 'text') setStatus('Şifrələnir və göndərilir…');

  const { status, body } = await api('/api/messages', {
    method: 'POST',
    body: { recipientId: currentPeer.id, mediaType, packet: b64encode(packet) },
  });

  setStatus('');
  if (status === 200) {
    renderPlaintext(bytes, mediaType, true, body.createdAt);
    lastMessageId = Math.max(lastMessageId, body.id);
  } else {
    setStatus('Göndərilmədi (xəta ' + status + ').');
  }
}

const sendForm = document.getElementById('send-form');
const messageInput = document.getElementById('message-input');
sendForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !currentPeer) return;
  messageInput.value = '';
  await sendBytes(new TextEncoder().encode(text), 'text');
});

const fileInput = document.getElementById('file-input');
fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file || !currentPeer) return;

  const mediaType = file.type.startsWith('image/')
    ? 'image'
    : file.type.startsWith('video/')
    ? 'video'
    : file.type.startsWith('audio/')
    ? 'audio'
    : null;

  if (!mediaType) {
    setStatus('Dəstəklənməyən fayl növü (yalnız şəkil/video/səs).');
    return;
  }
  const MAX = 14 * 1024 * 1024;
  if (file.size > MAX) {
    setStatus('Fayl çox böyükdür (maksimum ~14MB).');
    return;
  }
  const buf = new Uint8Array(await file.arrayBuffer());
  await sendBytes(buf, mediaType);
});

// ---------------------------------------------------------------------
// WebSocket — real-time delivery of new messages.
// ---------------------------------------------------------------------
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws?initData=${encodeURIComponent(initData)}`);

  ws.addEventListener('message', (ev) => {
    let data;
    try {
      data = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (data.type !== 'message') return;

    if (currentPeer && data.senderId === currentPeer.id) {
      renderMessage({
        id: data.id,
        senderId: data.senderId,
        mediaType: data.mediaType,
        packet: data.packet,
        createdAt: data.createdAt,
      });
      lastMessageId = Math.max(lastMessageId, data.id);
    }
    loadConversations();
  });

  ws.addEventListener('close', () => {
    setTimeout(connectWS, 3000);
  });
}

// ---------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------
async function init() {
  if (!tg) {
    document.getElementById('screen-loading').innerHTML =
      '<p class="muted">Bu tətbiq Telegram daxilində açılmalıdır.</p>';
    return;
  }
  tg.ready();
  tg.expand();

  const { status, body } = await api('/api/me');
  if (status === 200 && body.registered) {
    myProfile = { id: body.id, username: body.username, publicKey: body.publicKey };
    myIdentity = await loadOrCreateIdentity();
    enterApp();
  } else {
    showScreen('register');
  }
}

init();
