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
  groupChat: document.getElementById('screen-group-chat'),
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

// ---------------------------------------------------------------------
// Chats / Groups tabs
// ---------------------------------------------------------------------
const tabChatsBtn = document.getElementById('tab-chats-btn');
const tabGroupsBtn = document.getElementById('tab-groups-btn');
const paneChats = document.getElementById('pane-chats');
const paneGroups = document.getElementById('pane-groups');

tabChatsBtn.addEventListener('click', () => {
  tabChatsBtn.classList.add('tab-btn--active');
  tabGroupsBtn.classList.remove('tab-btn--active');
  paneChats.classList.remove('hidden');
  paneGroups.classList.add('hidden');
});
tabGroupsBtn.addEventListener('click', () => {
  tabGroupsBtn.classList.add('tab-btn--active');
  tabChatsBtn.classList.remove('tab-btn--active');
  paneGroups.classList.remove('hidden');
  paneChats.classList.add('hidden');
  loadGroups();
});

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
    newChatError.textContent = 'Bu ad və ya ID ilə istifadəçi tapılmadı.';
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
const bubbleById = new Map(); // messageId -> { bubble, readTick, mediaType, out }

async function openChat(peer) {
  currentPeer = peer;
  const peerPubBytes = b64decode(peer.publicKey);
  currentShared = computeSharedSecret(myIdentity.privateKey, peerPubBytes);
  currentSalt = conversationSalt(myIdentity.publicKey, peerPubBytes);
  lastMessageId = 0;
  bubbleById.clear();

  document.getElementById('chat-peer-name').textContent = peer.username;
  document.getElementById('chat-peer-id').textContent = formatId(peer.id);
  document.getElementById('message-list').innerHTML = '';
  setStatus('');
  showScreen('chat');

  tg?.BackButton?.show();

  await loadHistory();
  api('/api/messages/read-all', { method: 'POST', body: { peerId: peer.id } }).catch(() => {});
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
  if (m.deletedAt) {
    appendSystemBubble('🗑️ Mesaj silindi', m.id);
    return;
  }
  let plaintext;
  try {
    plaintext = decryptMessage(b64decode(m.packet), currentShared, currentSalt);
  } catch {
    appendSystemBubble('⚠️ Mesaj doğrulanmadı (manipulyasiya aşkarlandı)');
    return;
  }
  renderPlaintext(plaintext, m.mediaType, m.senderId === myProfile.id, m.createdAt, m.id, Boolean(m.readAt), Boolean(m.editedAt));
}

function renderPlaintext(bytes, mediaType, out, createdAtIso, messageId, isRead, isEdited) {
  const bubble = document.createElement('div');
  bubble.className = 'bubble ' + (out ? 'bubble--out' : 'bubble--in');
  if (messageId) bubble.dataset.messageId = messageId;

  if (mediaType === 'text') {
    const textSpan = document.createElement('span');
    textSpan.className = 'bubble__text';
    textSpan.textContent = new TextDecoder().decode(bytes);
    bubble.appendChild(textSpan);
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

  const meta = document.createElement('span');
  meta.className = 'bubble__meta';
  const editedTag = isEdited ? '<span class="bubble__edited">redaktə edilib</span>' : '';
  const time = formatTime(createdAtIso || new Date().toISOString());
  const tick = out ? `<span class="bubble__tick ${isRead ? 'bubble__tick--read' : ''}" data-tick="${messageId || ''}">${isRead ? '✓✓' : '✓'}</span>` : '';
  meta.innerHTML = `${editedTag}<span class="bubble__time">${time}</span>${tick}`;
  bubble.appendChild(meta);

  // Delete/edit affordance for my own text messages.
  if (out && messageId && mediaType === 'text') {
    const actions = document.createElement('div');
    actions.className = 'bubble__actions';
    const editBtn = document.createElement('button');
    editBtn.textContent = '✏️';
    editBtn.title = 'Redaktə et';
    editBtn.addEventListener('click', () => editOwnMessage(messageId, bubble));
    const delBtn = document.createElement('button');
    delBtn.textContent = '🗑️';
    delBtn.title = 'Sil';
    delBtn.addEventListener('click', () => deleteOwnMessage(messageId, bubble));
    actions.appendChild(editBtn);
    actions.appendChild(delBtn);
    bubble.appendChild(actions);
  }

  if (messageId) bubbleById.set(messageId, { bubble, out, mediaType });

  document.getElementById('message-list').appendChild(bubble);
  scrollToBottom();
}

async function editOwnMessage(messageId, bubble) {
  const textSpan = bubble.querySelector('.bubble__text');
  const current = textSpan ? textSpan.textContent : '';
  const next = prompt('Mesajı redaktə et:', current);
  if (next === null || next.trim() === '' || next === current) return;

  const bytes = new TextEncoder().encode(next);
  const packet = encryptMessage(bytes, currentShared, currentSalt);
  const { status } = await api(`/api/messages/${messageId}`, {
    method: 'PUT',
    body: { packet: b64encode(packet) },
  });
  if (status === 200 && textSpan) {
    textSpan.textContent = next;
    const meta = bubble.querySelector('.bubble__meta');
    if (meta && !meta.querySelector('.bubble__edited')) {
      meta.insertAdjacentHTML('afterbegin', '<span class="bubble__edited">redaktə edilib</span>');
    }
  }
}

async function deleteOwnMessage(messageId, bubble) {
  if (!confirm('Bu mesajı hər iki tərəf üçün silmək istəyirsən?')) return;
  const url = new URL(`/api/messages/${messageId}`, location.origin);
  url.searchParams.set('initData', initData);
  const res = await fetch(url, { method: 'DELETE' });
  if (res.status === 200) {
    bubble.outerHTML = `<div class="bubble bubble--system">🗑️ Mesaj silindi</div>`;
    bubbleById.delete(messageId);
  }
}

function appendSystemBubble(text, messageId) {
  const b = document.createElement('div');
  b.className = 'bubble bubble--system';
  b.textContent = text;
  if (messageId) bubbleById.set(messageId, { bubble: b, out: false, mediaType: 'system' });
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
    renderPlaintext(bytes, mediaType, true, body.createdAt, body.id, false, false);
    lastMessageId = Math.max(lastMessageId, body.id);
  } else if (status === 429) {
    setStatus('Çox tez-tez göndərirsən, bir az gözlə.');
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

    if (data.type === 'message') {
      if (currentPeer && data.senderId === currentPeer.id) {
        renderMessage({
          id: data.id,
          senderId: data.senderId,
          mediaType: data.mediaType,
          packet: data.packet,
          createdAt: data.createdAt,
        });
        lastMessageId = Math.max(lastMessageId, data.id);
        api('/api/messages/read-all', { method: 'POST', body: { peerId: data.senderId } }).catch(() => {});
      }
      loadConversations();
      return;
    }

    if (data.type === 'read' || data.type === 'read_bulk') {
      const ids = data.type === 'read' ? [data.messageId] : data.messageIds;
      for (const id of ids) {
        const entry = bubbleById.get(id);
        const tick = entry?.bubble?.querySelector?.(`[data-tick="${id}"]`);
        if (tick) {
          tick.textContent = '✓✓';
          tick.classList.add('bubble__tick--read');
        }
      }
      return;
    }

    if (data.type === 'deleted') {
      const entry = bubbleById.get(data.messageId);
      if (entry?.bubble) entry.bubble.outerHTML = `<div class="bubble bubble--system">🗑️ Mesaj silindi</div>`;
      return;
    }

    if (data.type === 'edited') {
      if (!currentPeer) return;
      const entry = bubbleById.get(data.messageId);
      if (!entry?.bubble) return;
      try {
        const plaintext = decryptMessage(b64decode(data.packet), currentShared, currentSalt);
        const textSpan = entry.bubble.querySelector('.bubble__text');
        if (textSpan) textSpan.textContent = new TextDecoder().decode(plaintext);
        const meta = entry.bubble.querySelector('.bubble__meta');
        if (meta && !meta.querySelector('.bubble__edited')) {
          meta.insertAdjacentHTML('afterbegin', '<span class="bubble__edited">redaktə edilib</span>');
        }
      } catch {
        /* ignore malformed edit */
      }
      return;
    }

    if (data.type === 'key_rotated') {
      appendSystemBubble(`⚠️ ${data.peerUsername} təhlükəsizlik açarını dəyişdi. Etibarlılığı təsdiqləmək istəyirsənsə, ondan başqa kanaldan soruş.`);
      if (currentPeer && currentPeer.id === data.peerId) {
        currentPeer.publicKey = data.newPublicKey;
        const peerPubBytes = b64decode(data.newPublicKey);
        currentShared = computeSharedSecret(myIdentity.privateKey, peerPubBytes);
        currentSalt = conversationSalt(myIdentity.publicKey, peerPubBytes);
      }
      loadConversations();
      return;
    }

    if (data.type === 'group_message') {
      if (currentGroup && data.groupId === currentGroup.id) {
        renderGroupMessage(data);
      }
      loadGroups();
      return;
    }
  });

  ws.addEventListener('close', () => {
    setTimeout(connectWS, 3000);
  });
}

// ---------------------------------------------------------------------
// Groups — E2E stays end-to-end: for every group message we encrypt
// the plaintext once per member with the same pairwise crypto used for
// 1-1 chats, and send the whole set of packets to the server, which
// only fans them out.
// ---------------------------------------------------------------------
let currentGroup = null; // { id, name, members: [{id, username, publicKey}] }
let groupBubbleId = 0;

const newGroupBtn = document.getElementById('new-group-btn');
const newGroupError = document.getElementById('new-group-error');

newGroupBtn.addEventListener('click', async () => {
  newGroupError.classList.add('hidden');
  const name = document.getElementById('new-group-name').value.trim();
  const idsRaw = document.getElementById('new-group-members').value.trim();
  if (!name) return;
  const memberIds = idsRaw
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0);

  const { status, body } = await api('/api/groups', { method: 'POST', body: { name, memberIds } });
  if (status !== 200) {
    newGroupError.textContent = 'Qrup yaradıla bilmədi.';
    newGroupError.classList.remove('hidden');
    return;
  }
  document.getElementById('new-group-name').value = '';
  document.getElementById('new-group-members').value = '';
  loadGroups();
});

async function loadGroups() {
  const { status, body } = await api('/api/groups');
  const list = document.getElementById('group-list');
  const empty = document.getElementById('group-empty');
  list.innerHTML = '';
  if (status !== 200) return;

  if (body.groups.length === 0) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  for (const g of body.groups) {
    const row = document.createElement('div');
    row.className = 'conv-row';
    row.innerHTML = `
      <div class="conv-row__main">
        <div class="conv-row__name">👥 ${escapeHtml(g.name)}</div>
        <div class="conv-row__preview">${g.memberCount} üzv</div>
      </div>
    `;
    row.addEventListener('click', () => openGroup(g));
    list.appendChild(row);
  }
}

async function openGroup(g) {
  const { status, body } = await api(`/api/groups/${g.id}/members`);
  if (status !== 200) return;
  currentGroup = { id: g.id, name: g.name, members: body.members };

  document.getElementById('group-chat-name').textContent = g.name;
  document.getElementById('group-chat-members').textContent = `${body.members.length} üzv`;
  document.getElementById('group-message-list').innerHTML = '';
  showScreen('groupChat');
  tg?.BackButton?.show();

  await loadGroupHistory();
}

document.getElementById('group-back').addEventListener('click', () => {
  currentGroup = null;
  showScreen('chats');
  loadGroups();
});

async function loadGroupHistory() {
  const { status, body } = await api(`/api/groups/${currentGroup.id}/messages?afterId=0`);
  if (status !== 200) return;
  for (const m of body.messages) renderGroupMessage(m);
  const list = document.getElementById('group-message-list');
  list.scrollTop = list.scrollHeight;
}

function renderGroupMessage(m) {
  const sender = currentGroup.members.find((mem) => mem.id === m.senderId);
  const senderPub = sender ? b64decode(sender.publicKey) : null;
  let plaintext;
  try {
    if (m.senderId === myProfile.id) {
      // My own sent message: decrypt using my own copy of the packet the server echoed back,
      // encrypted for myself (see sendGroupMessage — we include ourselves as a recipient).
      const shared = computeSharedSecret(myIdentity.privateKey, myIdentity.publicKey);
      plaintext = decryptMessage(b64decode(m.packet), shared, conversationSalt(myIdentity.publicKey, myIdentity.publicKey));
    } else {
      const shared = computeSharedSecret(myIdentity.privateKey, senderPub);
      const salt = conversationSalt(myIdentity.publicKey, senderPub);
      plaintext = decryptMessage(b64decode(m.packet), shared, salt);
    }
  } catch {
    appendGroupSystemBubble('⚠️ Mesaj doğrulanmadı');
    return;
  }

  const bubble = document.createElement('div');
  const out = m.senderId === myProfile.id;
  bubble.className = 'bubble ' + (out ? 'bubble--out' : 'bubble--in');
  if (!out) {
    const nameTag = document.createElement('div');
    nameTag.className = 'bubble__sender';
    nameTag.textContent = m.senderUsername || sender?.username || ('#' + m.senderId);
    bubble.appendChild(nameTag);
  }
  if (m.mediaType === 'text') {
    bubble.appendChild(document.createTextNode(new TextDecoder().decode(plaintext)));
  } else {
    const blob = new Blob([plaintext], { type: guessMime(m.mediaType) });
    const url = URL.createObjectURL(blob);
    const el = document.createElement(m.mediaType === 'video' ? 'video' : m.mediaType === 'audio' ? 'audio' : 'img');
    el.src = url;
    if (m.mediaType !== 'image') el.controls = true;
    bubble.appendChild(el);
  }
  const time = document.createElement('span');
  time.className = 'bubble__time';
  time.textContent = formatTime(m.createdAt || new Date().toISOString());
  bubble.appendChild(time);

  document.getElementById('group-message-list').appendChild(bubble);
  document.getElementById('group-message-list').scrollTop = 1e9;
}

function appendGroupSystemBubble(text) {
  const b = document.createElement('div');
  b.className = 'bubble bubble--system';
  b.textContent = text;
  document.getElementById('group-message-list').appendChild(b);
}

document.getElementById('group-send-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('group-message-input');
  const text = input.value.trim();
  if (!text || !currentGroup) return;
  input.value = '';

  const bytes = new TextEncoder().encode(text);
  const packets = [];
  for (const member of currentGroup.members) {
    let shared, salt;
    if (member.id === myProfile.id) {
      // Encrypt a copy for myself too, so my own device can re-render its own sent messages
      // (and so a second device of mine could read history) without storing plaintext server-side.
      shared = computeSharedSecret(myIdentity.privateKey, myIdentity.publicKey);
      salt = conversationSalt(myIdentity.publicKey, myIdentity.publicKey);
    } else {
      const pub = b64decode(member.publicKey);
      shared = computeSharedSecret(myIdentity.privateKey, pub);
      salt = conversationSalt(myIdentity.publicKey, pub);
    }
    const packet = encryptMessage(bytes, shared, salt);
    packets.push({ recipientId: member.id, packet: b64encode(packet) });
  }

  const { status, body } = await api(`/api/groups/${currentGroup.id}/messages`, {
    method: 'POST',
    body: { mediaType: 'text', packets },
  });
  if (status === 200) {
    renderGroupMessage({ id: body.id, senderId: myProfile.id, mediaType: 'text', createdAt: body.createdAt, packet: packets.find((p) => p.recipientId === myProfile.id).packet });
  }
});

// ---------------------------------------------------------------------
// Key rotation — if this device's local identity doesn't match what the
// server has on file (e.g. Telegram CloudStorage was cleared, or this is
// a fresh install under the same Telegram account), push the new public
// key to the server so peers get a verifiable rotation notice instead of
// silently failing to decrypt.
// ---------------------------------------------------------------------
async function reconcileIdentity(serverPublicKeyB64) {
  const localPubB64 = b64encode(myIdentity.publicKey);
  if (localPubB64 === serverPublicKeyB64) return serverPublicKeyB64;

  const { status, body } = await api('/api/key/rotate', {
    method: 'POST',
    body: { newPublicKey: localPubB64 },
  });
  return status === 200 ? body.publicKey : serverPublicKeyB64;
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
    myIdentity = await loadOrCreateIdentity();
    const reconciledKey = await reconcileIdentity(body.publicKey);
    myProfile = { id: body.id, username: body.username, publicKey: reconciledKey };
    enterApp();
  } else if (status === 403 && body.error === 'banned') {
    document.getElementById('screen-loading').innerHTML =
      '<p class="muted">Hesabın məhdudlaşdırılıb.</p>';
  } else {
    showScreen('register');
  }
}

init();
