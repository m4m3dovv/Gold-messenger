import 'dotenv/config';
import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';

import { validateInitData } from './telegramAuth.js';
import { startBot } from './bot.js';
import { validateUsername } from './username.js';
import {
  initSchema,
  findUserByTelegramId,
  findUserByUsername,
  findUserById,
  createUser,
  touchLastSeen,
  rotateUserKey,
  getPeerIdsOf,
  insertMessage,
  getConversation,
  getConversationList,
  markMessageRead,
  markConversationRead,
  deleteMessage,
  editMessage,
  createGroup,
  isGroupMember,
  getGroupMembers,
  addGroupMember,
  removeGroupMember,
  getUserGroups,
  insertGroupMessage,
  getGroupHistory,
  getTelegramIdOf,
  adminGetStats,
  adminListUsers,
  adminSetBanned,
} from './db.js';
import { checkAdminCredentials, issueAdminToken, adminMiddleware } from './adminAuth.js';
import { pushTelegramNotice, newMessageNotice, keyRotatedNotice } from './notify.js';
import { mediaStorageEnabled, shouldOffload, uploadPacket, downloadPacket, isPointer, makePointer, readPointerKey } from './media.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BOT_TOKEN = process.env.BOT_TOKEN;
const MINIAPP_URL = process.env.MINIAPP_URL;
const PORT = process.env.PORT || 3000;

const app = express();
app.set('trust proxy', 1); // Railway/behind a proxy — needed for correct rate-limit IPs
app.use(express.json({ limit: '20mb' }));

// ---------------------------------------------------------------------
// Rate limiting — protects register/login and message-sending from
// abuse/spam/DoS. Generous enough for normal chat use.
// ---------------------------------------------------------------------
const generalLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false });
const registerLimiter = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });
const messageLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false });
const adminLoginLimiter = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });

app.use('/api/', generalLimiter);

// ---------------------------------------------------------------------
// Auth helper — every API call carries `initData` (from
// Telegram.WebApp.initData on the client). We validate it, then look up
// the corresponding app user. telegramId is used ONLY for this lookup and
// is never returned to clients.
// ---------------------------------------------------------------------
async function authenticate(initData) {
  const tg = validateInitData(initData, BOT_TOKEN);
  if (!tg) return { error: 'invalid_init_data' };
  const user = await findUserByTelegramId(tg.telegramId);
  if (user?.is_banned) return { error: 'banned' };
  if (user) touchLastSeen(user.id).catch(() => {});
  return { tg, user }; // user may be null if not yet registered
}

function isValidPublicKeyB64(s) {
  if (typeof s !== 'string') return false;
  try {
    return Buffer.from(s, 'base64').length === 32;
  } catch {
    return false;
  }
}

function parseLookupId(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().replace(/^#/, '');
  if (!/^\d{1,6}$/.test(normalized)) return null;

  const id = Number(normalized);
  return Number.isInteger(id) && id > 0 ? id : null;
}

/** Resolve a stored packet buffer to base64, transparently fetching from
 * object storage if it's a pointer (large media offloaded to S3-compatible storage). */
async function packetToBase64(buf) {
  if (mediaStorageEnabled && isPointer(buf)) {
    const real = await downloadPacket(readPointerKey(buf));
    return real.toString('base64');
  }
  return buf.toString('base64');
}

async function storePacketBuffer(buf) {
  if (shouldOffload(buf)) {
    const key = await uploadPacket(buf);
    return makePointer(key);
  }
  return buf;
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

app.get('/health', (_req, res) => res.json({ ok: true, mediaStorage: mediaStorageEnabled }));

// Register a new app profile. Only the display name + X25519 public key
// are stored — no phone number, no email.
app.post('/api/register', registerLimiter, async (req, res) => {
  const { initData, username, publicKey } = req.body || {};
  const { error, tg, user } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });

  if (user) {
    return res.json({ id: user.id, username: user.username, publicKey: user.public_key, alreadyRegistered: true });
  }
  const check = validateUsername(username);
  if (!check.ok) {
    return res.status(400).json({ error: 'invalid_username', reason: check.reason });
  }
  if (!isValidPublicKeyB64(publicKey)) {
    return res.status(400).json({ error: 'invalid_public_key' });
  }

  try {
    const created = await createUser(tg.telegramId, check.value, publicKey);
    res.json({ id: created.id, username: created.username, publicKey: created.public_key, keyVersion: created.key_version });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'username_taken' });
    console.error('[register]', e);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Current user's own profile.
app.get('/api/me', async (req, res) => {
  const { error, user } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!user) return res.status(404).json({ registered: false });
  res.json({ registered: true, id: user.id, username: user.username, publicKey: user.public_key, keyVersion: user.key_version });
});

// Rotate my X25519 public key (e.g. CloudStorage was cleared / new device).
// All peers I've ever messaged get a real-time + bot push warning so they
// can verify the new key out-of-band before trusting it.
app.post('/api/key/rotate', async (req, res) => {
  const { initData, newPublicKey } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });
  if (!isValidPublicKeyB64(newPublicKey)) return res.status(400).json({ error: 'invalid_public_key' });

  const updated = await rotateUserKey(me.id, newPublicKey);
  const peerIds = await getPeerIdsOf(me.id);

  for (const peerId of peerIds) {
    pushToUser(peerId, {
      type: 'key_rotated',
      peerId: me.id,
      peerUsername: me.username,
      newPublicKey: updated.public_key,
      keyVersion: updated.key_version,
    });
    if (!isOnline(peerId)) {
      getTelegramIdOf(peerId).then((tgId) => pushTelegramNotice(tgId, keyRotatedNotice(me.username)));
    }
  }

  res.json({ id: updated.id, publicKey: updated.public_key, keyVersion: updated.key_version });
});

// Look up another user by app id (#000002) or username (to start a chat)
// and return their public key so the client can derive the shared secret.
app.get('/api/users/:lookup', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const lookup = req.params.lookup.trim();
  const lookupId = parseLookupId(lookup);
  const target = lookupId
    ? await findUserById(lookupId)
    : await findUserByUsername(lookup);
  if (!target) return res.status(404).json({ error: 'not_found' });
  res.json({ id: target.id, username: target.username, publicKey: target.public_key, keyVersion: target.key_version });
});

// List conversations (metadata only — packets are fetched per-conversation).
app.get('/api/conversations', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const rows = await getConversationList(me.id);
  res.json({
    conversations: rows.map((r) => ({
      peerId: r.peer_id,
      peerUsername: r.peer_username,
      peerPublicKey: r.peer_public_key,
      lastMessageId: r.last_message_id,
      lastMessageAt: r.last_message_at,
      lastMediaType: r.last_media_type,
    })),
  });
});

// Send an already-encrypted packet (produced by crypto-engine on the
// client). The server never sees plaintext — `packet` is opaque bytes.
app.post('/api/messages', messageLimiter, async (req, res) => {
  const { initData, recipientId, mediaType, packet } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const recipient = await findUserById(Number(recipientId));
  if (!recipient) return res.status(404).json({ error: 'recipient_not_found' });

  const validTypes = ['text', 'image', 'video', 'audio'];
  const type = validTypes.includes(mediaType) ? mediaType : 'text';

  let buf;
  try {
    buf = Buffer.from(packet, 'base64');
    if (buf.length === 0) throw new Error('empty');
  } catch {
    return res.status(400).json({ error: 'invalid_packet' });
  }

  const stored = await storePacketBuffer(buf);
  const row = await insertMessage(me.id, recipient.id, type, stored);
  const recipientOnline = isOnline(recipient.id);

  // Real-time push to the recipient if they're connected.
  pushToUser(recipient.id, {
    type: 'message',
    id: row.id,
    senderId: me.id,
    senderUsername: me.username,
    mediaType: type,
    packet: buf.toString('base64'), // live push always carries plaintext-of-ciphertext bytes directly (no offload roundtrip needed)
    createdAt: row.created_at,
  });

  // Recipient not connected right now → nudge them via the bot (no content, just a notice).
  if (!recipientOnline) {
    getTelegramIdOf(recipient.id).then((tgId) => pushTelegramNotice(tgId, newMessageNotice(me.username, type)));
  }

  res.json({ id: row.id, createdAt: row.created_at });
});

// Fetch conversation history with a peer (both directions), id > afterId.
app.get('/api/messages/:peerId', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const peerId = Number(req.params.peerId);
  const afterId = Number(req.query.afterId) || 0;
  if (!Number.isInteger(peerId)) return res.status(400).json({ error: 'invalid_peer' });

  const rows = await getConversation(me.id, peerId, afterId);
  const messages = await Promise.all(
    rows.map(async (r) => ({
      id: Number(r.id),
      senderId: r.sender_id,
      recipientId: r.recipient_id,
      mediaType: r.media_type,
      packet: r.deleted_at ? '' : await packetToBase64(r.packet),
      readAt: r.read_at,
      deletedAt: r.deleted_at,
      editedAt: r.edited_at,
      createdAt: r.created_at,
    }))
  );
  res.json({ messages });
});

// Mark a single message as read (recipient only).
app.post('/api/messages/:id/read', async (req, res) => {
  const { error, user: me } = await authenticate(req.body?.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const row = await markMessageRead(Number(req.params.id), me.id);
  if (!row) return res.status(404).json({ error: 'not_found' });

  pushToUser(row.sender_id, { type: 'read', messageId: row.id, readerId: me.id, readAt: row.read_at });
  res.json({ ok: true });
});

// Mark an entire conversation with a peer as read in one call.
app.post('/api/messages/read-all', async (req, res) => {
  const { initData, peerId } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const ids = await markConversationRead(me.id, Number(peerId));
  if (ids.length) {
    pushToUser(Number(peerId), { type: 'read_bulk', messageIds: ids, readerId: me.id });
  }
  res.json({ ok: true, count: ids.length });
});

// Delete-for-everyone (sender only). Packet bytes are wiped server-side.
app.delete('/api/messages/:id', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const row = await deleteMessage(Number(req.params.id), me.id);
  if (!row) return res.status(404).json({ error: 'not_found_or_not_yours' });

  pushToUser(row.recipient_id, { type: 'deleted', messageId: row.id });
  res.json({ ok: true });
});

// Edit a message (sender only) — client re-encrypts the new plaintext and
// sends a fresh packet; server just swaps it and stamps edited_at.
app.put('/api/messages/:id', async (req, res) => {
  const { initData, packet } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  let buf;
  try {
    buf = Buffer.from(packet, 'base64');
    if (buf.length === 0) throw new Error('empty');
  } catch {
    return res.status(400).json({ error: 'invalid_packet' });
  }

  const row = await editMessage(Number(req.params.id), me.id, buf);
  if (!row) return res.status(404).json({ error: 'not_found_or_not_yours' });

  pushToUser(row.recipient_id, { type: 'edited', messageId: row.id, packet: buf.toString('base64'), editedAt: row.edited_at });
  res.json({ ok: true, editedAt: row.edited_at });
});

// ---------------------------------------------------------------------
// Groups — server only fans out per-member ciphertext, never holds a
// group-wide key or plaintext.
// ---------------------------------------------------------------------
app.post('/api/groups', async (req, res) => {
  const { initData, name, memberIds } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });
  if (typeof name !== 'string' || name.trim().length < 2) return res.status(400).json({ error: 'invalid_name' });

  const ids = Array.isArray(memberIds) ? memberIds.map(Number).filter(Number.isInteger) : [];
  const group = await createGroup(name.trim(), me.id, ids);
  res.json({ id: group.id, name: group.name, ownerId: group.owner_id });
});

app.get('/api/groups', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const rows = await getUserGroups(me.id);
  res.json({
    groups: rows.map((r) => ({
      id: r.id,
      name: r.name,
      ownerId: r.owner_id,
      memberCount: Number(r.member_count),
      lastMessageAt: r.last_message_at,
    })),
  });
});

app.get('/api/groups/:id/members', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, me.id))) return res.status(403).json({ error: 'not_a_member' });

  const members = await getGroupMembers(groupId);
  res.json({
    members: members.map((m) => ({ id: m.id, username: m.username, publicKey: m.public_key, keyVersion: m.key_version })),
  });
});

app.post('/api/groups/:id/members', async (req, res) => {
  const { initData, userId } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, me.id))) return res.status(403).json({ error: 'not_a_member' });

  const target = await findUserById(Number(userId));
  if (!target) return res.status(404).json({ error: 'user_not_found' });
  await addGroupMember(groupId, target.id);
  res.json({ ok: true });
});

app.delete('/api/groups/:id/members/:userId', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const groupId = Number(req.params.id);
  const targetId = Number(req.params.userId);
  // Members can remove themselves (leave); anyone else needs to be the group's own request (kept simple: only self-leave for now).
  if (targetId !== me.id) return res.status(403).json({ error: 'only_self_leave_supported' });

  await removeGroupMember(groupId, me.id);
  res.json({ ok: true });
});

// Send a group message: client encrypts once per member and posts the
// full set of packets in one call.
app.post('/api/groups/:id/messages', messageLimiter, async (req, res) => {
  const { initData, mediaType, packets } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, me.id))) return res.status(403).json({ error: 'not_a_member' });
  if (!Array.isArray(packets) || packets.length === 0) return res.status(400).json({ error: 'invalid_packets' });

  const validTypes = ['text', 'image', 'video', 'audio'];
  const type = validTypes.includes(mediaType) ? mediaType : 'text';

  const packetsByRecipient = [];
  for (const p of packets) {
    const recipientId = Number(p.recipientId);
    let buf;
    try {
      buf = Buffer.from(p.packet, 'base64');
      if (buf.length === 0) throw new Error('empty');
    } catch {
      return res.status(400).json({ error: 'invalid_packet' });
    }
    packetsByRecipient.push([recipientId, buf]);
  }

  const gm = await insertGroupMessage(groupId, me.id, type, packetsByRecipient);

  for (const [recipientId, buf] of packetsByRecipient) {
    if (recipientId === me.id) continue;
    pushToUser(recipientId, {
      type: 'group_message',
      groupId,
      id: gm.id,
      senderId: me.id,
      senderUsername: me.username,
      mediaType: type,
      packet: buf.toString('base64'),
      createdAt: gm.created_at,
    });
    if (!isOnline(recipientId)) {
      getTelegramIdOf(recipientId).then((tgId) => pushTelegramNotice(tgId, newMessageNotice(`${me.username} (qrup)`, type)));
    }
  }

  res.json({ id: gm.id, createdAt: gm.created_at });
});

app.get('/api/groups/:id/messages', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(error === 'banned' ? 403 : 401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, me.id))) return res.status(403).json({ error: 'not_a_member' });

  const afterId = Number(req.query.afterId) || 0;
  const rows = await getGroupHistory(groupId, me.id, afterId);
  res.json({
    messages: rows.map((r) => ({
      id: Number(r.id),
      senderId: r.sender_id,
      senderUsername: r.sender_username,
      mediaType: r.media_type,
      packet: r.packet.toString('base64'),
      createdAt: r.created_at,
    })),
  });
});

// ---------------------------------------------------------------------
// Admin API — metadata-only (no message content, ever). JWT-protected.
// ---------------------------------------------------------------------
app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const ok = await checkAdminCredentials(username, password);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  res.json({ token: issueAdminToken(username) });
});

app.get('/api/admin/stats', adminMiddleware, async (_req, res) => {
  res.json(await adminGetStats());
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const offset = Number(req.query.offset) || 0;
  const search = String(req.query.search || '');
  const rows = await adminListUsers(limit, offset, search);
  res.json({
    users: rows.map((u) => ({
      id: u.id,
      username: u.username,
      keyVersion: u.key_version,
      isBanned: u.is_banned,
      lastSeenAt: u.last_seen_at,
      createdAt: u.created_at,
    })),
  });
});

app.post('/api/admin/users/:id/ban', adminMiddleware, async (req, res) => {
  const banned = Boolean(req.body?.banned);
  const row = await adminSetBanned(Number(req.params.id), banned);
  if (!row) return res.status(404).json({ error: 'not_found' });
  // Force any live session for this user to disconnect immediately if banned.
  if (banned) {
    const set = liveConnections.get(row.id);
    if (set) for (const ws of set) ws.close(4003, 'banned');
  }
  res.json({ id: row.id, username: row.username, isBanned: row.is_banned });
});

// ---------------------------------------------------------------------
// Static files (Mini App + Admin panel)
// ---------------------------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'webapp')));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin')));

// ---------------------------------------------------------------------
// HTTP + WebSocket server
// ---------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

/** userId -> Set<WebSocket> */
const liveConnections = new Map();

function isOnline(userId) {
  const set = liveConnections.get(userId);
  return Boolean(set && set.size > 0);
}

function pushToUser(userId, payload) {
  const set = liveConnections.get(userId);
  if (!set) return;
  const msg = JSON.stringify(payload);
  for (const ws of set) {
    if (ws.readyState === ws.OPEN) ws.send(msg);
  }
}

wss.on('connection', async (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const initData = url.searchParams.get('initData');
  const tg = validateInitData(initData, BOT_TOKEN);
  if (!tg) {
    ws.close(4001, 'invalid_init_data');
    return;
  }
  const user = await findUserByTelegramId(tg.telegramId);
  if (!user) {
    ws.close(4002, 'not_registered');
    return;
  }
  if (user.is_banned) {
    ws.close(4003, 'banned');
    return;
  }

  if (!liveConnections.has(user.id)) liveConnections.set(user.id, new Set());
  liveConnections.get(user.id).add(ws);
  touchLastSeen(user.id).catch(() => {});

  ws.on('close', () => {
    const set = liveConnections.get(user.id);
    if (set) {
      set.delete(ws);
      if (set.size === 0) liveConnections.delete(user.id);
    }
  });

  ws.send(JSON.stringify({ type: 'connected', userId: user.id }));
});

// ---------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------
async function main() {
  await initSchema();
  console.log('[db] schema ready');
  console.log(`[media] object storage ${mediaStorageEnabled ? 'ENABLED' : 'disabled (inline BYTEA fallback)'}`);

  server.listen(PORT, () => {
    console.log(`[server] http://localhost:${PORT}`);
  });

  await startBot(BOT_TOKEN, MINIAPP_URL);
}

main().catch((e) => {
  console.error('[startup] fatal:', e);
  process.exit(1);
});
