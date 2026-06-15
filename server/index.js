import 'dotenv/config';
import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';

import { validateInitData } from './telegramAuth.js';
import { startBot } from './bot.js';
import {
  pool,
  initSchema,
  findUserByTelegramId,
  findUserByUsername,
  findUserById,
  createUser,
  insertMessage,
  getConversation,
  getConversationList,
} from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BOT_TOKEN = process.env.BOT_TOKEN;
const MINIAPP_URL = process.env.MINIAPP_URL;
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json({ limit: '20mb' }));

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
  return { tg, user }; // user may be null if not yet registered
}

function isValidUsername(u) {
  return typeof u === 'string' && u.trim().length >= 2 && u.trim().length <= 24;
}

function isValidPublicKeyB64(s) {
  if (typeof s !== 'string') return false;
  try {
    return Buffer.from(s, 'base64').length === 32;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

app.get('/health', (_req, res) => res.json({ ok: true }));

// Register a new app profile. Only the display name + X25519 public key
// are stored — no phone number, no email.
app.post('/api/register', async (req, res) => {
  const { initData, username, publicKey } = req.body || {};
  const { error, tg, user } = await authenticate(initData);
  if (error) return res.status(401).json({ error });

  if (user) {
    return res.json({ id: user.id, username: user.username, publicKey: user.public_key, alreadyRegistered: true });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'invalid_username' });
  }
  if (!isValidPublicKeyB64(publicKey)) {
    return res.status(400).json({ error: 'invalid_public_key' });
  }

  try {
    const created = await createUser(tg.telegramId, username.trim(), publicKey);
    res.json({ id: created.id, username: created.username, publicKey: created.public_key });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'username_taken' });
    console.error('[register]', e);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Current user's own profile.
app.get('/api/me', async (req, res) => {
  const { error, user } = await authenticate(req.query.initData);
  if (error) return res.status(401).json({ error });
  if (!user) return res.status(404).json({ registered: false });
  res.json({ registered: true, id: user.id, username: user.username, publicKey: user.public_key });
});

// Look up another user by username (to start a chat) — returns their
// public key so the client can derive the shared secret.
app.get('/api/users/:username', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const target = await findUserByUsername(req.params.username.trim());
  if (!target) return res.status(404).json({ error: 'not_found' });
  res.json({ id: target.id, username: target.username, publicKey: target.public_key });
});

// List conversations (metadata only — packets are fetched per-conversation).
app.get('/api/conversations', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(401).json({ error });
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
app.post('/api/messages', async (req, res) => {
  const { initData, recipientId, mediaType, packet } = req.body || {};
  const { error, user: me } = await authenticate(initData);
  if (error) return res.status(401).json({ error });
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

  const row = await insertMessage(me.id, recipient.id, type, buf);

  // Real-time push to the recipient if they're connected.
  pushToUser(recipient.id, {
    type: 'message',
    id: row.id,
    senderId: me.id,
    senderUsername: me.username,
    mediaType: type,
    packet: buf.toString('base64'),
    createdAt: row.created_at,
  });

  res.json({ id: row.id, createdAt: row.created_at });
});

// Fetch conversation history with a peer (both directions), id > afterId.
app.get('/api/messages/:peerId', async (req, res) => {
  const { error, user: me } = await authenticate(req.query.initData);
  if (error) return res.status(401).json({ error });
  if (!me) return res.status(403).json({ error: 'not_registered' });

  const peerId = Number(req.params.peerId);
  const afterId = Number(req.query.afterId) || 0;
  if (!Number.isInteger(peerId)) return res.status(400).json({ error: 'invalid_peer' });

  const rows = await getConversation(me.id, peerId, afterId);
  res.json({
    messages: rows.map((r) => ({
      id: Number(r.id),
      senderId: r.sender_id,
      recipientId: r.recipient_id,
      mediaType: r.media_type,
      packet: r.packet.toString('base64'),
      createdAt: r.created_at,
    })),
  });
});

// ---------------------------------------------------------------------
// Static files (Mini App)
// ---------------------------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'webapp')));

// ---------------------------------------------------------------------
// HTTP + WebSocket server
// ---------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

/** userId -> Set<WebSocket> */
const liveConnections = new Map();

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

  if (!liveConnections.has(user.id)) liveConnections.set(user.id, new Set());
  liveConnections.get(user.id).add(ws);

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

  server.listen(PORT, () => {
    console.log(`[server] http://localhost:${PORT}`);
  });

  await startBot(BOT_TOKEN, MINIAPP_URL);
}

main().catch((e) => {
  console.error('[startup] fatal:', e);
  process.exit(1);
});
