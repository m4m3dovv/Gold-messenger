/**
 * PostgreSQL connection + schema.
 *
 * Tables:
 *  - users:    app-internal profile (numeric id, unique username, X25519
 *               public key). telegram_id is stored only as a one-account
 *               anti-abuse key and is never exposed via the API.
 *  - messages: stores the fully-encrypted 10-layer packet as BYTEA.
 *               The server never sees plaintext content.
 */
import pg from 'pg';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway')
    ? { rejectUnauthorized: false }
    : undefined,
});

export async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id           SERIAL PRIMARY KEY,
      telegram_id  BIGINT UNIQUE NOT NULL,
      username     TEXT UNIQUE NOT NULL,
      public_key   TEXT NOT NULL,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id            BIGSERIAL PRIMARY KEY,
      sender_id     INT NOT NULL REFERENCES users(id),
      recipient_id  INT NOT NULL REFERENCES users(id),
      media_type    TEXT NOT NULL DEFAULT 'text',
      packet        BYTEA NOT NULL,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conv
      ON messages (recipient_id, sender_id, id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conv2
      ON messages (sender_id, recipient_id, id);
  `);
}

export async function findUserByTelegramId(telegramId) {
  const { rows } = await pool.query(
    'SELECT id, username, public_key FROM users WHERE telegram_id = $1',
    [telegramId]
  );
  return rows[0] || null;
}

export async function findUserByUsername(username) {
  const { rows } = await pool.query(
    'SELECT id, username, public_key FROM users WHERE username = $1',
    [username]
  );
  return rows[0] || null;
}

export async function findUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, username, public_key FROM users WHERE id = $1',
    [id]
  );
  return rows[0] || null;
}

export async function createUser(telegramId, username, publicKeyBase64) {
  const { rows } = await pool.query(
    `INSERT INTO users (telegram_id, username, public_key)
     VALUES ($1, $2, $3)
     RETURNING id, username, public_key`,
    [telegramId, username, publicKeyBase64]
  );
  return rows[0];
}

export async function insertMessage(senderId, recipientId, mediaType, packetBuffer) {
  const { rows } = await pool.query(
    `INSERT INTO messages (sender_id, recipient_id, media_type, packet)
     VALUES ($1, $2, $3, $4)
     RETURNING id, created_at`,
    [senderId, recipientId, mediaType, packetBuffer]
  );
  return rows[0];
}

export async function getConversation(userId, peerId, afterId = 0) {
  const { rows } = await pool.query(
    `SELECT id, sender_id, recipient_id, media_type, packet, created_at
       FROM messages
      WHERE ((sender_id = $1 AND recipient_id = $2)
          OR (sender_id = $2 AND recipient_id = $1))
        AND id > $3
      ORDER BY id ASC
      LIMIT 200`,
    [userId, peerId, afterId]
  );
  return rows;
}

/** Distinct peers the user has exchanged messages with, with last message info. */
export async function getConversationList(userId) {
  const { rows } = await pool.query(
    `SELECT
       peer.id AS peer_id,
       peer.username AS peer_username,
       peer.public_key AS peer_public_key,
       last_msg.id AS last_message_id,
       last_msg.created_at AS last_message_at,
       last_msg.media_type AS last_media_type
     FROM (
       SELECT DISTINCT
         CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END AS peer_id
       FROM messages
       WHERE sender_id = $1 OR recipient_id = $1
     ) peers
     JOIN users peer ON peer.id = peers.peer_id
     LEFT JOIN LATERAL (
       SELECT id, created_at, media_type
       FROM messages m
       WHERE (m.sender_id = $1 AND m.recipient_id = peers.peer_id)
          OR (m.sender_id = peers.peer_id AND m.recipient_id = $1)
       ORDER BY id DESC
       LIMIT 1
     ) last_msg ON true
     ORDER BY last_msg.id DESC`,
    [userId]
  );
  return rows;
}
