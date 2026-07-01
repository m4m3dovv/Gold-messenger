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
      id             SERIAL PRIMARY KEY,
      telegram_id    BIGINT UNIQUE NOT NULL,
      username       TEXT UNIQUE NOT NULL,
      public_key     TEXT NOT NULL,
      key_version    INT NOT NULL DEFAULT 1,
      key_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      is_banned      BOOLEAN NOT NULL DEFAULT false,
      last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Migration guards for pre-existing installs (before these columns existed).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS key_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (lower(username));`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id            BIGSERIAL PRIMARY KEY,
      sender_id     INT NOT NULL REFERENCES users(id),
      recipient_id  INT NOT NULL REFERENCES users(id),
      media_type    TEXT NOT NULL DEFAULT 'text',
      packet        BYTEA NOT NULL,
      read_at       TIMESTAMPTZ,
      deleted_at    TIMESTAMPTZ,
      edited_at     TIMESTAMPTZ,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;`);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conv
      ON messages (recipient_id, sender_id, id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conv2
      ON messages (sender_id, recipient_id, id);
  `);

  // -------------------------------------------------------------
  // Groups — E2E stays client-side: for every group message the
  // client encrypts the plaintext once per member (using the same
  // pairwise X25519 pipeline already used for 1-1 chats) and sends
  // an array of packets. The server only fans them out; it never
  // holds a group-wide key.
  // -------------------------------------------------------------
  await pool.query(`
    CREATE TABLE IF NOT EXISTS groups (
      id          SERIAL PRIMARY KEY,
      name        TEXT NOT NULL,
      owner_id    INT NOT NULL REFERENCES users(id),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_members (
      group_id   INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
      user_id    INT NOT NULL REFERENCES users(id),
      joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (group_id, user_id)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id            BIGSERIAL PRIMARY KEY,
      group_id      INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
      sender_id     INT NOT NULL REFERENCES users(id),
      media_type    TEXT NOT NULL DEFAULT 'text',
      deleted_at    TIMESTAMPTZ,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // One encrypted packet per recipient member, keyed off the group message.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_message_packets (
      group_message_id  BIGINT NOT NULL REFERENCES group_messages(id) ON DELETE CASCADE,
      recipient_id       INT NOT NULL REFERENCES users(id),
      packet              BYTEA NOT NULL,
      PRIMARY KEY (group_message_id, recipient_id)
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_group_messages_group
      ON group_messages (group_id, id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_group_packets_recipient
      ON group_message_packets (recipient_id, group_message_id);
  `);
}

// ---------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------
export async function getTelegramIdOf(userId) {
  const { rows } = await pool.query('SELECT telegram_id FROM users WHERE id = $1', [userId]);
  return rows[0]?.telegram_id || null;
}

export async function adminGetStats() {
  const [{ rows: u }, { rows: m }, { rows: g }, { rows: active24 }] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS c FROM users'),
    pool.query('SELECT COUNT(*)::int AS c FROM messages'),
    pool.query('SELECT COUNT(*)::int AS c FROM groups'),
    pool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen_at > now() - interval '24 hours'"),
  ]);
  return {
    totalUsers: u[0].c,
    totalMessages: m[0].c,
    totalGroups: g[0].c,
    activeLast24h: active24[0].c,
  };
}

export async function adminListUsers(limit = 50, offset = 0, search = '') {
  const { rows } = await pool.query(
    `SELECT id, username, key_version, is_banned, last_seen_at, created_at
       FROM users
      WHERE $3 = '' OR username ILIKE '%' || $3 || '%'
      ORDER BY id DESC
      LIMIT $1 OFFSET $2`,
    [limit, offset, search]
  );
  return rows;
}

export async function adminSetBanned(userId, banned) {
  const { rows } = await pool.query(
    'UPDATE users SET is_banned = $2 WHERE id = $1 RETURNING id, username, is_banned',
    [userId, banned]
  );
  return rows[0] || null;
}

export async function findUserByTelegramId(telegramId) {
  const { rows } = await pool.query(
    'SELECT id, telegram_id, username, public_key, key_version, is_banned FROM users WHERE telegram_id = $1',
    [telegramId]
  );
  return rows[0] || null;
}

export async function findUserByUsername(username) {
  const { rows } = await pool.query(
    'SELECT id, username, public_key, key_version, is_banned FROM users WHERE lower(username) = lower($1)',
    [username]
  );
  return rows[0] || null;
}

export async function findUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, username, public_key, key_version, is_banned FROM users WHERE id = $1',
    [id]
  );
  return rows[0] || null;
}

export async function createUser(telegramId, username, publicKeyBase64) {
  const { rows } = await pool.query(
    `INSERT INTO users (telegram_id, username, public_key)
     VALUES ($1, $2, $3)
     RETURNING id, username, public_key, key_version`,
    [telegramId, username, publicKeyBase64]
  );
  return rows[0];
}

export async function touchLastSeen(userId) {
  await pool.query('UPDATE users SET last_seen_at = now() WHERE id = $1', [userId]);
}

/** Rotate a user's public key (e.g. after re-installing / clearing CloudStorage). */
export async function rotateUserKey(userId, newPublicKeyBase64) {
  const { rows } = await pool.query(
    `UPDATE users
        SET public_key = $2, key_version = key_version + 1, key_updated_at = now()
      WHERE id = $1
      RETURNING id, username, public_key, key_version`,
    [userId, newPublicKeyBase64]
  );
  return rows[0] || null;
}

/** Every distinct peer (1-1) a user has a conversation with — used to fan out key-rotation notices. */
export async function getPeerIdsOf(userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END AS peer_id
       FROM messages WHERE sender_id = $1 OR recipient_id = $1`,
    [userId]
  );
  return rows.map((r) => r.peer_id);
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
    `SELECT id, sender_id, recipient_id, media_type, packet, read_at, deleted_at, edited_at, created_at
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

export async function markMessageRead(messageId, readerId) {
  // Only the recipient can mark a message as read.
  const { rows } = await pool.query(
    `UPDATE messages SET read_at = now()
      WHERE id = $1 AND recipient_id = $2 AND read_at IS NULL
      RETURNING id, sender_id, recipient_id, read_at`,
    [messageId, readerId]
  );
  return rows[0] || null;
}

export async function markConversationRead(readerId, peerId) {
  const { rows } = await pool.query(
    `UPDATE messages SET read_at = now()
      WHERE recipient_id = $1 AND sender_id = $2 AND read_at IS NULL
      RETURNING id`,
    [readerId, peerId]
  );
  return rows.map((r) => r.id);
}

export async function deleteMessage(messageId, requesterId) {
  // Only the sender can delete (delete-for-everyone). Packet is wiped, not just flagged.
  const { rows } = await pool.query(
    `UPDATE messages SET deleted_at = now(), packet = ''::bytea
      WHERE id = $1 AND sender_id = $2 AND deleted_at IS NULL
      RETURNING id, sender_id, recipient_id`,
    [messageId, requesterId]
  );
  return rows[0] || null;
}

export async function editMessage(messageId, requesterId, newPacketBuffer) {
  // Only the sender can edit, and only their own not-yet-deleted message.
  const { rows } = await pool.query(
    `UPDATE messages SET packet = $3, edited_at = now()
      WHERE id = $1 AND sender_id = $2 AND deleted_at IS NULL
      RETURNING id, sender_id, recipient_id, edited_at`,
    [messageId, requesterId, newPacketBuffer]
  );
  return rows[0] || null;
}

// ---------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------
export async function createGroup(name, ownerId, memberIds) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO groups (name, owner_id) VALUES ($1, $2) RETURNING id, name, owner_id, created_at`,
      [name, ownerId]
    );
    const group = rows[0];
    const allMembers = [...new Set([ownerId, ...memberIds])];
    for (const uid of allMembers) {
      await client.query(
        `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [group.id, uid]
      );
    }
    await client.query('COMMIT');
    return group;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function isGroupMember(groupId, userId) {
  const { rows } = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2',
    [groupId, userId]
  );
  return rows.length > 0;
}

export async function getGroupMembers(groupId) {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.public_key, u.key_version
       FROM group_members gm JOIN users u ON u.id = gm.user_id
      WHERE gm.group_id = $1`,
    [groupId]
  );
  return rows;
}

export async function addGroupMember(groupId, userId) {
  await pool.query(
    `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [groupId, userId]
  );
}

export async function removeGroupMember(groupId, userId) {
  await pool.query('DELETE FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, userId]);
}

export async function getUserGroups(userId) {
  const { rows } = await pool.query(
    `SELECT g.id, g.name, g.owner_id,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS member_count,
            lm.created_at AS last_message_at
       FROM group_members gm
       JOIN groups g ON g.id = gm.group_id
       LEFT JOIN LATERAL (
         SELECT created_at FROM group_messages
          WHERE group_id = g.id AND deleted_at IS NULL
          ORDER BY id DESC LIMIT 1
       ) lm ON true
      WHERE gm.user_id = $1
      ORDER BY lm.created_at DESC NULLS LAST`,
    [userId]
  );
  return rows;
}

/** Insert one group message with a distinct encrypted packet per member (fan-out, client-encrypted). */
export async function insertGroupMessage(groupId, senderId, mediaType, packetsByRecipient) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO group_messages (group_id, sender_id, media_type) VALUES ($1, $2, $3) RETURNING id, created_at`,
      [groupId, senderId, mediaType]
    );
    const gm = rows[0];
    for (const [recipientId, buf] of packetsByRecipient) {
      await client.query(
        `INSERT INTO group_message_packets (group_message_id, recipient_id, packet) VALUES ($1, $2, $3)`,
        [gm.id, recipientId, buf]
      );
    }
    await client.query('COMMIT');
    return gm;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function getGroupHistory(groupId, forUserId, afterId = 0) {
  const { rows } = await pool.query(
    `SELECT m.id, m.sender_id, u.username AS sender_username, m.media_type, m.created_at,
            p.packet
       FROM group_messages m
       JOIN group_message_packets p ON p.group_message_id = m.id AND p.recipient_id = $2
       JOIN users u ON u.id = m.sender_id
      WHERE m.group_id = $1 AND m.id > $3 AND m.deleted_at IS NULL
      ORDER BY m.id ASC
      LIMIT 200`,
    [groupId, forUserId, afterId]
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
