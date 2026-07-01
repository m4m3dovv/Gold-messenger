/**
 * Minimal admin auth: a single admin account configured via env vars
 * (ADMIN_USERNAME / ADMIN_PASSWORD_HASH), JWT session token.
 *
 * Note: admins can see usage metadata (usernames, timestamps, ban
 * status) — never message content, since packets stay E2E-encrypted
 * and the server has no way to decrypt them.
 */
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.BOT_TOKEN || 'dev-insecure-secret-change-me';

export async function checkAdminCredentials(username, password) {
  const expectedUser = process.env.ADMIN_USERNAME;
  const expectedHash = process.env.ADMIN_PASSWORD_HASH; // bcrypt hash, generate with scripts/hash-admin-password.mjs
  if (!expectedUser || !expectedHash) return false;
  if (username !== expectedUser) return false;
  return bcrypt.compare(password, expectedHash);
}

export function issueAdminToken(username) {
  return jwt.sign({ sub: username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
}

export function adminMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'no_token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') throw new Error('not_admin');
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
}
