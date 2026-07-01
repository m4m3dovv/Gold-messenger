/**
 * Stronger username validation:
 *  - 3..24 chars, letters/digits/underscore only (unicode letters allowed
 *    so Azerbaijani/Cyrillic names work), must start with a letter.
 *  - Case-insensitive uniqueness is enforced at the DB layer via a
 *    lowercase index (see db.js) — this module only checks shape + a
 *    reserved-word/slur blocklist.
 */
const RESERVED = new Set([
  'admin', 'administrator', 'root', 'support', 'moderator', 'mod',
  'system', 'bot', 'goldmessenger', 'gold_messenger', 'muhur',
  'null', 'undefined', 'api', 'help', 'security', 'staff', 'owner',
]);

const USERNAME_RE = /^[\p{L}][\p{L}\p{N}_]{2,23}$/u;

export function validateUsername(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: 'invalid' };
  const trimmed = raw.trim();
  if (!USERNAME_RE.test(trimmed)) {
    return { ok: false, reason: 'format' };
  }
  if (RESERVED.has(trimmed.toLowerCase())) {
    return { ok: false, reason: 'reserved' };
  }
  return { ok: true, value: trimmed };
}
