/**
 * Telegram Mini App "initData" validation.
 *
 * This is the standard algorithm documented by Telegram:
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 *
 * It proves the request really came from Telegram's client for the given
 * bot (the Mini App page can't forge this — only Telegram, which knows the
 * bot token's derived secret, can produce a matching `hash`).
 *
 * We use the resulting `telegramId` purely as a one-account-per-registration
 * anti-abuse key. It is NEVER exposed to other users — only the
 * app-internal username + numeric id are.
 */
import crypto from 'crypto';

export function validateInitData(initData, botToken, maxAgeSec = 86400) {
  if (!initData || !botToken) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  // Constant-time compare.
  const a = Buffer.from(computedHash, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  if (maxAgeSec > 0) {
    const authDate = Number(params.get('auth_date'));
    if (!authDate || Date.now() / 1000 - authDate > maxAgeSec) return null;
  }

  let user = null;
  try {
    user = JSON.parse(params.get('user'));
  } catch {
    /* ignore */
  }
  if (!user?.id) return null;

  return {
    telegramId: user.id,
    firstName: user.first_name || null,
    telegramUsername: user.username || null,
  };
}
