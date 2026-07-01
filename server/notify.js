/**
 * Push notifications via the Telegram bot for events that happen while
 * the recipient's Mini App isn't open (no live WebSocket connection).
 * The bot only ever sends a generic "you have a new message" style
 * notice — never plaintext content, since the server doesn't have it.
 */
let botInstance = null;

export function registerBotForNotify(bot) {
  botInstance = bot;
}

export async function pushTelegramNotice(telegramId, text) {
  if (!botInstance || !telegramId) return;
  try {
    await botInstance.api.sendMessage(telegramId, text);
  } catch (e) {
    // Common benign cases: user blocked the bot, or never started it.
    console.warn('[notify] sendMessage failed:', e?.description || e?.message || e);
  }
}

export function newMessageNotice(senderUsername, mediaType) {
  const label = { text: 'mesaj', image: 'şəkil', video: 'video', audio: 'səsli mesaj' }[mediaType] || 'mesaj';
  return `🔐 ${senderUsername} sənə yeni bir ${label} göndərdi. Açmaq üçün Mini App-ı aç.`;
}

export function keyRotatedNotice(peerUsername) {
  return `⚠️ Təhlükəsizlik bildirişi: ${peerUsername} açarını yenilədi (yeni cihaz və ya sıfırlama ola bilər). Söhbəti açanda bunu görəcəksən — əgər gözləmirdinsə, diqqətli ol.`;
}
