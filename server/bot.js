/**
 * Telegram bot — webhook rejimində işləyir (Railway üçün optimal).
 * Polling əvəzinə webhook istifadə edir ki, çoxlu instansiya konflikti olmasın.
 */
import { Bot, webhookCallback } from 'grammy';

let botInstance = null;

export async function startBot(token, miniAppUrl) {
  if (!token) {
    console.warn('[bot] BOT_TOKEN tapılmadı — Telegram bot deaktivdir.');
    return null;
  }
  if (!miniAppUrl) {
    console.warn('[bot] MINIAPP_URL tapılmadı — "Aç" düyməsi işləməyəcək.');
  }

  const bot = new Bot(token);
  botInstance = bot;

  bot.command('start', async (ctx) => {
    await ctx.reply(
      'Salam! 🔐\n\nBu, ucdan-uca şifrələnmiş söhbət sistemidir. Aşağıdakı düyməyə bas, profilini yarat və danış.',
      {
        reply_markup: {
          inline_keyboard: [[{ text: '🔐 Aç', web_app: { url: miniAppUrl || 'https://example.com' } }]],
        },
      }
    );
  });

  bot.catch((err) => {
    console.error('[bot] error:', err?.message || err);
  });

  // Menu düyməsini set et
  if (miniAppUrl) {
    try {
      await bot.api.setChatMenuButton({
        menu_button: { type: 'web_app', text: 'Aç', web_app: { url: miniAppUrl } },
      });
      console.log('[bot] Menu düyməsi quruldu.');
    } catch (e) {
      console.warn('[bot] setChatMenuButton alınmadı:', e?.message || e);
    }
  }

  // Webhook qur
  if (miniAppUrl) {
    const webhookUrl = `${miniAppUrl}/telegram-webhook`;
    try {
      await bot.api.setWebhook(webhookUrl, { drop_pending_updates: true });
      console.log(`[bot] Webhook quruldu: ${webhookUrl}`);
    } catch (e) {
      console.error('[bot] Webhook qurmaq alınmadı:', e?.message || e);
    }
  }

  console.log('[bot] Telegram bot webhook rejimində hazırdır.');
  return bot;
}

export function getBotWebhookHandler() {
  if (!botInstance) return null;
  return webhookCallback(botInstance, 'express');
}
