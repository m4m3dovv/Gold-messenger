/**
 * Telegram bot — minimal: /start sends a "web_app" button that opens the
 * Mini App. All real logic (registration, chat, encryption) lives in the
 * Mini App itself, not in bot chat commands.
 */
import { Bot } from 'grammy';

export async function startBot(token, miniAppUrl) {
  if (!token) {
    console.warn('[bot] BOT_TOKEN tapılmadı — Telegram bot deaktivdir.');
    return null;
  }
  if (!miniAppUrl) {
    console.warn('[bot] MINIAPP_URL tapılmadı — "Aç" düyməsi işləməyəcək.');
  }

  const bot = new Bot(token);

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

  // Persistent "menu button" (next to the message input, always visible) —
  // gives users one-tap access to the Mini App without needing /start.
  if (miniAppUrl) {
    try {
      await bot.api.setChatMenuButton({
        menu_button: { type: 'web_app', text: 'Aç', web_app: { url: miniAppUrl } },
      });
    } catch (e) {
      console.warn('[bot] setChatMenuButton alınmadı:', e?.message || e);
    }
  }

  bot.start();
  console.log('[bot] Telegram bot polling rejimində başladı.');
  return bot;
}
