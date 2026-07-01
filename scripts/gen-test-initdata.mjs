/**
 * Real Telegram olmadan, lokal serveri (npm start) curl ilə test etmək üçün
 * keçərli bir "initData" yaradır (BOT_TOKEN ilə düzgün imzalanmış).
 *
 * İstifadə:
 *   node scripts/gen-test-initdata.mjs --id=100000001 --name=Elvin --username=elvin
 */
import 'dotenv/config';
import crypto from 'crypto';

const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
  console.error('XƏTA: .env faylında BOT_TOKEN tapılmadı (.env.example-dən köçür).');
  process.exit(1);
}

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, ...v] = a.replace(/^--/, '').split('=');
    return [k, v.join('=')];
  })
);

const telegramId = Number(args.id || 100000001);
const firstName = args.name || 'Test';
const username = args.username || 'testuser';

const user = JSON.stringify({ id: telegramId, first_name: firstName, username });
const authDate = String(Math.floor(Date.now() / 1000));

const params = new URLSearchParams({ user, auth_date: authDate, query_id: 'AAtest' });
const dataCheckString = [...params.entries()]
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  .map(([k, v]) => `${k}=${v}`)
  .join('\n');

const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
const hash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
params.set('hash', hash);

const initData = params.toString();
const encoded = encodeURIComponent(initData);
const fakePubKey = Buffer.alloc(32, 1).toString('base64');

console.log('initData:\n' + initData + '\n');
console.log('--- nümunə sorğular (server `npm start` ilə lokalda :3000-də işləyirsə) ---\n');

console.log('1) Qeydiyyat (yeni profil):');
console.log(
  `curl -s -X POST http://localhost:3000/api/register -H 'Content-Type: application/json' ` +
    `-d '${JSON.stringify({ initData, username, publicKey: fakePubKey })}'; echo`
);

console.log('\n2) Öz profilini al:');
console.log(`curl -s "http://localhost:3000/api/me?initData=${encoded}"; echo`);

console.log('\n3) Söhbət siyahısı:');
console.log(`curl -s "http://localhost:3000/api/conversations?initData=${encoded}"; echo`);
