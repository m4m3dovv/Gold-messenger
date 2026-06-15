import crypto from 'crypto';
import { validateInitData } from '../server/telegramAuth.js';

const BOT_TOKEN = 'test-bot-token-12345';

function buildInitData(fields, botToken) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) params.set(k, v);
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const hash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  params.set('hash', hash);
  return params.toString();
}

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    console.log(`  ❌ ${name}`);
  }
}

const userObj = JSON.stringify({ id: 123456, first_name: 'Test', username: 'testuser' });
const authDate = Math.floor(Date.now() / 1000);

const valid = buildInitData({ user: userObj, auth_date: String(authDate), query_id: 'AAQtest' }, BOT_TOKEN);

console.log('=== telegramAuth.validateInitData ===');

const r1 = validateInitData(valid, BOT_TOKEN);
check('valid initData accepted, correct telegramId', r1 && r1.telegramId === 123456);

check('wrong bot token rejected', validateInitData(valid, 'wrong-token') === null);

const tamperedHash = valid.replace(/hash=[a-f0-9]+/, 'hash=' + '0'.repeat(64));
check('tampered hash rejected', validateInitData(tamperedHash, BOT_TOKEN) === null);

const tamperedParams = new URLSearchParams(valid);
tamperedParams.set('user', JSON.stringify({ id: 999999, first_name: 'Evil', username: 'evil' }));
check('tampered user payload (hash now stale) rejected', validateInitData(tamperedParams.toString(), BOT_TOKEN) === null);

const oldAuthDate = authDate - 90000; // > 24h ago
const expired = buildInitData({ user: userObj, auth_date: String(oldAuthDate), query_id: 'AAQtest' }, BOT_TOKEN);
check('expired auth_date rejected (maxAgeSec=86400)', validateInitData(expired, BOT_TOKEN, 86400) === null);

const r6 = validateInitData(expired, BOT_TOKEN, 0);
check('old auth_date accepted when maxAgeSec=0', r6 && r6.telegramId === 123456);

const noHash = valid.replace(/&hash=[a-f0-9]+/, '');
check('missing hash rejected', validateInitData(noHash, BOT_TOKEN) === null);

check('empty initData rejected', validateInitData('', BOT_TOKEN) === null);
check('null botToken rejected', validateInitData(valid, null) === null);

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
