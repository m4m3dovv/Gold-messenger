import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateKeyPair,
  computeSharedSecret,
  conversationSalt,
  encryptMessage,
  decryptMessage,
} from '../crypto-engine/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

const scenario = process.env.SCENARIO || 'unregistered';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const html = fs.readFileSync(path.join(root, 'webapp', 'index.html'), 'utf-8');
const dom = new JSDOM(html, { url: 'https://example.com/' });
const { window } = dom;

global.window = window;
global.document = window.document;
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
global.Blob = window.Blob;
global.URL = window.URL;
if (!window.URL.createObjectURL) window.URL.createObjectURL = () => 'blob:mock';
global.location = window.location;
global.HTMLElement = window.HTMLElement;
global.CustomEvent = window.CustomEvent;
global.Event = window.Event;

global.WebSocket = class {
  constructor() {}
  addEventListener() {}
  send() {}
  close() {}
};
window.WebSocket = global.WebSocket;

const cloudStore = new Map();
window.Telegram = {
  WebApp: {
    initData: 'mock_init_data',
    ready: () => {},
    expand: () => {},
    BackButton: { show: () => {}, hide: () => {}, onClick: () => {} },
    CloudStorage: {
      getItem: (key, cb) => cb(null, cloudStore.get(key) || null),
      setItem: (key, value, cb) => { cloudStore.set(key, value); cb(null, true); },
    },
  },
};

function b64(bytes) { return Buffer.from(bytes).toString('base64'); }
function unb64(s) { return new Uint8Array(Buffer.from(s, 'base64')); }

const bob = generateKeyPair();
let myPublicKeyB64 = null;

const json = (status, body) => ({ status, json: async () => body });

global.fetch = async (urlOrPath, opts) => {
  const url = new URL(String(urlOrPath), 'https://example.com');
  const path = url.pathname;
  const body = opts?.body ? JSON.parse(opts.body) : null;

  if (path === '/api/me') {
    if (scenario === 'registered' || scenario === 'chat') {
      return json(200, { registered: true, id: 42, username: 'Tester', publicKey: myPublicKeyB64 || b64(new Uint8Array(32)) });
    }
    return json(404, { registered: false });
  }
  if (path === '/api/register') {
    myPublicKeyB64 = body.publicKey;
    return json(200, { id: 42, username: body.username, publicKey: myPublicKeyB64 });
  }
  if (path === '/api/conversations') return json(200, { conversations: [] });
  if (path === '/api/users/bob') return json(200, { id: 99, username: 'bob', publicKey: b64(bob.publicKey) });

  if (path === '/api/messages/99') {
    const myPub = unb64(myPublicKeyB64);
    const shared = computeSharedSecret(bob.privateKey, myPub);
    const salt = conversationSalt(myPub, bob.publicKey);
    const packet = encryptMessage(new TextEncoder().encode('Salam Bob-dan!'), shared, salt);
    return json(200, { messages: [
      { id: 1, senderId: 99, recipientId: 42, mediaType: 'text', packet: b64(packet), createdAt: new Date().toISOString() },
    ]});
  }

  if (path === '/api/messages' && opts?.method === 'POST') {
    const myPub = unb64(myPublicKeyB64);
    const shared = computeSharedSecret(bob.privateKey, myPub);
    const salt = conversationSalt(myPub, bob.publicKey);
    const plaintext = decryptMessage(unb64(body.packet), shared, salt);
    console.log('  [server saw outgoing plaintext]:', new TextDecoder().decode(plaintext));
    return json(200, { id: 2, createdAt: new Date().toISOString() });
  }

  return json(404, {});
};

await import('../webapp/dist/bundle.js');
await sleep(50);

function isHidden(id) { return window.document.getElementById(id).classList.contains('hidden'); }
function text(id) { return window.document.getElementById(id).textContent; }

console.log('SCENARIO:', scenario);

if (scenario === 'unregistered') {
  console.log('  register screen visible:', !isHidden('screen-register'));
}

if (scenario === 'registered') {
  console.log('  chats screen visible:', !isHidden('screen-chats'));
  console.log('  my-id-chip:', text('my-id-chip'));
  console.log('  privkey stored:', cloudStore.has('mh_privkey_v1'));
}

if (scenario === 'chat') {
  window.document.getElementById('register-name').value = 'Tester';
  window.document.getElementById('register-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
  await sleep(100);
  console.log('  after register -> chats visible:', !isHidden('screen-chats'));
  console.log('  my public key captured:', !!myPublicKeyB64);

  window.document.getElementById('new-chat-username').value = 'bob';
  window.document.getElementById('new-chat-btn').click();
  await sleep(100);
  console.log('  after open chat -> chat screen visible:', !isHidden('screen-chat'));
  console.log('  peer name:', text('chat-peer-name'), '| peer id:', text('chat-peer-id'));

  const listHtml1 = window.document.getElementById('message-list').textContent;
  console.log('  incoming message decrypted & shown:', listHtml1.includes('Salam Bob-dan!'));

  window.document.getElementById('message-input').value = 'Salam Eziz';
  window.document.getElementById('send-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
  await sleep(100);

  const listHtml2 = window.document.getElementById('message-list').textContent;
  console.log('  outgoing message rendered locally:', listHtml2.includes('Salam Eziz'));

  const bubbles = [...window.document.querySelectorAll('#message-list .bubble')];
  console.log('  bubble classes:', bubbles.map((b) => b.className.includes('bubble--in') ? 'in' : b.className.includes('bubble--out') ? 'out' : 'sys').join(', '));
}

console.log('OK — no exceptions thrown.');
