import {
  encryptMessage,
  decryptMessage,
  HEADER_LEN,
  generateKeyPair,
  computeSharedSecret,
  conversationSalt,
} from '../crypto-engine/index.js';

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
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

console.log('=== 1) Identity / key exchange ===');
const alice = generateKeyPair();
const bob = generateKeyPair();
const sharedA = computeSharedSecret(alice.privateKey, bob.publicKey);
const sharedB = computeSharedSecret(bob.privateKey, alice.publicKey);
check('Alice & Bob derive the same shared secret', bytesEqual(sharedA, sharedB));

const salt = conversationSalt(alice.publicKey, bob.publicKey);
const saltSwapped = conversationSalt(bob.publicKey, alice.publicKey);
check('conversationSalt is order-independent', bytesEqual(salt, saltSwapped));

console.log(`\nHEADER_LEN = ${HEADER_LEN} bytes (sum of 8 layer nonces/IVs/seeds)`);

console.log('\n=== 2) Roundtrip — short text message ===');
{
  const plaintext = new TextEncoder().encode('Salam Bob, sabah saat 5-de gorusek. 🔐');
  const packet = encryptMessage(plaintext, sharedA, salt);
  const decrypted = decryptMessage(packet, sharedB, salt);
  check('decrypted text matches original', bytesEqual(plaintext, decrypted));
  console.log(
    `  plaintext: ${plaintext.length}B -> packet: ${packet.length}B (overhead: ${packet.length - plaintext.length}B)`
  );
}

console.log('\n=== 3) Roundtrip — edge cases (empty, 1 byte, 1 block) ===');
for (const len of [0, 1, 15, 16, 17, 100]) {
  const plaintext = crypto.getRandomValues(new Uint8Array(len));
  const packet = encryptMessage(plaintext, sharedA, salt);
  const decrypted = decryptMessage(packet, sharedB, salt);
  check(`len=${len}: roundtrip ok`, bytesEqual(plaintext, decrypted));
}

console.log('\n=== 4) Roundtrip — "image-like" binary blob (200 KB) ===');
{
  const size = 200 * 1024;
  const plaintext = new Uint8Array(size);
  for (let i = 0; i < size; i++) plaintext[i] = i & 0xff; // deterministic pattern

  const t0 = Date.now();
  const packet = encryptMessage(plaintext, sharedA, salt);
  const t1 = Date.now();
  const decrypted = decryptMessage(packet, sharedB, salt);
  const t2 = Date.now();

  check('200KB roundtrip matches', bytesEqual(plaintext, decrypted));
  console.log(`  encrypt: ${t1 - t0}ms, decrypt: ${t2 - t1}ms, packet size: ${packet.length}B`);
}

console.log('\n=== 5) Tamper detection ===');
{
  const plaintext = new TextEncoder().encode('Tampering test message');
  const packet = encryptMessage(plaintext, sharedA, salt);

  // Flip a bit in the middle of the payload (after the header).
  const tamperedPayload = packet.slice();
  tamperedPayload[HEADER_LEN + 5] ^= 0x01;
  let threwPayload = false;
  try {
    decryptMessage(tamperedPayload, sharedB, salt);
  } catch (e) {
    threwPayload = /Integrity check failed/.test(e.message);
  }
  check('tampered payload byte -> rejected', threwPayload);

  // Flip a bit in the header (a layer's nonce/IV).
  const tamperedHeader = packet.slice();
  tamperedHeader[3] ^= 0x01;
  let threwHeader = false;
  try {
    decryptMessage(tamperedHeader, sharedB, salt);
  } catch (e) {
    threwHeader = /Integrity check failed/.test(e.message);
  }
  check('tampered header byte -> rejected', threwHeader);

  // Flip a bit in tag9 itself.
  const tamperedTag = packet.slice();
  tamperedTag[packet.length - 40] ^= 0x01; // inside tag9 region
  let threwTag = false;
  try {
    decryptMessage(tamperedTag, sharedB, salt);
  } catch (e) {
    threwTag = /Integrity check failed/.test(e.message);
  }
  check('tampered tag9 byte -> rejected', threwTag);

  // Wrong shared secret (different conversation key) must fail too.
  const mallory = generateKeyPair();
  const wrongShared = computeSharedSecret(mallory.privateKey, bob.publicKey);
  let threwWrongKey = false;
  try {
    decryptMessage(packet, wrongShared, salt);
  } catch (e) {
    threwWrongKey = /Integrity check failed/.test(e.message);
  }
  check('wrong shared secret -> rejected', threwWrongKey);
}

console.log('\n=== 6) Each layer individually sanity-checked via full pipeline diff ===');
{
  // Two different plaintexts should never produce colliding packets,
  // and re-encrypting the same plaintext twice should produce DIFFERENT
  // packets (because nonces/IVs/seeds are fresh random each time) —
  // this is what gives semantic security (no two messages look alike).
  const pt = new TextEncoder().encode('same message');
  const p1 = encryptMessage(pt, sharedA, salt);
  const p2 = encryptMessage(pt, sharedA, salt);
  check('same plaintext -> different ciphertext packets (fresh randomness)', !bytesEqual(p1, p2));
  check('but both decrypt to the same plaintext', bytesEqual(decryptMessage(p1, sharedB, salt), decryptMessage(p2, sharedB, salt)));
}

console.log('\n=== 7) Larger payload — "video chunk" simulation (2 MB) ===');
{
  const size = 2 * 1024 * 1024;
  const plaintext = new Uint8Array(size);
  // Fill with pseudo-random-ish data to better mimic real media
  let seed = 12345;
  for (let i = 0; i < size; i++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    plaintext[i] = seed & 0xff;
  }

  const t0 = Date.now();
  const packet = encryptMessage(plaintext, sharedA, salt);
  const t1 = Date.now();
  const decrypted = decryptMessage(packet, sharedB, salt);
  const t2 = Date.now();

  check('2MB roundtrip matches', bytesEqual(plaintext, decrypted));
  console.log(`  encrypt: ${t1 - t0}ms, decrypt: ${t2 - t1}ms`);
  console.log(`  throughput (encrypt): ${(size / 1024 / 1024 / ((t1 - t0) / 1000)).toFixed(2)} MB/s`);
}

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
