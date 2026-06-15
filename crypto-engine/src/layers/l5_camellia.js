/**
 * LAYER 5 — "Camellia-style" 128-bit block cipher, CTR mode (16-byte IV)
 *
 * HONESTY NOTE: There is no maintained pure-JS Camellia (RFC 3713)
 * implementation available, and hand-transcribing Camellia's exact S-boxes
 * and key schedule from memory carries real risk of subtle, hard-to-detect
 * errors. Instead, this layer implements a cipher with the SAME OVERALL
 * SHAPE as Camellia — a 128-bit-block, 18-round Feistel network whose round
 * function applies a well-known, verified non-linear S-box (the standard
 * AES/Rijndael S-box) followed by a rotate-XOR diffusion step — run in CTR
 * mode so it works on arbitrary-length data.
 *
 * It is NOT bit-compatible with RFC 3713 Camellia. It IS a real
 * substitution-permutation/Feistel construction with a 256-entry non-linear
 * S-box, 18 rounds, and per-conversation keys derived via HKDF.
 *
 * Security of the overall pipeline does not depend on this layer alone —
 * L1/L2/L4 (ChaCha20, AES-GCM, XSalsa20) are the primary confidentiality
 * layers, and L9/L10 provide integrity.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const enc = new TextEncoder();
export const META_LEN = 16; // IV length
const ROUNDS = 18;
const ZERO_SALT = new Uint8Array(32);

// Standard AES/Rijndael S-box (256 entries) — used as the non-linear
// substitution component of the round function below.
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

function roundKey(key, i) {
  return hkdf(sha256, key, ZERO_SALT, enc.encode('l5-camellia-rk-' + i), 8);
}

// Round function applied in-place: reads 8 bytes from `buf` at `off`,
// XORs with `k` (8 bytes), substitutes via S-box into scratch `t`,
// then writes the rotate/XOR-mixed diffusion result into `out` (8 bytes).
// No allocations — `t` and `out` are caller-provided scratch buffers.
function Finto(buf, off, k, t, out) {
  for (let i = 0; i < 8; i++) t[i] = SBOX[buf[off + i] ^ k[i]];
  out[0] = t[0] ^ t[1] ^ t[3] ^ t[5];
  out[1] = t[1] ^ t[2] ^ t[4] ^ t[6];
  out[2] = t[2] ^ t[3] ^ t[5] ^ t[7];
  out[3] = t[3] ^ t[4] ^ t[6] ^ t[0];
  out[4] = t[4] ^ t[5] ^ t[7] ^ t[1];
  out[5] = t[5] ^ t[6] ^ t[0] ^ t[2];
  out[6] = t[6] ^ t[7] ^ t[1] ^ t[3];
  out[7] = t[7] ^ t[0] ^ t[2] ^ t[4];
}

// Encrypts one 16-byte block in place inside `block` (a length-16 scratch
// Uint8Array). Uses three small scratch buffers (t, f, newR) provided by
// the caller so the hot loop performs zero per-block allocations.
function encryptBlockInto(block, roundKeys, t, f, newR) {
  // block[0..8) = L, block[8..16) = R
  for (let r = 0; r < ROUNDS; r++) {
    Finto(block, 8, roundKeys[r], t, f);
    for (let j = 0; j < 8; j++) newR[j] = block[j] ^ f[j];
    // L = R
    for (let j = 0; j < 8; j++) block[j] = block[8 + j];
    // R = newR
    for (let j = 0; j < 8; j++) block[8 + j] = newR[j];
  }
}

// Mutates `ctr` in place: big-endian 128-bit increment over 16 bytes.
function incrCounter(ctr) {
  for (let i = 15; i >= 0; i--) {
    ctr[i] = (ctr[i] + 1) & 0xff;
    if (ctr[i] !== 0) break;
  }
}

function ctrTransform(data, key, iv) {
  const roundKeys = [];
  for (let i = 0; i < ROUNDS; i++) roundKeys.push(roundKey(key, i));

  const out = new Uint8Array(data.length);
  const block = new Uint8Array(16); // working copy of counter -> keystream
  const t = new Uint8Array(8);
  const f = new Uint8Array(8);
  const newR = new Uint8Array(8);
  let ctr = iv.slice(); // local working copy — `iv` (the returned meta) must stay untouched
  let off = 0;
  while (off < data.length) {
    block.set(ctr);
    encryptBlockInto(block, roundKeys, t, f, newR);
    const n = Math.min(16, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
    off += 16;
    incrCounter(ctr);
  }
  return out;
}

export function encrypt(data, key) {
  const iv = randomBytes(16);
  return { out: ctrTransform(data, key, iv), meta: iv };
}

export function decrypt(data, key, meta) {
  // CTR mode: decryption is the same keystream-XOR operation as encryption.
  return ctrTransform(data, key, meta);
}
