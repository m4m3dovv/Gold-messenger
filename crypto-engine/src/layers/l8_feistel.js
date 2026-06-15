/**
 * LAYER 8 — Feistel network (BLAKE3-keyed + ChaCha20 round function, 16-byte nonce)
 *
 * "Feistel" is a network STRUCTURE, not a standalone algorithm — it needs a
 * round function F. Here F works in two steps: first BLAKE3 (keyed mode)
 * compresses the entire half-buffer down to a 32-byte digest (this is the
 * O(len) "mixing" step, using BLAKE3 in normal hash mode rather than its
 * expensive XOF mode), then that 32-byte digest is used as a ChaCha20 key
 * to generate a len(half)-byte keystream which is XORed into the other
 * half. Both BLAKE3 and ChaCha20 are real, standard primitives; combining a
 * hash-compression step with a stream-expansion step is a standard and
 * efficient way to build a hash-based PRF over large inputs. As with any
 * Feistel round function, F does NOT need to be invertible — the network
 * structure guarantees overall invertibility regardless.
 *
 * The buffer is split into two equal halves (pipeline guarantees an even
 * length at this point, since L3's AES-CBC output is always a multiple of
 * 16) and run through 6 Feistel rounds.
 */
import { blake3 } from '@noble/hashes/blake3.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, concatBytes } from '@noble/hashes/utils.js';

const enc = new TextEncoder();
export const META_LEN = 16; // per-message nonce length
const ROUNDS = 6;
const ZERO_SALT = new Uint8Array(32);

function roundKey(key, i) {
  return hkdf(sha256, key, ZERO_SALT, enc.encode('l8-round-' + i), 32);
}

function F(half, nonce, roundKeyBytes, i) {
  const len = half.length;
  if (len === 0) return new Uint8Array(0);
  const info = concatBytes(nonce, new Uint8Array([i]));
  // O(len) compression step (BLAKE3 keyed, normal 32-byte digest — no XOF).
  const digest = blake3(concatBytes(info, half), { key: roundKeyBytes, dkLen: 32 });
  // O(len) expansion step (ChaCha20 keystream from the digest).
  const ccNonce = concatBytes(nonce.slice(0, 11), new Uint8Array([i]));
  return chacha20(digest, ccNonce, new Uint8Array(len));
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function transform(data, key, nonce, forward) {
  const n = data.length;
  const half = n >> 1; // n is even (guaranteed by pipeline ordering after L3)
  let L = data.slice(0, half);
  let R = data.slice(half, n);

  const keys = [];
  for (let i = 0; i < ROUNDS; i++) keys.push(roundKey(key, i));

  if (forward) {
    for (let i = 0; i < ROUNDS; i++) {
      const f = F(R, nonce, keys[i], i);
      const newR = xorBytes(L, f);
      L = R;
      R = newR;
    }
  } else {
    for (let i = ROUNDS - 1; i >= 0; i--) {
      const f = F(L, nonce, keys[i], i);
      const newL = xorBytes(R, f);
      R = L;
      L = newL;
    }
  }
  return concatBytes(L, R);
}

export function encrypt(data, key) {
  const nonce = randomBytes(16);
  return { out: transform(data, key, nonce, true), meta: nonce };
}

export function decrypt(data, key, meta) {
  return transform(data, key, meta, false);
}
