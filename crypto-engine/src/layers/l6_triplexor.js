/**
 * LAYER 6 — TripleXOR
 *
 * HONESTY NOTE: "XOR" by itself (e.g. repeating-key XOR) is a classical,
 * trivially breakable cipher (frequency analysis / Vigenère-style attacks).
 * To make this layer cryptographically meaningful, it does NOT XOR with a
 * short repeating key. Instead it derives THREE independent 256-bit keys
 * (via HKDF from the layer key + a random per-message seed), generates a
 * full-length ChaCha20 keystream from each, and XORs the data with the
 * combination of all three keystreams. Each individual keystream is a real
 * ChaCha20 output (computationally indistinguishable from random), so the
 * combined keystream is as well — "TripleXOR" describes the structure, not
 * a weak classical cipher.
 */
import { chacha20 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const enc = new TextEncoder();
export const META_LEN = 16; // per-message seed length

function deriveSubKey(key, seed, label) {
  return hkdf(sha256, key, seed, enc.encode(label), 32);
}

function deriveNonce(key, seed, label) {
  return hkdf(sha256, key, seed, enc.encode(label), 12);
}

function keystream(subKey, nonce, len) {
  return chacha20(subKey, nonce, new Uint8Array(len));
}

function transform(data, key, seed) {
  const ka = deriveSubKey(key, seed, 'l6a');
  const kb = deriveSubKey(key, seed, 'l6b');
  const kc = deriveSubKey(key, seed, 'l6c');
  const na = deriveNonce(key, seed, 'l6na');
  const nb = deriveNonce(key, seed, 'l6nb');
  const nc = deriveNonce(key, seed, 'l6nc');

  const ksa = keystream(ka, na, data.length);
  const ksb = keystream(kb, nb, data.length);
  const ksc = keystream(kc, nc, data.length);

  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ ksa[i] ^ ksb[i] ^ ksc[i];
  }
  return out;
}

export function encrypt(data, key) {
  const seed = randomBytes(16);
  return { out: transform(data, key, seed), meta: seed };
}

export function decrypt(data, key, meta) {
  // XOR is self-inverse given the same combined keystream.
  return transform(data, key, meta);
}
