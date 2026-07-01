/**
 * LAYER 1 — ChaCha20 (stream cipher, 12-byte nonce)
 * Real, standard algorithm (RFC 8439 core). Symmetric XOR-keystream,
 * so encrypt() and decrypt() are the same operation given the same nonce.
 */
import { chacha20 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';

export const META_LEN = 12; // nonce length

export function encrypt(data, key) {
  const nonce = randomBytes(12);
  return { out: chacha20(key, nonce, data), meta: nonce };
}

export function decrypt(data, key, meta) {
  return chacha20(key, meta, data);
}
