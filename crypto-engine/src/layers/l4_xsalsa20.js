/**
 * LAYER 4 — XSalsa20 (extended-nonce Salsa20, 24-byte nonce)
 * Real, standard algorithm (used by NaCl/libsodium's secretbox). Symmetric
 * XOR-keystream, so encrypt() and decrypt() are the same operation given
 * the same nonce.
 */
import { xsalsa20 } from '@noble/ciphers/salsa.js';
import { randomBytes } from '@noble/hashes/utils.js';

export const META_LEN = 24; // nonce length

export function encrypt(data, key) {
  const nonce = randomBytes(24);
  return { out: xsalsa20(key, nonce, data), meta: nonce };
}

export function decrypt(data, key, meta) {
  return xsalsa20(key, meta, data);
}
