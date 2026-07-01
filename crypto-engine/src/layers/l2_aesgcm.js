/**
 * LAYER 2 — AES-256-GCM (AEAD, 12-byte nonce)
 * Real, standard algorithm (NIST SP 800-38D). Output already includes a
 * 16-byte authentication tag appended by @noble/ciphers, so this layer
 * provides its own built-in tamper detection in addition to L9/L10.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/hashes/utils.js';

export const META_LEN = 12; // nonce length

export function encrypt(data, key) {
  const nonce = randomBytes(12);
  return { out: gcm(key, nonce).encrypt(data), meta: nonce };
}

export function decrypt(data, key, meta) {
  // Throws if the embedded GCM tag does not verify (tamper detection).
  return gcm(key, meta).decrypt(data);
}
