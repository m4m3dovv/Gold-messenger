/**
 * LAYER 10 — HMAC-SHA256 (32-byte tag)
 * Real, standard algorithm (RFC 2104). Final integrity tag, computed over
 * (L1-L8 output || L9 tag) — a second, independent MAC using a different
 * construction (HMAC vs BLAKE3-keyed) and a different key, so a weakness
 * in one MAC construction does not break the other.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

export function tag(key, data) {
  return hmac(sha256, key, data);
}
