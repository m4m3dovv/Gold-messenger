/**
 * Per-layer key derivation.
 *
 * From a single shared secret (32 bytes, e.g. an X25519 ECDH output) and a
 * per-conversation salt, derive 10 independent 256-bit keys — one per
 * pipeline layer — via HKDF-SHA256 with distinct "info" labels. This means
 * a weakness affecting one layer's key does not reveal anything about the
 * other layers' keys.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const enc = new TextEncoder();

export function deriveLayerKeys(sharedSecret, salt) {
  const keys = {};
  for (let i = 1; i <= 10; i++) {
    keys['K' + i] = hkdf(sha256, sharedSecret, salt, enc.encode('layer-' + i), 32);
  }
  return keys;
}
