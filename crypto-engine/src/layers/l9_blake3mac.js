/**
 * LAYER 9 — BLAKE3 keyed MAC (32-byte tag)
 * Real, standard algorithm. BLAKE3's native keyed mode is itself a secure
 * MAC. Produces a 32-byte authentication tag over the output of L1–L8.
 */
import { blake3 } from '@noble/hashes/blake3.js';

export function tag(key, data) {
  return blake3(data, { key, dkLen: 32 });
}
