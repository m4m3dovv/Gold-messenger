/**
 * 10-layer encryption pipeline.
 *
 * encryptMessage(): plaintext -> L1 -> L2 -> ... -> L8 -> [+L9 tag] -> [+L10 tag] -> packet
 * decryptMessage(): packet -> verify L10 -> verify L9 -> L8 -> ... -> L1 -> plaintext
 *
 * Packet layout:
 *   [ HEADER (128 bytes: per-layer nonces/IVs/seeds, fixed sizes) ]
 *   [ PAYLOAD (variable: output of L8) ]
 *   [ TAG9  (32 bytes: BLAKE3 keyed MAC) ]
 *   [ TAG10 (32 bytes: HMAC-SHA256) ]
 *
 * On any tamper (payload, tag9, or header bytes that affect a layer's
 * nonce/IV), L10 and/or L9 verification fails BEFORE any layer is reversed,
 * and decryptMessage() throws.
 */
import { concatBytes } from '@noble/hashes/utils.js';
import { deriveLayerKeys } from './keys.js';

import * as L1 from './layers/l1_chacha20.js';
import * as L2 from './layers/l2_aesgcm.js';
import * as L3 from './layers/l3_aescbc.js';
import * as L4 from './layers/l4_xsalsa20.js';
import * as L5 from './layers/l5_camellia.js';
import * as L6 from './layers/l6_triplexor.js';
import * as L7 from './layers/l7_bittransp.js';
import * as L8 from './layers/l8_feistel.js';
import * as L9 from './layers/l9_blake3mac.js';
import * as L10 from './layers/l10_hmac.js';

const LAYERS = [L1, L2, L3, L4, L5, L6, L7, L8];
export const HEADER_LEN = LAYERS.reduce((sum, L) => sum + L.META_LEN, 0); // 128
const TAG_LEN = 32 + 32; // BLAKE3 + HMAC

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} sharedSecret - 32-byte X25519 shared secret
 * @param {Uint8Array} salt - per-conversation salt (see identity.js)
 * @returns {Uint8Array} packet ready to send to the other party / server
 */
export function encryptMessage(plaintext, sharedSecret, salt) {
  const keys = deriveLayerKeys(sharedSecret, salt);

  let data = plaintext;
  const metas = [];
  for (let i = 0; i < LAYERS.length; i++) {
    const { out, meta } = LAYERS[i].encrypt(data, keys['K' + (i + 1)]);
    data = out;
    metas.push(meta);
  }

  // The header (all per-layer nonces/IVs/seeds) is bound into both MACs as
  // associated data: any tampering with the header is detected up front,
  // before any layer is reversed, exactly like tampering with the payload.
  const header = concatBytes(...metas);
  const tag9 = L9.tag(keys.K9, concatBytes(header, data));
  const tag10 = L10.tag(keys.K10, concatBytes(header, data, tag9));

  return concatBytes(header, data, tag9, tag10);
}

/**
 * @param {Uint8Array} packet
 * @param {Uint8Array} sharedSecret - 32-byte X25519 shared secret
 * @param {Uint8Array} salt - per-conversation salt (see identity.js)
 * @returns {Uint8Array} plaintext
 * @throws if the packet is malformed or fails integrity verification
 */
export function decryptMessage(packet, sharedSecret, salt) {
  if (packet.length < HEADER_LEN + TAG_LEN) {
    throw new Error('Packet too short');
  }
  const keys = deriveLayerKeys(sharedSecret, salt);

  let offset = 0;
  const metas = [];
  for (const L of LAYERS) {
    metas.push(packet.slice(offset, offset + L.META_LEN));
    offset += L.META_LEN;
  }
  const header = packet.slice(0, HEADER_LEN);

  const rest = packet.slice(offset);
  const tag10 = rest.slice(rest.length - 32);
  const tag9 = rest.slice(rest.length - 64, rest.length - 32);
  let data = rest.slice(0, rest.length - 64);

  const expected10 = L10.tag(keys.K10, concatBytes(header, data, tag9));
  if (!timingSafeEqual(expected10, tag10)) {
    throw new Error('Integrity check failed (L10/HMAC) — message rejected');
  }

  const expected9 = L9.tag(keys.K9, concatBytes(header, data));
  if (!timingSafeEqual(expected9, tag9)) {
    throw new Error('Integrity check failed (L9/BLAKE3) — message rejected');
  }

  for (let i = LAYERS.length - 1; i >= 0; i--) {
    data = LAYERS[i].decrypt(data, keys['K' + (i + 1)], metas[i]);
  }
  return data;
}
