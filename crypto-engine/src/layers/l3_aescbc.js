/**
 * LAYER 3 — AES-256-CBC with PKCS#7 padding (16-byte IV)
 * Real, standard algorithm (NIST SP 800-38A). CBC requires block-aligned
 * input, hence the PKCS#7 padding (self-describing, so no extra metadata
 * is needed to reverse it).
 */
import { cbc } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/hashes/utils.js';

export const META_LEN = 16; // IV length
const BLOCK = 16;

function pkcs7Pad(data) {
  const padLen = BLOCK - (data.length % BLOCK);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data) {
  if (data.length === 0 || data.length % BLOCK !== 0) {
    throw new Error('L3 AES-CBC: invalid padded length');
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > BLOCK || padLen > data.length) {
    throw new Error('L3 AES-CBC: invalid padding');
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('L3 AES-CBC: invalid padding bytes');
  }
  return data.slice(0, data.length - padLen);
}

export function encrypt(data, key) {
  const iv = randomBytes(16);
  const padded = pkcs7Pad(data);
  return { out: cbc(key, iv).encrypt(padded), meta: iv };
}

export function decrypt(data, key, meta) {
  const padded = cbc(key, meta).decrypt(data);
  return pkcs7Unpad(padded);
}
