/**
 * LAYER 7 — BitTransp (key-derived byte transposition)
 *
 * Splits the buffer into fixed-size chunks and permutes the byte order
 * within each chunk according to a permutation derived from the layer key
 * + a random per-message seed (via ChaCha20-driven Durstenfeld shuffle).
 * The same permutation is reused across all full chunks (generated once,
 * O(CHUNK) cost) so this stays fast even for multi-MB media; the final
 * partial chunk gets its own correctly-sized permutation.
 *
 * This is a pure diffusion/transposition layer — it does not by itself
 * provide confidentiality (a permutation of known length leaks the
 * multiset of bytes), which is why it sits in the middle of the pipeline,
 * operating on data that previous layers have already encrypted.
 */
import { chacha20 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const enc = new TextEncoder();
export const META_LEN = 16; // per-message seed length
const CHUNK = 4096;

function genPermutation(key, seed, n, label) {
  const subKey = hkdf(sha256, key, seed, enc.encode(label), 32);
  const nonce = hkdf(sha256, key, seed, enc.encode(label + '-n'), 12);
  const rand = chacha20(subKey, nonce, new Uint8Array(n * 4));

  const perm = new Uint32Array(n);
  for (let i = 0; i < n; i++) perm[i] = i;

  let ri = 0;
  for (let i = n - 1; i > 0; i--) {
    const r =
      ((rand[ri] << 24) | (rand[ri + 1] << 16) | (rand[ri + 2] << 8) | rand[ri + 3]) >>> 0;
    ri += 4;
    const j = r % (i + 1);
    const tmp = perm[i];
    perm[i] = perm[j];
    perm[j] = tmp;
  }
  return perm;
}

function applyPerm(buf, perm, inverse) {
  const out = new Uint8Array(buf.length);
  if (!inverse) {
    for (let i = 0; i < buf.length; i++) out[i] = buf[perm[i]];
  } else {
    for (let i = 0; i < buf.length; i++) out[perm[i]] = buf[i];
  }
  return out;
}

function transform(data, key, seed, inverse) {
  const fullChunks = Math.floor(data.length / CHUNK);
  const rem = data.length % CHUNK;
  const out = new Uint8Array(data.length);

  if (fullChunks > 0) {
    const permFull = genPermutation(key, seed, CHUNK, 'l7full');
    for (let c = 0; c < fullChunks; c++) {
      const chunk = data.subarray(c * CHUNK, (c + 1) * CHUNK);
      out.set(applyPerm(chunk, permFull, inverse), c * CHUNK);
    }
  }
  if (rem > 0) {
    const permRem = genPermutation(key, seed, rem, 'l7rem');
    const chunk = data.subarray(fullChunks * CHUNK);
    out.set(applyPerm(chunk, permRem, inverse), fullChunks * CHUNK);
  }
  return out;
}

export function encrypt(data, key) {
  const seed = randomBytes(16);
  return { out: transform(data, key, seed, false), meta: seed };
}

export function decrypt(data, key, meta) {
  return transform(data, key, meta, true);
}
