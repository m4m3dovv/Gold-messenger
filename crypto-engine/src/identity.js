/**
 * Identity & key agreement (X25519 / ECDH).
 *
 * Each user generates one long-term X25519 keypair on their device at
 * registration. The PRIVATE key never leaves the device (and, ideally,
 * never reaches the server in plaintext). Two users derive a shared
 * secret from (myPrivateKey, theirPublicKey) — this is the foundation of
 * end-to-end encryption: the server only ever sees public keys and
 * already-encrypted packets.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';

export function generateKeyPair() {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Re-derive the public key from a stored private key (e.g. after loading
 *  it back from device storage). */
export function publicKeyFromPrivate(privateKey) {
  return x25519.getPublicKey(privateKey);
}

export function computeSharedSecret(myPrivateKey, theirPublicKey) {
  return x25519.getSharedSecret(myPrivateKey, theirPublicKey);
}

function cmpBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Order-independent per-conversation salt, derived from both users' public
 * keys so both sides compute the same value regardless of who is "A" and
 * who is "B".
 */
export function conversationSalt(pubKeyA, pubKeyB) {
  const [x, y] = cmpBytes(pubKeyA, pubKeyB) <= 0 ? [pubKeyA, pubKeyB] : [pubKeyB, pubKeyA];
  return sha256(concatBytes(x, y));
}
