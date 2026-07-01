/**
 * Optional object-storage backend for large encrypted media blobs.
 *
 * Why: the default path stores every packet (including images/video)
 * straight in Postgres as BYTEA via JSON+base64, capped at ~14MB by
 * the client and the 20mb express.json() limit. That's fine for text
 * and small media, but wasteful for anything bigger and doesn't scale.
 *
 * If S3-compatible credentials are present (works with AWS S3,
 * Cloudflare R2, Backblaze B2 — anything S3-compatible), large
 * encrypted packets are streamed to object storage instead, and only
 * a small pointer is stored in Postgres. The server still only ever
 * handles opaque ciphertext — it has no keys and cannot decrypt.
 *
 * If no credentials are configured, everything falls back to the
 * original inline-BYTEA behaviour automatically — no code changes
 * needed elsewhere.
 */
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import crypto from 'crypto';

const {
  S3_BUCKET,
  S3_ENDPOINT,
  S3_REGION = 'auto',
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_INLINE_MAX_BYTES = String(256 * 1024), // packets smaller than this stay inline in Postgres
} = process.env;

export const mediaStorageEnabled = Boolean(S3_BUCKET && S3_ACCESS_KEY_ID && S3_SECRET_ACCESS_KEY);

let s3 = null;
if (mediaStorageEnabled) {
  s3 = new S3Client({
    region: S3_REGION,
    endpoint: S3_ENDPOINT || undefined,
    credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
    forcePathStyle: Boolean(S3_ENDPOINT), // needed for R2/B2/minio-style endpoints
  });
}

export function shouldOffload(buf) {
  return mediaStorageEnabled && buf.length > Number(S3_INLINE_MAX_BYTES);
}

/** Uploads an opaque encrypted packet, returns an object key to store instead of raw bytes. */
export async function uploadPacket(buf) {
  if (!s3) throw new Error('media_storage_disabled');
  const key = `packets/${crypto.randomUUID()}.bin`;
  await s3.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: buf,
      ContentType: 'application/octet-stream',
    })
  );
  return key;
}

export async function downloadPacket(key) {
  if (!s3) throw new Error('media_storage_disabled');
  const out = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }));
  const chunks = [];
  for await (const chunk of out.Body) chunks.push(chunk);
  return Buffer.concat(chunks);
}

export async function deletePacket(key) {
  if (!s3) return;
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: key }));
  } catch (e) {
    console.warn('[media] delete failed:', e?.message || e);
  }
}

// A stored "packet" is either raw bytes (legacy/small) or a small JSON
// pointer `{"$s3": "packets/xxx.bin"}` — these helpers hide that from callers.
const POINTER_PREFIX = Buffer.from('{"$s3":"');

export function isPointer(buf) {
  return buf.subarray(0, POINTER_PREFIX.length).equals(POINTER_PREFIX);
}

export function makePointer(key) {
  return Buffer.from(JSON.stringify({ $s3: key }));
}

export function readPointerKey(buf) {
  return JSON.parse(buf.toString('utf8')).$s3;
}
