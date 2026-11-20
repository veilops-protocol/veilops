/**
 * @veilops/encryption — browser- and Node-compatible envelope encryption.
 *
 * - Payload cipher: AES-256-GCM (WebCrypto), 96-bit random nonce, associated data bound to the operation id.
 * - Key wrapping: X25519 ECDH + HKDF-SHA256 → AES-256-GCM key-encryption key, one wrap per recipient.
 *   This is how selective disclosure works: the same data key is wrapped for the owner and for each
 *   authorized viewer (e.g. an auditor). Nobody else can open the envelope.
 *
 * Status: implemented (unit-tested). Not externally reviewed.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, toBase64, fromBase64, concatBytes } from '@veilops/shared';

const subtle = () => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto (crypto.subtle) is not available in this environment');
  return s;
};

export interface KeyPair { publicKey: string; secretKey: Uint8Array }

/** X25519 key pair. The secret key never leaves the caller; VEILOPS never persists it. */
export function generateViewingKeyPair(): KeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: bytesToHex(x25519.getPublicKey(secretKey)) };
}

export interface WrappedKey {
  /** Recipient public key (hex) — tells the reader which wrap is theirs. */
  recipient: string;
  /** Ephemeral X25519 public key (hex). */
  ephemeral: string;
  nonce: string;
  wrapped: string; // base64
}

export interface Envelope {
  alg: 'AES-256-GCM+X25519-HKDF-SHA256';
  aad: string;
  nonce: string;
  ciphertext: string; // base64
  keys: WrappedKey[];
}

async function aesKey(raw: Uint8Array, usage: KeyUsage[]) {
  return subtle().importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, usage);
}

async function aesEncrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array) {
  const k = await aesKey(key, ['encrypt']);
  return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource }, k, data as BufferSource));
}

async function aesDecrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array) {
  const k = await aesKey(key, ['decrypt']);
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource }, k, data as BufferSource));
}

function kek(shared: Uint8Array, ephemeral: Uint8Array, recipient: Uint8Array) {
  return hkdf(sha256, shared, concatBytes(ephemeral, recipient), utf8ToBytes('veilops/kek/v1'), 32);
}

async function wrapFor(dataKey: Uint8Array, recipientHex: string, aad: Uint8Array): Promise<WrappedKey> {
  const recipient = hexToBytes(recipientHex);
  const eSk = x25519.utils.randomSecretKey();
  const ePk = x25519.getPublicKey(eSk);
  const shared = x25519.getSharedSecret(eSk, recipient);
  const nonce = randomBytes(12);
  const wrapped = await aesEncrypt(kek(shared, ePk, recipient), nonce, dataKey, aad);
  return { recipient: recipientHex, ephemeral: bytesToHex(ePk), nonce: bytesToHex(nonce), wrapped: toBase64(wrapped) };
}

/** Encrypt `plaintext` so that only the listed X25519 public keys can read it. */
export async function seal(plaintext: Uint8Array | string, recipients: string[], aad: string): Promise<Envelope> {
  if (recipients.length === 0) throw new Error('seal: at least one recipient is required');
  const data = typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext;
  const aadBytes = utf8ToBytes(aad);
  const dataKey = randomBytes(32);
  const nonce = randomBytes(12);
  const ciphertext = await aesEncrypt(dataKey, nonce, data, aadBytes);
  const keys = await Promise.all(recipients.map(r => wrapFor(dataKey, r, aadBytes)));
  dataKey.fill(0);
  return { alg: 'AES-256-GCM+X25519-HKDF-SHA256', aad, nonce: bytesToHex(nonce), ciphertext: toBase64(ciphertext), keys };
}

/** Open an envelope with a recipient's secret key. Throws if the key is not a recipient or data was altered. */
export async function open(envelope: Envelope, secretKey: Uint8Array): Promise<Uint8Array> {
  const pub = bytesToHex(x25519.getPublicKey(secretKey));
  const wrap = envelope.keys.find(k => k.recipient === pub);
  if (!wrap) throw new Error('open: this key is not an authorized recipient of the envelope');
  const aad = utf8ToBytes(envelope.aad);
  const ePk = hexToBytes(wrap.ephemeral);
  const shared = x25519.getSharedSecret(secretKey, ePk);
  const dataKey = await aesDecrypt(kek(shared, ePk, hexToBytes(pub)), hexToBytes(wrap.nonce), fromBase64(wrap.wrapped), aad);
  try {
    return await aesDecrypt(dataKey, hexToBytes(envelope.nonce), fromBase64(envelope.ciphertext), aad);
  } finally {
    dataKey.fill(0);
  }
}

export async function openText(envelope: Envelope, secretKey: Uint8Array): Promise<string> {
  return new TextDecoder().decode(await open(envelope, secretKey));
}

/** Add another authorized reader (selective disclosure) without re-encrypting the payload. */
export async function grantAccess(envelope: Envelope, ownerSecret: Uint8Array, newRecipient: string): Promise<Envelope> {
  const pub = bytesToHex(x25519.getPublicKey(ownerSecret));
  const wrap = envelope.keys.find(k => k.recipient === pub);
  if (!wrap) throw new Error('grantAccess: owner key is not a recipient');
  if (envelope.keys.some(k => k.recipient === newRecipient)) return envelope;
  const aad = utf8ToBytes(envelope.aad);
  const ePk = hexToBytes(wrap.ephemeral);
  const shared = x25519.getSharedSecret(ownerSecret, ePk);
  const dataKey = await aesDecrypt(kek(shared, ePk, hexToBytes(pub)), hexToBytes(wrap.nonce), fromBase64(wrap.wrapped), aad);
  const added = await wrapFor(dataKey, newRecipient, aad);
  dataKey.fill(0);
  return { ...envelope, keys: [...envelope.keys, added] };
}

/** Digest that can be published to prove which envelope a record refers to, without publishing it. */
export function envelopeDigest(envelope: Envelope): string {
  return bytesToHex(sha256(utf8ToBytes(envelope.ciphertext + '|' + envelope.nonce + '|' + envelope.aad)));
}
