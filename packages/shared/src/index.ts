/**
 * @veilops/shared — encoding helpers, identifiers and the core record types
 * shared by every VEILOPS package. No cryptographic decisions live here.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes, concatBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, utf8ToBytes, randomBytes, concatBytes };

export const PROTOCOL_VERSION = 'veilops/0.1';

/** Implementation status labels used across the SDK, docs and UI. Never upgrade a label without evidence. */
export type ImplementationStatus =
  | 'implemented'      // real code, unit-tested in this repository
  | 'experimental'     // real code, not reviewed, not production-ready
  | 'simulated'        // a stand-in that imitates a future component's interface
  | 'planned';         // design only

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Deterministic JSON: object keys sorted recursively. Used for anything that gets hashed or signed. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'bigint') return JSON.stringify(value.toString());
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256(typeof data === 'string' ? utf8ToBytes(data) : data));
}

/** Short, prefixed, random identifier, e.g. `op_4f1c9a02b7e3d815`. */
export function randomId(prefix: string, bytes = 8): string {
  return `${prefix}_${bytesToHex(randomBytes(bytes))}`;
}

/** Content-derived identifier: the same content always yields the same id. */
export function contentId(prefix: string, content: unknown, bytes = 10): string {
  return `${prefix}_${sha256Hex(canonicalJson(content)).slice(0, bytes * 2)}`;
}

export function shortHex(hex: string, head = 6, tail = 4): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export type OperationCategory = 'treasury' | 'payroll' | 'vendor' | 'grant' | 'operations';
export type ConfidentialityMode = 'amount-only' | 'amount-and-recipient' | 'full';
export type VerificationStatus = 'verified' | 'failed' | 'pending';

/** What the operator types in. Never published as-is. */
export interface OperationInput {
  name: string;
  category: OperationCategory;
  recipient: string;
  /** Integer amount in the asset's smallest display unit (e.g. cents). */
  amount: number;
  asset: string;
  policyLimit: number;
  mode: ConfidentialityMode;
  memo?: string;
}

/** The record that may be published to the public explorer. Contains no plaintext sensitive values. */
export interface PublicRecord {
  version: typeof PROTOCOL_VERSION;
  operationId: string;
  proofId: string;
  createdAt: string;
  category: OperationCategory;
  asset: string;
  mode: ConfidentialityMode;
  policy: { id: string; maxAmount: number; rangeBits: number };
  /** Hex of the Pedersen commitment to the amount. */
  amountCommitment: string;
  /** Hex SHA-256 of the AES-GCM envelope; the ciphertext itself stays with the operator. */
  envelopeDigest: string;
  /** Present only when the recipient is public under the chosen mode. */
  recipient?: string;
  proofSystem: string;
  proof: string; // base64 serialized proof
  attestation: { publicKey: string; signature: string };
  sample?: boolean;
}
