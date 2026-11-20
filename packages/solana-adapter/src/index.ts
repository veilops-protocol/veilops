/**
 * @veilops/solana-adapter — anchoring proof records on Solana.
 *
 * Status: experimental. The adapter builds an SPL Memo instruction that anchors
 *   veilops:<version>:<proofId>:<recordDigest>
 * so anyone can later check that a published record existed at a slot. It has been exercised on devnet
 * (scripts/devnet-anchor.ts, 6 anchors, verified daily); never on mainnet. No transaction is sent by this package. Signing and sending
 * stay with the caller's wallet. Confidential transfers (Token-2022 extension) are a planned integration.
 */
import { canonicalJson, sha256Hex, type PublicRecord } from '@veilops/shared';

export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

export type Cluster = 'devnet' | 'testnet' | 'mainnet-beta';
export const CLUSTER_STATUS: Record<Cluster, 'untested' | 'tested'> = { devnet: 'tested', testnet: 'untested', 'mainnet-beta': 'untested' };

export function recordDigest(rec: PublicRecord): string {
  return sha256Hex(canonicalJson(rec));
}

export function anchorMemo(rec: PublicRecord): string {
  const memo = `veilops:${rec.version}:${rec.proofId}:${recordDigest(rec)}`;
  if (new TextEncoder().encode(memo).length > 566) throw new Error('memo too long');
  return memo;
}

/** A transport-agnostic instruction description; convert it with your Solana client of choice. */
export interface InstructionLike { programId: string; keys: { pubkey: string; isSigner: boolean; isWritable: boolean }[]; data: Uint8Array }

export function buildAnchorInstruction(rec: PublicRecord, signer: string): InstructionLike {
  return { programId: MEMO_PROGRAM_ID, keys: [{ pubkey: signer, isSigner: true, isWritable: false }], data: new TextEncoder().encode(anchorMemo(rec)) };
}

/** Parse a memo previously written by `anchorMemo`. */
export function parseAnchorMemo(memo: string): { version: string; proofId: string; digest: string } | null {
  const m = /^veilops:([^:]+):(prf_[0-9a-f]+):([0-9a-f]{64})$/.exec(memo.trim());
  return m ? { version: m[1]!, proofId: m[2]!, digest: m[3]! } : null;
}
