/**
 * Minimal client for the `veilops-verifier` Solana program (onchain/programs/veilops-verifier).
 * Instructions are encoded by hand (Anchor discriminator + Borsh) so the format is easy to audit.
 */
import { createHash } from 'node:crypto';
import {
  AccountRole, address, getAddressEncoder, getProgramDerivedAddress, generateKeyPairSigner,
  type Address, type Instruction, type TransactionSigner,
} from '@solana/kit';
import { getCreateAccountInstruction } from '@solana-program/system';

export const PROGRAM_ID = address('4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ');
export const SYSTEM_PROGRAM = address('11111111111111111111111111111111');
export const COMPUTE_BUDGET = address('ComputeBudget111111111111111111111111111111');
export const BIT_BYTES = 160;
export const proofLen = (n: number) => 2 + 2 * n * BIT_BYTES;

const sha256 = (...parts: (Uint8Array | string)[]) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const disc = (name: string) => sha256(`global:${name}`).slice(0, 8);

/* ---------------- borsh ---------------- */
const u8 = (n: number) => Uint8Array.of(n);
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n: bigint | number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const str = (s: string) => { const b = new TextEncoder().encode(s); return cat(u32(b.length), b); };
const vec = (b: Uint8Array) => cat(u32(b.length), b);
export function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/* ---------------- PDAs ---------------- */
const enc = getAddressEncoder();
export async function verificationPda(buffer: Address) {
  return (await getProgramDerivedAddress({ programAddress: PROGRAM_ID, seeds: [new TextEncoder().encode('verification'), enc.encode(buffer)] }))[0];
}
export async function recordPda(operationId: string) {
  return (await getProgramDerivedAddress({ programAddress: PROGRAM_ID, seeds: [new TextEncoder().encode('record'), sha256(operationId)] }))[0];
}

/* ---------------- instructions ---------------- */
export interface BeginArgs { operationId: string; policyId: string; asset: string; category: string; maxAmount: number; rangeBits: number; commitment: Uint8Array }

export async function createBufferIx(payer: TransactionSigner, rangeBits: number, lamports: bigint) {
  const buffer = await generateKeyPairSigner();
  const ix = getCreateAccountInstruction({ payer, newAccount: buffer, lamports, space: proofLen(rangeBits), programAddress: PROGRAM_ID });
  return { buffer, ix };
}

export async function beginIx(authority: TransactionSigner, buffer: Address, a: BeginArgs): Promise<Instruction> {
  const verification = await verificationPda(buffer);
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: authority.address, role: AccountRole.WRITABLE_SIGNER, signer: authority } as never,
      { address: buffer, role: AccountRole.READONLY },
      { address: verification, role: AccountRole.WRITABLE },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: cat(disc('begin'), str(a.operationId), str(a.policyId), str(a.asset), str(a.category), u64(a.maxAmount), u8(a.rangeBits), a.commitment),
  };
}

export async function writeIx(authority: TransactionSigner, buffer: Address, offset: number, bytes: Uint8Array): Promise<Instruction> {
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: authority.address, role: AccountRole.READONLY_SIGNER, signer: authority } as never,
      { address: await verificationPda(buffer), role: AccountRole.READONLY },
      { address: buffer, role: AccountRole.WRITABLE },
    ],
    data: cat(disc('write'), u32(offset), vec(bytes)),
  };
}

export async function verifyBitsIx(authority: TransactionSigner, buffer: Address, range: 0 | 1, count: number): Promise<Instruction> {
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: authority.address, role: AccountRole.READONLY_SIGNER, signer: authority } as never,
      { address: await verificationPda(buffer), role: AccountRole.WRITABLE },
      { address: buffer, role: AccountRole.READONLY },
    ],
    data: cat(disc('verify_bits'), u8(range), u8(count)),
  };
}

export async function finalizeIx(authority: TransactionSigner, buffer: Address, operationId: string): Promise<Instruction> {
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: authority.address, role: AccountRole.WRITABLE_SIGNER, signer: authority } as never,
      { address: await verificationPda(buffer), role: AccountRole.READONLY },
      { address: buffer, role: AccountRole.READONLY },
      { address: await recordPda(operationId), role: AccountRole.WRITABLE },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: disc('finalize'),
  };
}

/** SetComputeUnitLimit, for transactions sent without simulation (the deliberate-failure demonstrations). */
export function computeLimitIx(units: number): Instruction {
  return { programAddress: COMPUTE_BUDGET, accounts: [], data: cat(u8(2), u32(units)) };
}

/* ---------------- Record account decoding ---------------- */
export interface DecodedRecord {
  authority: string; verification: string; buffer: string; operationId: string; policyId: string; asset: string; category: string;
  maxAmount: bigint; rangeBits: number; commitment: Uint8Array; proofHash: Uint8Array; verifiedSlot: bigint;
}
export const RECORD_DISCRIMINATOR = sha256('account:Record').slice(0, 8);

export function decodeRecord(data: Uint8Array, toBase58: (b: Uint8Array) => string): DecodedRecord {
  if (!RECORD_DISCRIMINATOR.every((b, i) => data[i] === b)) throw new Error('not a Record account');
  let o = 8;
  const key = () => { const k = toBase58(data.slice(o, o + 32)); o += 32; return k; };
  const s = () => { const len = new DataView(data.buffer, data.byteOffset + o, 4).getUint32(0, true); o += 4; const v = new TextDecoder().decode(data.slice(o, o + len)); o += len; return v; };
  const authority = key(), verification = key(), buffer = key();
  const operationId = s(), policyId = s(), asset = s(), category = s();
  const maxAmount = new DataView(data.buffer, data.byteOffset + o, 8).getBigUint64(0, true); o += 8;
  const rangeBits = data[o]!; o += 1;
  const commitment = data.slice(o, o + 32); o += 32;
  const proofHash = data.slice(o, o + 32); o += 32;
  const verifiedSlot = new DataView(data.buffer, data.byteOffset + o, 8).getBigUint64(0, true);
  return { authority, verification, buffer, operationId, policyId, asset, category, maxAmount, rangeBits, commitment, proofHash, verifiedSlot };
}

/* ---------------- base58 ---------------- */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function toBase58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}
