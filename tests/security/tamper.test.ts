import { describe, it, expect } from 'vitest';
import { provePolicy, verifyPolicy, verifyRecord, encodeProof, decodeProof } from '@veilops/proof-engine';
import { createClient } from '@veilops/sdk';
import { definePolicy } from '@veilops/policy-engine';

const base = { operationId: 'op_sec', policyId: 'pol_sec', maxAmount: 5000, rangeBits: 16, asset: 'USDC', category: 'treasury' };

describe('tamper resistance', () => {
  const out = provePolicy({ ...base, amount: 1200 });
  it('a proof does not transfer to a lower limit (cannot claim a stricter policy)', () => {
    expect(verifyPolicy({ ...out.publicInputs, maxAmount: 1000 }, out.proof).valid).toBe(false);
  });
  it('a proof does not transfer to another operation', () => {
    expect(verifyPolicy({ ...out.publicInputs, operationId: 'op_other' }, out.proof).valid).toBe(false);
  });
  it('swapping a single bit commitment breaks verification', () => {
    const p = structuredClone(out.proof);
    const t = p.lower.bits[0]!.C; p.lower.bits[0]!.C = p.lower.bits[1]!.C; p.lower.bits[1]!.C = t;
    expect(verifyPolicy(out.publicInputs, p).valid).toBe(false);
  });
  it('malformed scalars and points are rejected without throwing', () => {
    const p = structuredClone(out.proof);
    p.upper.bits[3]!.s0 = 'zz';
    expect(verifyPolicy(out.publicInputs, p).valid).toBe(false);
    expect(verifyPolicy({ ...out.publicInputs, amountCommitment: '00'.repeat(31) + '01' }, out.proof).valid).toBe(false);
  });
  it('truncated proofs are rejected', () => {
    const p = structuredClone(out.proof);
    p.lower.bits.pop();
    expect(verifyPolicy(out.publicInputs, p).valid).toBe(false);
  });
});

describe('published records', () => {
  it('detect edits to any public field, the proof, or the signature', async () => {
    const veil = createClient();
    const { record } = await veil.process({ name: 'n', category: 'treasury', recipient: 'r', amount: 10, asset: 'USDC', policyLimit: 100, mode: 'full' }, definePolicy({ name: 'p', maxAmount: 100, rangeBits: 16 }));
    expect(verifyRecord(record).valid).toBe(true);
    expect(verifyRecord({ ...record, asset: 'SOL' }).valid).toBe(false);
    expect(verifyRecord({ ...record, createdAt: '2020-01-01T00:00:00.000Z' }).valid).toBe(false);
    const p = decodeProof(record.proof); p.lower.bits[0]!.c0 = p.lower.bits[0]!.c1;
    expect(verifyRecord({ ...record, proof: encodeProof(p) }).valid).toBe(false);
    expect(verifyRecord({ ...record, attestation: { ...record.attestation, signature: '00'.repeat(64) } }).valid).toBe(false);
  });
  it('reject a non-canonical (S + L) signature and malformed records instead of throwing', async () => {
    const veil = createClient();
    const { record } = await veil.process({ name: 'n', category: 'treasury', recipient: 'r', amount: 10, asset: 'USDC', policyLimit: 100, mode: 'full' }, definePolicy({ name: 'p', maxAmount: 100, rangeBits: 16 }));
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const sig = record.attestation.signature;
    const sLE = BigInt('0x' + (sig.slice(64).match(/../g) ?? []).reverse().join(''));
    const hi = (sLE + L).toString(16).padStart(64, '0');
    const malleable = sig.slice(0, 64) + (hi.match(/../g) ?? []).reverse().join('');
    expect(verifyRecord({ ...record, attestation: { ...record.attestation, signature: malleable } }).attestation).toBe(false);
    const broken = { ...record } as Partial<typeof record>;
    delete broken.policy;
    expect(() => verifyRecord(broken as typeof record)).not.toThrow();
    expect(verifyRecord(broken as typeof record).valid).toBe(false);
  });
});

