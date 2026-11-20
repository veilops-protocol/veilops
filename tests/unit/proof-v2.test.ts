import { describe, expect, it } from 'vitest';
import { provePolicyV2, verifyPolicyV2, decodeProofV2, encodeProofV2, proofIdV2, V2_BIT_BYTES } from '@veilops/proof-engine';

const base = { operationId: 'op_v2test0000000001', policyId: 'pol_v2test00000001', asset: 'USDC', category: 'vendor' };

describe('veilops-range-v2', () => {
  it('proves and verifies 0 <= amount <= max, with a compact binary encoding', () => {
    for (const [amount, max, bits] of [[0, 1000, 16], [1000, 1000, 16], [742500, 15000000, 32], [1, 1, 1]] as const) {
      const out = provePolicyV2({ ...base, amount, maxAmount: max, rangeBits: bits });
      expect(out.proofBytes.length).toBe(2 + 2 * bits * V2_BIT_BYTES);
      expect(verifyPolicyV2(out.publicInputs, out.proofBytes)).toBe(true);
      expect(encodeProofV2(decodeProofV2(out.proofBytes))).toEqual(out.proofBytes);
      expect(out.proofId).toBe(proofIdV2(out.proofBytes));
    }
  });
  it('refuses to prove an amount over the limit', () => {
    expect(() => provePolicyV2({ ...base, amount: 1001, maxAmount: 1000, rangeBits: 16 })).toThrow();
  });
  it('rejects tampering with the statement or the proof', () => {
    const out = provePolicyV2({ ...base, amount: 500, maxAmount: 1000, rangeBits: 16 });
    const pi = out.publicInputs;
    expect(verifyPolicyV2({ ...pi, maxAmount: 400 }, out.proofBytes)).toBe(false);
    expect(verifyPolicyV2({ ...pi, operationId: 'op_other' }, out.proofBytes)).toBe(false);
    expect(verifyPolicyV2({ ...pi, asset: 'SOL' }, out.proofBytes)).toBe(false);
    const flipped = out.proofBytes.slice(); flipped[2 + 100]! ^= 1; // s0 of lower bit 0
    expect(verifyPolicyV2(pi, flipped)).toBe(false);
    const swapped = out.proofBytes.slice(); const half = 16 * V2_BIT_BYTES;
    swapped.set(out.proofBytes.slice(2 + half), 2); swapped.set(out.proofBytes.slice(2, 2 + half), 2 + half);
    expect(verifyPolicyV2(pi, swapped)).toBe(false);
    expect(verifyPolicyV2(pi, out.proofBytes.slice(0, -1))).toBe(false);
    expect(verifyPolicyV2({ ...pi, asset: 'US"DC' }, out.proofBytes)).toBe(false);
  });
});
