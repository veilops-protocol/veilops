import { describe, it, expect } from 'vitest';
import { commit, verifyOpening, randomScalar, pointHex, proveRange, verifyRange, provePolicy, verifyPolicy, G, H } from '@veilops/proof-engine';

const base = { operationId: 'op_test', policyId: 'pol_test', maxAmount: 1_000_000, rangeBits: 24, asset: 'USDC', category: 'payroll' };

describe('pedersen', () => {
  it('commitments open correctly and hide the value', () => {
    const r = randomScalar();
    const C = pointHex(commit(42n, r));
    expect(verifyOpening(C, 42n, r)).toBe(true);
    expect(verifyOpening(C, 43n, r)).toBe(false);
    expect(pointHex(commit(42n, randomScalar()))).not.toBe(C);
  });
  it('H is independent of G', () => {
    expect(H.equals(G)).toBe(false);
  });
});

describe('range proof', () => {
  it('accepts values in range, including 0 and 2^n − 1', () => {
    for (const v of [0n, 1n, 77n, 255n]) {
      const r = randomScalar();
      const p = proveRange(v, r, 8, 'ctx');
      expect(verifyRange(commit(v, r), p, 'ctx')).toBe(true);
    }
  });
  it('refuses to prove out-of-range values', () => {
    expect(() => proveRange(256n, randomScalar(), 8, 'ctx')).toThrow();
  });
  it('is bound to its commitment and context', () => {
    const r = randomScalar();
    const p = proveRange(9n, r, 8, 'ctx');
    expect(verifyRange(commit(10n, r), p, 'ctx')).toBe(false);
    expect(verifyRange(commit(9n, r), p, 'other')).toBe(false);
  });
});

describe('policy proof', () => {
  it('proves amount ≤ maxAmount and verifies', () => {
    const out = provePolicy({ ...base, amount: 250_000 });
    const rep = verifyPolicy(out.publicInputs, out.proof);
    expect(rep.valid).toBe(true);
    expect(JSON.stringify(out.proof)).not.toContain('250000');
  });
  it('works at the boundary', () => {
    const out = provePolicy({ ...base, amount: base.maxAmount });
    expect(verifyPolicy(out.publicInputs, out.proof).valid).toBe(true);
  });
  it('cannot be produced for an over-limit amount', () => {
    expect(() => provePolicy({ ...base, amount: base.maxAmount + 1 })).toThrow(/exceeds/);
  });
});
