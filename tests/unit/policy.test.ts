import { describe, it, expect } from 'vitest';
import { definePolicy, evaluate, policyId, evaluatePublic } from '@veilops/policy-engine';
import type { OperationInput } from '@veilops/shared';

const op: OperationInput = { name: 'Q3 audit', category: 'vendor', recipient: 'vendor-17', amount: 4_500_00, asset: 'USDC', policyLimit: 10_000_00, mode: 'amount-and-recipient' };

describe('policy-engine', () => {
  const pol = definePolicy({ name: 'vendors', maxAmount: 10_000_00 });
  it('passes a compliant operation', () => {
    expect(evaluate(pol, op).passed).toBe(true);
  });
  it('fails over-limit, wrong asset and weak mode', () => {
    expect(evaluate(pol, { ...op, amount: 10_000_01 }).checks.find(c => c.rule === 'amount.withinLimit')!.passed).toBe(false);
    expect(evaluate(pol, { ...op, asset: 'DOGE' }).passed).toBe(false);
    const strict = definePolicy({ name: 'payroll', maxAmount: 100, minimumMode: 'full' });
    expect(evaluate(strict, { ...op, amount: 1 }).checks.find(c => c.rule === 'mode.minimum')!.passed).toBe(false);
  });
  it('rejects invalid policies', () => {
    expect(() => definePolicy({ name: 'x', maxAmount: 2 ** 32, rangeBits: 32 })).toThrow();
    expect(() => definePolicy({ name: 'x', maxAmount: -1 })).toThrow();
  });
  it('policy id is stable', () => {
    expect(policyId(pol)).toBe(policyId(definePolicy({ name: 'vendors', maxAmount: 10_000_00 })));
  });
  it('public evaluation never touches confidential rules', () => {
    expect(evaluatePublic(pol, op).every(c => c.visibility === 'public')).toBe(true);
  });
});
