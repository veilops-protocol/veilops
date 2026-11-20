/**
 * @veilops/policy-engine — declarative policies for confidential operations.
 *
 * A policy has two kinds of rules:
 *  - public rules (category, asset, mode) that anyone can check against the public record;
 *  - confidential rules (amount ≤ maxAmount) that are checked by the operator on plaintext AND
 *    enforced publicly by the range proof from @veilops/proof-engine, without revealing the amount.
 *
 * Status: implemented (unit-tested).
 */
import type { ConfidentialityMode, OperationCategory, OperationInput } from '@veilops/shared';
import { contentId } from '@veilops/shared';

export interface Policy {
  name: string;
  maxAmount: number;
  allowedCategories: OperationCategory[];
  allowedAssets: string[];
  /** Minimum confidentiality required for operations under this policy. */
  minimumMode: ConfidentialityMode;
  /** Number of bits the range proof covers; amounts must be < 2^rangeBits. */
  rangeBits: number;
}

export interface PolicyCheck { rule: string; passed: boolean; visibility: 'public' | 'confidential'; detail: string }
export interface PolicyResult { policyId: string; passed: boolean; checks: PolicyCheck[] }

const MODE_RANK: Record<ConfidentialityMode, number> = { 'amount-only': 0, 'amount-and-recipient': 1, full: 2 };
export const MAX_RANGE_BITS = 48;

export function policyId(policy: Policy): string {
  return contentId('pol', policy, 8);
}

export function definePolicy(p: Partial<Policy> & Pick<Policy, 'name' | 'maxAmount'>): Policy {
  const policy: Policy = {
    allowedCategories: ['treasury', 'payroll', 'vendor', 'grant', 'operations'],
    allowedAssets: ['USDC', 'SOL', 'USDT', 'PYUSD'],
    minimumMode: 'amount-only',
    rangeBits: 32,
    ...p,
  };
  validatePolicy(policy);
  return policy;
}

export function validatePolicy(p: Policy): void {
  if (!Number.isSafeInteger(p.maxAmount) || p.maxAmount < 0) throw new Error('policy.maxAmount must be a non-negative safe integer');
  if (!Number.isInteger(p.rangeBits) || p.rangeBits < 1 || p.rangeBits > MAX_RANGE_BITS) throw new Error(`policy.rangeBits must be 1..${MAX_RANGE_BITS}`);
  if (p.maxAmount >= 2 ** p.rangeBits) throw new Error('policy.maxAmount must be below 2^rangeBits');
  if (p.allowedCategories.length === 0 || p.allowedAssets.length === 0) throw new Error('policy must allow at least one category and asset');
}

/** Evaluate every rule on the operator side (plaintext available). */
export function evaluate(policy: Policy, op: OperationInput): PolicyResult {
  const checks: PolicyCheck[] = [
    { rule: 'category.allowed', visibility: 'public', passed: policy.allowedCategories.includes(op.category), detail: `category "${op.category}"` },
    { rule: 'asset.allowed', visibility: 'public', passed: policy.allowedAssets.includes(op.asset), detail: `asset ${op.asset}` },
    { rule: 'mode.minimum', visibility: 'public', passed: MODE_RANK[op.mode] >= MODE_RANK[policy.minimumMode], detail: `mode ${op.mode} ≥ ${policy.minimumMode}` },
    { rule: 'amount.integer', visibility: 'confidential', passed: Number.isSafeInteger(op.amount) && op.amount >= 0, detail: 'amount is a non-negative integer' },
    { rule: 'amount.withinLimit', visibility: 'confidential', passed: op.amount <= policy.maxAmount, detail: `amount ≤ ${policy.maxAmount} (proven in zero knowledge)` },
  ];
  return { policyId: policyId(policy), passed: checks.every(c => c.passed), checks };
}

/** Public-side check: only rules that can be evaluated from a public record. */
export function evaluatePublic(policy: Policy, rec: { category: OperationCategory; asset: string; mode: ConfidentialityMode }): PolicyCheck[] {
  return evaluate(policy, { ...rec, name: '', recipient: '', amount: 0, policyLimit: policy.maxAmount }).checks.filter(c => c.visibility === 'public');
}
