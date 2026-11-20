import { describe, it, expect } from 'vitest';
import { createClient, PolicyViolation, encryption, proofs } from '@veilops/sdk';
import { definePolicy } from '@veilops/policy-engine';
import { anchorMemo, parseAnchorMemo } from '@veilops/solana-adapter';

describe('end-to-end operation lifecycle', () => {
  const auditor = encryption.generateViewingKeyPair();
  const veil = createClient({ viewers: [auditor.publicKey] });
  const pol = definePolicy({ name: 'contributors', maxAmount: 2_000_000, rangeBits: 32 });

  it('runs all five stages and produces a publishable record without plaintext', async () => {
    const stages: string[] = [];
    const res = await veil.process(
      { name: 'Sept contributor payout', category: 'payroll', recipient: 'alice.sol', amount: 812_345, asset: 'USDC', policyLimit: 1_500_000, mode: 'amount-and-recipient' },
      pol, { onStage: e => { stages.push(e.stage); } });
    expect(stages).toEqual(['created', 'encrypted', 'policy', 'proof', 'verified']);
    expect(res.verification.valid).toBe(true);
    const pub = JSON.stringify(res.record);
    expect(pub).not.toContain('alice.sol');
    expect(pub).not.toContain('812345');
    expect(res.record.policy.maxAmount).toBe(1_500_000);

    // selective disclosure: the auditor can read the envelope and check the commitment opening
    const plain = JSON.parse(await encryption.openText(res.envelope, auditor.secretKey));
    expect(plain.amount).toBe(812_345);
    expect(proofs.verifyOpening(res.record.amountCommitment, BigInt(res.opening.value), proofs.scalarFromHex(res.opening.blinding))).toBe(true);
  });

  it('refuses to produce a proof for a policy violation', async () => {
    await expect(veil.process({ name: 'x', category: 'payroll', recipient: 'b', amount: 3_000_000, asset: 'USDC', policyLimit: 3_000_000, mode: 'full' }, pol)).rejects.toBeInstanceOf(PolicyViolation);
  });

  it('anchor memo round-trips', async () => {
    const { record } = await veil.process({ name: 'x', category: 'treasury', recipient: 'b', amount: 5, asset: 'SOL', policyLimit: 10, mode: 'amount-only' }, pol);
    expect(record.recipient).toBe('b'); // amount-only mode keeps the recipient public, by design
    expect(parseAnchorMemo(anchorMemo(record))?.proofId).toBe(record.proofId);
  });
});
