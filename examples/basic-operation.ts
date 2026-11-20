/**
 * Basic VEILOPS operation: define a policy, process a confidential payout, and verify the
 * public record the way an independent third party would.
 *
 * Run from the repository root:
 *   npx tsx examples/basic-operation.ts
 *
 * Everything runs locally. Nothing is sent to a network and no key is persisted.
 */
import { createClient, PolicyViolation, type StageEvent } from '@veilops/sdk';
import { definePolicy } from '@veilops/policy-engine';
import { verifyRecord } from '@veilops/proof-engine';

async function main(): Promise<void> {
  // 1. A policy. maxAmount is in the asset's smallest display unit (here: USDC cents).
  const policy = definePolicy({
    name: 'contributor-payouts',
    maxAmount: 2_000_000, // 20,000.00 USDC
    allowedCategories: ['payroll', 'grant'],
    allowedAssets: ['USDC'],
    minimumMode: 'amount-and-recipient',
    rangeBits: 32,
  });

  // 2. A client. Without options it generates a fresh Ed25519 signing key and X25519 owner key.
  const veil = createClient();

  // 3. Process an operation. onStage fires for: created → encrypted → policy → proof → verified.
  const result = await veil.process(
    {
      name: 'October contributor payout',
      category: 'payroll',
      recipient: 'contributor-042',
      amount: 812_345, // 8,123.45 USDC — never appears in the public record
      asset: 'USDC',
      policyLimit: 1_500_000,
      mode: 'amount-and-recipient',
    },
    policy,
    { onStage: (e: StageEvent) => console.log(`[${e.stage.padEnd(9)}] ${e.ok ? 'ok  ' : 'FAIL'} ${e.detail}`) },
  );

  // 4. The public record: safe to publish. It holds a commitment, not the amount.
  const { record } = result;
  const published = JSON.stringify(record);
  console.log('\nPublic record');
  console.log('  operationId     ', record.operationId);
  console.log('  proofId         ', record.proofId);
  console.log('  proofSystem     ', record.proofSystem);
  console.log('  policy          ', JSON.stringify(record.policy));
  console.log('  amountCommitment', record.amountCommitment);
  console.log('  envelopeDigest  ', record.envelopeDigest);
  console.log('  recipient       ', record.recipient ?? '(hidden under this mode)');
  console.log('  record size     ', `${published.length} bytes (proof ${record.proof.length} bytes base64)`);
  console.log('  contains amount?', published.includes('812345'));
  console.log('  contains recipient?', published.includes('contributor-042'));

  // 5. Independent verification: needs only the record itself.
  const check = verifyRecord(record);
  console.log(`\nIndependent verification: ${check.valid ? 'VALID' : 'INVALID'} (${check.verifyMs} ms)`);
  for (const c of check.checks) console.log(`  ${c.passed ? 'pass' : 'FAIL'}  ${c.name.padEnd(11)} ${c.detail}`);

  // 6. Tampering with any public field invalidates the record.
  const tampered = verifyRecord({ ...record, asset: 'SOL' });
  console.log(`\nAfter changing asset to SOL: ${tampered.valid ? 'VALID' : 'INVALID'}`);

  // 7. An over-limit operation is refused before any proof is produced.
  try {
    await veil.process(
      { name: 'too large', category: 'payroll', recipient: 'x', amount: 1_600_000, asset: 'USDC', policyLimit: 1_500_000, mode: 'full' },
      policy,
    );
  } catch (err) {
    if (err instanceof PolicyViolation) console.log(`Over-limit operation refused: ${err.message}`);
    else throw err;
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
