/**
 * Selective disclosure: an operation is sealed for its owner and one auditor; later the owner grants
 * a second reader access without re-encrypting, and the amount is disclosed by opening the commitment.
 *
 * Run from the repository root:
 *   npx tsx examples/selective-disclosure.ts
 */
import { createClient } from '@veilops/sdk';
import { definePolicy } from '@veilops/policy-engine';
import { generateViewingKeyPair, openText, grantAccess, envelopeDigest } from '@veilops/encryption';
import { verifyOpening, scalarFromHex, verifyRecord } from '@veilops/proof-engine';

async function main(): Promise<void> {
  const auditor = generateViewingKeyPair();
  const veil = createClient({ viewers: [auditor.publicKey] });
  const policy = definePolicy({ name: 'vendor-payments', maxAmount: 5_000_000, allowedCategories: ['vendor'], rangeBits: 32 });

  const { record, envelope, opening } = await veil.process(
    { name: 'Q4 security review', category: 'vendor', recipient: 'vendor-17', amount: 1_250_000, asset: 'USDC', policyLimit: 5_000_000, mode: 'amount-and-recipient', memo: 'invoice 2026-114' },
    policy,
  );
  console.log(`Record ${record.operationId} verified: ${verifyRecord(record).valid}`);
  console.log(`Envelope sealed for ${envelope.keys.length} keys (owner + auditor)`);

  // 1. The auditor, an authorized viewer, decrypts the envelope.
  const forAuditor = JSON.parse(await openText(envelope, auditor.secretKey)) as { amount: number; recipient: string; memo: string | null };
  console.log(`Auditor reads: amount=${forAuditor.amount} recipient=${forAuditor.recipient} memo=${forAuditor.memo}`);

  // 2. A stranger cannot.
  const stranger = generateViewingKeyPair();
  try {
    await openText(envelope, stranger.secretKey);
    console.log('Stranger read the envelope (unexpected)');
  } catch (err) {
    console.log(`Stranger refused: ${(err as Error).message}`);
  }

  // 3. The owner grants a late reader access. Ciphertext and published digest are unchanged.
  const finance = generateViewingKeyPair();
  const widened = await grantAccess(envelope, veil.owner.secretKey, finance.publicKey);
  console.log(`grantAccess: keys ${envelope.keys.length} -> ${widened.keys.length}, digest unchanged: ${envelopeDigest(widened) === record.envelopeDigest}`);
  console.log(`Finance reads amount=${(JSON.parse(await openText(widened, finance.secretKey)) as { amount: number }).amount}`);

  // 4. Disclosing the amount against the public record: share the commitment opening (v, r).
  //    Anyone holding it can check it against record.amountCommitment, without any decryption key.
  const ok = verifyOpening(record.amountCommitment, BigInt(opening.value), scalarFromHex(opening.blinding));
  const wrong = verifyOpening(record.amountCommitment, BigInt(opening.value) + 1n, scalarFromHex(opening.blinding));
  console.log(`Opening (value=${opening.value}) matches public commitment: ${ok}; value+1 matches: ${wrong}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
