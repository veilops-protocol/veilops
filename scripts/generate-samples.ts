/**
 * Generates the SAMPLE explorer dataset used by the website (apps/website/data/samples.json).
 *
 * Every "verified" record carries a real veilops-range-v1 proof and a real Ed25519 attestation made by a
 * throwaway sample-operator key generated at run time (its secret is discarded). Two records are
 * deliberately corrupted so the explorer can show a failed verification, and three are pending (no proof
 * yet). All records are flagged `sample: true`. Plaintext amounts and recipients are never written.
 *
 *   npm run samples
 */
import { writeFileSync } from 'node:fs';
import { PROTOCOL_VERSION, randomId, sha256Hex, hexToBytes, type PublicRecord, type OperationCategory, type ConfidentialityMode } from '@veilops/shared';
import { definePolicy, policyId, type Policy } from '@veilops/policy-engine';
import { provePolicy, attest, encodeProof, decodeProof, verifyRecord, generateSigningKey, signingKeyFromSeed, PROOF_SYSTEM } from '@veilops/proof-engine';

/** Indexer entry: the signed record plus indexer-side annotations (not part of the signed payload). */
type Stored = { record: PublicRecord; status: 'verified' | 'failed' | 'pending'; note?: string };

// Optional fixed operator key (32-byte hex seed) so regenerated samples keep the same public key.
const seedHex = process.env.VEILOPS_SIGNING_SEED_HEX?.trim();
const operator = seedHex ? signingKeyFromSeed(hexToBytes(seedHex)) : generateSigningKey();
const P = {
  treasury: definePolicy({ name: 'Treasury rebalancing', maxAmount: 2_500_000_00, rangeBits: 40, allowedCategories: ['treasury', 'operations'] }),
  payroll: definePolicy({ name: 'Contributor payroll', maxAmount: 25_000_00, rangeBits: 24, allowedCategories: ['payroll'], minimumMode: 'amount-and-recipient' }),
  vendor: definePolicy({ name: 'Vendor payments', maxAmount: 150_000_00, rangeBits: 32, allowedCategories: ['vendor', 'operations'] }),
  grant: definePolicy({ name: 'Ecosystem grants', maxAmount: 500_000_00, rangeBits: 32, allowedCategories: ['grant'] }),
} satisfies Record<string, Policy>;

const rand = (min: number, max: number) => Math.floor(min + Math.random() * (max - min));
const plan: [Policy, OperationCategory, string, ConfidentialityMode][] = [
  [P.treasury, 'treasury', 'USDC', 'full'], [P.payroll, 'payroll', 'USDC', 'amount-and-recipient'], [P.vendor, 'vendor', 'USDC', 'amount-only'],
  [P.payroll, 'payroll', 'PYUSD', 'full'], [P.grant, 'grant', 'USDC', 'amount-and-recipient'], [P.treasury, 'operations', 'SOL', 'full'],
  [P.vendor, 'operations', 'USDT', 'amount-and-recipient'], [P.payroll, 'payroll', 'USDC', 'full'], [P.grant, 'grant', 'SOL', 'amount-only'],
  [P.vendor, 'vendor', 'USDC', 'full'], [P.treasury, 'treasury', 'USDC', 'amount-and-recipient'], [P.payroll, 'payroll', 'USDC', 'amount-and-recipient'],
  [P.vendor, 'vendor', 'PYUSD', 'amount-only'], [P.grant, 'grant', 'USDC', 'full'], [P.treasury, 'treasury', 'USDT', 'full'], [P.payroll, 'payroll', 'USDC', 'full'],
];

const t0 = Date.parse('2026-11-02T09:00:00Z');
const at = (i: number) => new Date(t0 + i * 5.1 * 3600_000 + rand(0, 3000_000)).toISOString();
const out: Stored[] = [];

plan.forEach(([pol, category, asset, mode], i) => {
  const operationId = randomId('op');
  const prover = provePolicy({ operationId, policyId: policyId(pol), maxAmount: pol.maxAmount, rangeBits: pol.rangeBits, asset, category, amount: rand(Math.floor(pol.maxAmount * 0.03), pol.maxAmount) });
  const rec = attest({
    version: PROTOCOL_VERSION, operationId, proofId: prover.proofId, createdAt: at(i), category, asset, mode,
    policy: { id: policyId(pol), maxAmount: pol.maxAmount, rangeBits: pol.rangeBits },
    amountCommitment: prover.publicInputs.amountCommitment,
    envelopeDigest: sha256Hex(`sample-envelope-${operationId}`),
    ...(mode === 'amount-only' ? { recipient: `sample-recipient-${rand(100, 999)}.sol` } : {}),
    proofSystem: PROOF_SYSTEM, proof: encodeProof(prover.proof), sample: true,
  }, operator);
  out.push({ record: rec, status: 'verified' });
});

// Failure case 1: the published policy limit was edited after signing (claims a stricter limit).
{
  const base = out[3]!.record;
  out.push({ record: { ...base, operationId: randomId('op'), createdAt: at(plan.length), policy: { ...base.policy, maxAmount: Math.floor(base.policy.maxAmount / 4) } },
    status: 'failed', note: 'Sample of a tampered record: copied from another operation, then its id, timestamp and policy limit were edited after signing.' });
}
// Failure case 2: a proof component was altered.
{
  const base = out[9]!.record;
  const proof = decodeProof(base.proof);
  proof.upper.bits[5]!.s1 = proof.upper.bits[6]!.s1;
  out.push({ record: { ...base, operationId: randomId('op'), createdAt: at(plan.length + 1), proof: encodeProof(proof) },
    status: 'failed', note: 'Sample of a corrupted record: copied from another operation with a new id, and one OR-proof response replaced.' });
}
// Pending: submitted, no proof attached yet.
for (let k = 0; k < 3; k++) {
  const [pol, category, asset, mode] = plan[k * 4 + 1]!;
  out.push({ record: {
    version: PROTOCOL_VERSION, operationId: randomId('op'), proofId: '', createdAt: at(plan.length + 2 + k), category, asset, mode,
    policy: { id: policyId(pol), maxAmount: pol.maxAmount, rangeBits: pol.rangeBits }, amountCommitment: '', envelopeDigest: sha256Hex(`pending-${k}`),
    proofSystem: PROOF_SYSTEM, proof: '', attestation: { publicKey: operator.publicKey, signature: '' }, sample: true,
  }, status: 'pending', note: 'Submitted to the sample indexer; no proof attached yet.' });
}

// Sanity: stored status must match independent verification.
for (const r of out) {
  if (r.status === 'pending') continue;
  const ok = verifyRecord(r.record).valid;
  if (ok !== (r.status === 'verified')) throw new Error(`status mismatch for ${r.record.operationId}`);
}
out.sort((a, b) => b.record.createdAt.localeCompare(a.record.createdAt));
const policies = Object.values(P).map(p => ({ id: policyId(p), name: p.name, maxAmount: p.maxAmount, rangeBits: p.rangeBits, allowedCategories: p.allowedCategories, minimumMode: p.minimumMode }));
writeFileSync('apps/website/data/samples.json', JSON.stringify({ generatedAt: new Date().toISOString(), operator: operator.publicKey, policies, records: out }));
console.log(`wrote ${out.length} sample records`);
