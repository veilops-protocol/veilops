/**
 * Generates test-vectors/veilops-range-v1.json — the reference vectors for the VEILOPS proof system.
 *
 * Deterministic fields (generator H, commitments, challenges, transcript contexts, Ed25519 attestations) are
 * recomputed and checked by tests/vectors/vectors.test.ts. Proofs contain fresh randomness, so the file is
 * generated once and frozen; every implementation must reach the `expected` verdict for every case.
 *
 * Usage: npx tsx scripts/generate-test-vectors.ts   (overwrites the file; only do this for a new version)
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { ristretto255 } from '@noble/curves/ed25519.js';
import {
  provePolicy, verifyPolicy, proveRange, verifyRange, attest, verifyAttestation, signingKeyFromSeed, transcriptContext,
  commit, pointHex, G, H, encodeProof, proofIdOf, verifyRecord, type PolicyProof, type RangeProof,
} from '@veilops/proof-engine';
import { challenge, scalarHex, L, mod, randomScalar } from '../packages/proof-engine/src/pedersen';
import { bytesToHex, hexToBytes, sha256Hex, PROTOCOL_VERSION, type PublicRecord } from '@veilops/shared';

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const flipHex = (h: string, at = 0) => h.slice(0, at) + ((parseInt(h[at]!, 16) ^ 1).toString(16)) + h.slice(at + 1);

/* ---------- generator and base point ---------- */
const generators = {
  G: pointHex(G),
  H: pointHex(H),
  H_derivation: {
    method: 'RFC 9380 hash_to_ristretto255 (expand_message_xmd, SHA-512)',
    msg: 'VEILOPS/pedersen/H/v1',
    DST: 'VEILOPS-V01-CS01-with-ristretto255_XMD:SHA-512_R255MAP_RO_',
  },
};

/* ---------- commitments: C = v*G + r*H ---------- */
const commitCases: [bigint, bigint][] = [
  [0n, 1n], [1n, 0n], [1n, 1n], [42n, 7n], [250000000n, 123456789n], [2n ** 48n - 1n, L - 1n],
  [5000n, BigInt('0x' + sha256Hex('VEILOPS/vector/blinding/1'))],
];
const commitments = commitCases.map(([v, r]) => {
  const rr = mod(r);
  return { value: v.toString(), blinding: scalarHex(rr), commitment: pointHex(commit(v, rr)) };
});

/* ---------- Fiat–Shamir challenge ---------- */
const challengeCases: { domain: string; parts: ({ utf8: string } | { hex: string })[] }[] = [
  { domain: 'VEILOPS/range/bit-or/v1', parts: [{ utf8: 'ctx' }, { utf8: '0' }, { hex: pointHex(G) }, { hex: pointHex(H) }, { hex: pointHex(ristretto255.Point.ZERO) }] },
  { domain: 'VEILOPS/test', parts: [] },
  { domain: 'VEILOPS/test', parts: [{ utf8: '' }, { hex: '00ff' }] },
];
const challenges = challengeCases.map(c => ({
  ...c,
  expected: scalarHex(challenge(c.domain, ...c.parts.map(p => ('utf8' in p ? p.utf8 : hexToBytes(p.hex))))),
}));

/* ---------- single range proofs ---------- */
function rangeCase(v: bigint, n: number, ctx: string) {
  const r = randomScalar();
  const C = commit(v, r);
  return { C, proof: proveRange(v, r, n, ctx), ctx };
}
const rangeProofs: { description: string; n: number; context: string; commitment: string; proof: RangeProof; expected: boolean }[] = [];
for (const [v, n] of [[0n, 1], [1n, 1], [5n, 4], [255n, 8], [123456n, 24]] as [bigint, number][]) {
  const { C, proof, ctx } = rangeCase(v, n, `vector|range|${n}`);
  rangeProofs.push({ description: `valid: value in [0, 2^${n})`, n, context: ctx, commitment: pointHex(C), proof, expected: true });
}
{
  const { C, proof, ctx } = rangeCase(5n, 4, 'vector|range|neg');
  const base = { n: 4, context: ctx, commitment: pointHex(C) };
  rangeProofs.push({ description: 'valid baseline for the negative cases below', ...base, proof, expected: true });
  rangeProofs.push({ description: 'invalid: transcript context changed', ...base, context: ctx + 'x', proof, expected: false });
  rangeProofs.push({ description: 'invalid: proof checked against a different commitment', ...base, commitment: pointHex(commit(5n, 1n)), proof, expected: false });
  const p1 = clone(proof); p1.bits[1]!.s0 = flipHex(p1.bits[1]!.s0, 63);
  rangeProofs.push({ description: 'invalid: response scalar s0 of bit 1 modified', ...base, proof: p1, expected: false });
  const p2 = clone(proof); p2.bits[0]!.c1 = scalarHex(mod(BigInt('0x' + p2.bits[0]!.c1) + 1n));
  rangeProofs.push({ description: 'invalid: challenge share c1 of bit 0 modified', ...base, proof: p2, expected: false });
  const p3 = clone(proof); [p3.bits[0], p3.bits[1]] = [p3.bits[1]!, p3.bits[0]!];
  rangeProofs.push({ description: 'invalid: bit proofs reordered', ...base, proof: p3, expected: false });
  const p4 = clone(proof); p4.n = 3; p4.bits = p4.bits.slice(0, 3);
  rangeProofs.push({ description: 'invalid: truncated to 3 bits', ...base, proof: p4, expected: false });
  const p5 = clone(proof); p5.bits[2]!.s1 = (BigInt('0x' + p5.bits[2]!.s1) + L).toString(16).padStart(64, '0');
  rangeProofs.push({ description: 'invalid: non-canonical scalar (s1 + L) must be rejected', ...base, proof: p5, expected: false });
  const p6 = clone(proof); p6.bits[3]!.C = 'ff'.repeat(32);
  rangeProofs.push({ description: 'invalid: bit commitment is not a valid ristretto255 encoding', ...base, proof: p6, expected: false });
  const p7 = clone(proof); p7.n = 5;
  rangeProofs.push({ description: 'invalid: declared n does not match number of bit proofs', ...base, proof: p7, expected: false });
}
{
  // A value outside the range cannot be proven honestly; a proof for 2^4 = 16 with n=4 is built for n=5 and relabelled.
  const r = randomScalar();
  const C = commit(16n, r);
  const proof = proveRange(16n, r, 5, 'vector|range|overflow');
  const forged = clone(proof); forged.n = 4; forged.bits = forged.bits.slice(0, 4);
  rangeProofs.push({ description: 'invalid: value 16 does not fit in 4 bits (top bit dropped)', n: 4, context: 'vector|range|overflow', commitment: pointHex(C), proof: forged, expected: false });
}
for (const rp of rangeProofs) {
  let C; try { C = ristretto255.Point.fromHex(rp.commitment); } catch { C = null; }
  const got = !!C && verifyRange(C, rp.proof, rp.context);
  if (got !== rp.expected) throw new Error(`range vector disagrees: ${rp.description}`);
}

/* ---------- policy proofs (veilops-range-v1) ---------- */
const policyProofs: { description: string; publicInputs: ReturnType<typeof provePolicy>['publicInputs']; transcriptContext: string; proof: PolicyProof; proofId: string; expected: boolean }[] = [];
const base = { operationId: 'op_vector000000001', policyId: 'pol_vector00000001', asset: 'USDC', category: 'vendor' };
for (const [amount, max, bits] of [[0, 1000, 16], [1000, 1000, 16], [742500, 15000000, 32], [1, 1, 1]] as [number, number, number][]) {
  const out = provePolicy({ ...base, amount, maxAmount: max, rangeBits: bits });
  policyProofs.push({ description: `valid: 0 <= amount <= ${max} (${bits} bits; amount hidden)`, publicInputs: out.publicInputs, transcriptContext: transcriptContext(out.publicInputs), proof: out.proof, proofId: out.proofId, expected: true });
}
{
  const out = provePolicy({ ...base, amount: 500, maxAmount: 1000, rangeBits: 16 });
  const pi = out.publicInputs;
  const add = (description: string, p: typeof pi, proof: PolicyProof) =>
    policyProofs.push({ description, publicInputs: p, transcriptContext: transcriptContext(p), proof, proofId: proofIdOf(proof), expected: false });
  add('invalid: maxAmount lowered after proving (1000 -> 400)', { ...pi, maxAmount: 400 }, out.proof);
  add('invalid: operationId changed (binds the transcript)', { ...pi, operationId: 'op_vector000000002' }, out.proof);
  add('invalid: lower and upper proofs swapped', pi, { ...out.proof, lower: out.proof.upper, upper: out.proof.lower });
  add('invalid: commitment replaced', { ...pi, amountCommitment: pointHex(commit(500n, 1n)) }, out.proof);
  add('invalid: rangeBits 16 -> 17 without new proofs', { ...pi, rangeBits: 17 }, out.proof);
  add('invalid: unknown proof system label', pi, { ...out.proof, system: 'veilops-range-v0' as PolicyProof['system'] });
}
for (const pp of policyProofs) {
  if (verifyPolicy(pp.publicInputs, pp.proof).valid !== pp.expected) throw new Error(`policy vector disagrees: ${pp.description}`);
}

/* ---------- Ed25519 attestation of a public record ---------- */
const seed = hexToBytes(sha256Hex('VEILOPS/vector/operator-seed/v1'));
const key = signingKeyFromSeed(seed);
const valid = provePolicy({ ...base, operationId: 'op_vector000000009', amount: 742500, maxAmount: 15000000, rangeBits: 32 });
const unsigned: Omit<PublicRecord, 'attestation'> = {
  version: PROTOCOL_VERSION, operationId: 'op_vector000000009', proofId: valid.proofId, createdAt: '2026-11-20T00:00:00.000Z',
  category: 'vendor', asset: 'USDC', mode: 'amount-only', policy: { id: base.policyId, maxAmount: 15000000, rangeBits: 32 },
  amountCommitment: valid.publicInputs.amountCommitment, envelopeDigest: sha256Hex('VEILOPS/vector/envelope'),
  recipient: 'vendor-0001', proofSystem: 'veilops-range-v1', proof: encodeProof(valid.proof),
};
const record = attest(unsigned, key);
const tamperedAmount = { ...record, amountCommitment: pointHex(commit(1n, 1n)) };
const tamperedRecipient = { ...record, recipient: 'attacker' };
const reSigned = attest({ ...unsigned, policy: { ...unsigned.policy, maxAmount: 1000 } }, key);
const records = [
  { description: 'valid: proof, proof id and operator signature all check', record, expected: { valid: true, attestation: true, proofIdMatches: true } },
  { description: 'invalid: commitment swapped (proof and signature both fail)', record: tamperedAmount, expected: { valid: false, attestation: false, proofIdMatches: true } },
  { description: 'invalid: recipient edited after signing (signature fails, proof still valid)', record: tamperedRecipient, expected: { valid: false, attestation: false, proofIdMatches: true } },
  { description: 'invalid: operator re-signed a lower limit; signature is valid but the proof is not', record: reSigned, expected: { valid: false, attestation: true, proofIdMatches: true } },
];
for (const r of records) {
  const got = verifyRecord(r.record as PublicRecord);
  if (got.valid !== r.expected.valid || got.attestation !== r.expected.attestation || got.proofIdMatches !== r.expected.proofIdMatches) throw new Error(`record vector disagrees: ${r.description}`);
  if (verifyAttestation(r.record as PublicRecord) !== r.expected.attestation) throw new Error('attestation mismatch');
}

const out = {
  name: 'veilops-range-v1 reference test vectors',
  version: 1,
  protocol: PROTOCOL_VERSION,
  status: 'experimental, not externally audited',
  generatedBy: 'scripts/generate-test-vectors.ts (@veilops/proof-engine)',
  encoding: {
    points: 'ristretto255, 32-byte canonical encoding (RFC 9496), lowercase hex',
    scalars: '32-byte big-endian lowercase hex, must be < L (non-canonical values are rejected)',
    L: L.toString(),
    challenge: 'SHA-512( utf8(domain) || for each part: u32be(len) || part ) read as little-endian integer, reduced mod L',
    transcriptContext: 'canonical JSON (keys sorted recursively, no whitespace) of {v: "veilops-range-v1", ...publicInputs}; lower proof uses ctx + "|lower", upper proof uses ctx + "|upper" against D = maxAmount*G - C',
    bitProofChallenge: 'challenge("VEILOPS/range/bit-or/v1", ctx, utf8(decimal index), C_i, A_0, A_1) with A_b = s_b*H - c_b*(C_i - b*G); accept iff c_0 + c_1 = e (mod L) and sum(2^i * C_i) = C',
    attestation: 'Ed25519 (RFC 8032) over utf8("VEILOPS/record/v1|" + canonicalJson(record without attestation))',
    proofId: '"prf_" + first 20 hex chars of SHA-256(canonicalJson(proof))',
    recordProof: 'base64 of utf8 JSON of the policy proof',
  },
  generators,
  commitments,
  challenges,
  rangeProofs,
  policyProofs,
  attestation: { seedHex: bytesToHex(seed), publicKey: key.publicKey },
  records,
};
mkdirSync('test-vectors', { recursive: true });
writeFileSync('test-vectors/veilops-range-v1.json', JSON.stringify(out, null, 2) + '\n');
console.log(`wrote test-vectors/veilops-range-v1.json: ${commitments.length} commitments, ${challenges.length} challenges, ${rangeProofs.length} range proofs, ${policyProofs.length} policy proofs, ${records.length} records`);
