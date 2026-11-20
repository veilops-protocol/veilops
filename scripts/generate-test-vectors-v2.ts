/**
 * Generates test-vectors/veilops-range-v2.json — reference vectors for the on-chain proof encoding.
 * Deterministic parts (contexts, context hashes, bit challenges) are recomputed by tests/vectors/vectors-v2.test.ts;
 * proofs are generated once and frozen, each with its expected verdict.
 *
 *   npx tsx scripts/generate-test-vectors-v2.ts
 */
import { writeFileSync } from 'node:fs';
import {
  provePolicyV2, verifyPolicyV2, transcriptContextV2, ctxHashV2, bitChallengeV2, proofIdV2, pointHex, G, H, commit, V2_BIT_BYTES,
  type PublicInputsV2,
} from '@veilops/proof-engine';
import { bytesToHex } from '@veilops/shared';

const base = { operationId: 'op_v2vector000001', policyId: 'pol_v2vector00001', asset: 'USDC', category: 'vendor' };

/* deterministic: context, hashes, one challenge */
const piFixed: PublicInputsV2 = { ...base, maxAmount: 15000000, rangeBits: 32, amountCommitment: pointHex(commit(742500n, 7n)) };
const contexts = [{
  publicInputs: piFixed,
  transcriptContext: transcriptContextV2(piFixed),
  ctxHashLower: bytesToHex(ctxHashV2(piFixed, 'lower')),
  ctxHashUpper: bytesToHex(ctxHashV2(piFixed, 'upper')),
  challenge: { index: 3, Ci: pointHex(G), A0: pointHex(H), A1: pointHex(commit(1n, 1n)),
    expectedLE: (() => { const e = bitChallengeV2(ctxHashV2(piFixed, 'lower'), 3, G, H, commit(1n, 1n)); return bytesToHex(Uint8Array.from({ length: 32 }, (_, i) => Number((e >> BigInt(8 * i)) & 0xffn))); })() },
}];

const cases: { description: string; publicInputs: PublicInputsV2; proofHex: string; proofId: string; expected: boolean }[] = [];
const add = (description: string, publicInputs: PublicInputsV2, proof: Uint8Array, expected: boolean) => {
  if (verifyPolicyV2(publicInputs, proof) !== expected) throw new Error(`vector disagrees: ${description}`);
  cases.push({ description, publicInputs, proofHex: bytesToHex(proof), proofId: proofIdV2(proof), expected });
};
for (const [amount, max, bits] of [[0, 1000, 16], [1000, 1000, 16], [742500, 15000000, 32], [1, 1, 1], [180000000, 250000000, 40]] as const) {
  const out = provePolicyV2({ ...base, amount, maxAmount: max, rangeBits: bits });
  add(`valid: 0 <= amount <= ${max} (${bits} bits)`, out.publicInputs, out.proofBytes, true);
}
{
  const out = provePolicyV2({ ...base, amount: 500, maxAmount: 1000, rangeBits: 16 });
  const pi = out.publicInputs, p = out.proofBytes;
  const mut = (f: (b: Uint8Array) => void) => { const b = p.slice(); f(b); return b; };
  add('invalid: maxAmount lowered after proving (1000 -> 400)', { ...pi, maxAmount: 400 }, p, false);
  add('invalid: operationId changed', { ...pi, operationId: 'op_v2vector000002' }, p, false);
  add('invalid: asset changed', { ...pi, asset: 'SOL' }, p, false);
  add('invalid: one bit flipped in s0 of lower bit 0', pi, mut(b => { b[2 + 96] = b[2 + 96]! ^ 1; }), false);
  add('invalid: c1 of upper bit 5 changed', pi, mut(b => { const o = 2 + (16 + 5) * V2_BIT_BYTES + 64; b[o] = b[o]! ^ 1; }), false);
  add('invalid: lower and upper halves swapped', pi, mut(b => { const half = 16 * V2_BIT_BYTES; b.set(p.slice(2 + half), 2); b.set(p.slice(2, 2 + half), 2 + half); }), false);
  add('invalid: non-canonical scalar (s1 of lower bit 2 set to L)', pi, mut(b => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n; const o = 2 + 2 * V2_BIT_BYTES + 128;
    for (let i = 0; i < 32; i++) b[o + i] = Number((L >> BigInt(8 * i)) & 0xffn);
  }), false);
  add('invalid: bit commitment of lower bit 1 is not a valid point', pi, mut(b => { b.fill(0xff, 2 + V2_BIT_BYTES, 2 + V2_BIT_BYTES + 32); }), false);
  add('invalid: wrong version byte', pi, mut(b => { b[0] = 1; }), false);
  add('invalid: truncated by one byte', pi, p.slice(0, -1), false);
  add('invalid: text field outside [A-Za-z0-9_.-]', { ...pi, category: 'ven dor' }, p, false);
}

writeFileSync('test-vectors/veilops-range-v2.json', JSON.stringify({
  name: 'veilops-range-v2 reference test vectors', version: 1, status: 'experimental, not externally audited',
  generatedBy: 'scripts/generate-test-vectors-v2.ts (@veilops/proof-engine)',
  encoding: {
    generators: 'unchanged from v1 (see veilops-range-v1.json)',
    transcriptContext: 'canonical JSON of {v: "veilops-range-v2", ...publicInputs}; text fields must match [A-Za-z0-9_.-]{1,64}',
    ctxHash: 'SHA-256( utf8("VEILOPS/range/v2|") || ctx || utf8("|lower" or "|upper") )',
    bitChallenge: 'T = utf8("VEILOPS/range/v2/bit") || ctxHash || u32be(index) || C_i || A_0 || A_1; e = LE( SHA-256(0x00||T) || SHA-256(0x01||T) ) mod L',
    bitCheck: 'A_0 = s0*H - c0*C_i, A_1 = s1*H - c1*(C_i - G); accept iff c0 + c1 = e (mod L); then sum(2^i * C_i) = C (lower) and = maxAmount*G - C (upper)',
    proof: 'u8 version (2) || u8 n || n lower bits || n upper bits; bit = C_i(32) || c0 || c1 || s0 || s1 (32-byte little-endian scalars, must be < L)',
    proofId: '"prf_" + first 20 hex chars of SHA-256(proof bytes)',
  },
  contexts, cases,
}, null, 2) + '\n');
console.log(`wrote test-vectors/veilops-range-v2.json: ${cases.length} cases`);
