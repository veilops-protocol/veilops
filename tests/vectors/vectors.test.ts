/**
 * Reference test vectors (test-vectors/veilops-range-v1.json).
 * Deterministic values are recomputed; every proof case must reach its `expected` verdict.
 * The same file is verified by the independent Python implementation in verifiers/python/.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ristretto255 } from '@noble/curves/ed25519.js';
import {
  commit, pointHex, G, H, verifyRange, verifyPolicy, verifyRecord, transcriptContext, proofIdOf, signingKeyFromSeed,
  type RangeProof, type PolicyProof, type PublicInputs,
} from '@veilops/proof-engine';
import { challenge, scalarHex, scalarFromHex } from '../../packages/proof-engine/src/pedersen';
import { hexToBytes, type PublicRecord } from '@veilops/shared';

const V = JSON.parse(readFileSync(new URL('../../test-vectors/veilops-range-v1.json', import.meta.url), 'utf8'));

describe('reference vectors: generators and commitments', () => {
  it('G and H', () => {
    expect(pointHex(G)).toBe(V.generators.G);
    expect(pointHex(H)).toBe(V.generators.H);
  });
  it.each(V.commitments as { value: string; blinding: string; commitment: string }[])('commit(v=$value)', c => {
    expect(pointHex(commit(BigInt(c.value), scalarFromHex(c.blinding)))).toBe(c.commitment);
  });
  it.each(V.challenges as { domain: string; parts: ({ utf8: string } | { hex: string })[]; expected: string }[])('challenge($domain)', c => {
    expect(scalarHex(challenge(c.domain, ...c.parts.map(p => ('utf8' in p ? p.utf8 : hexToBytes(p.hex)))))).toBe(c.expected);
  });
});

describe('reference vectors: range proofs', () => {
  it.each(V.rangeProofs as { description: string; context: string; commitment: string; proof: RangeProof; expected: boolean }[])('$description', c => {
    let C; try { C = ristretto255.Point.fromHex(c.commitment); } catch { C = null; }
    expect(!!C && verifyRange(C, c.proof, c.context)).toBe(c.expected);
  });
});

describe('reference vectors: policy proofs', () => {
  it.each(V.policyProofs as { description: string; publicInputs: PublicInputs; transcriptContext: string; proof: PolicyProof; proofId: string; expected: boolean }[])('$description', c => {
    expect(transcriptContext(c.publicInputs)).toBe(c.transcriptContext);
    expect(proofIdOf(c.proof)).toBe(c.proofId);
    expect(verifyPolicy(c.publicInputs, c.proof).valid).toBe(c.expected);
  });
});

describe('reference vectors: records and attestation', () => {
  it('operator key derives from the published seed', () => {
    expect(signingKeyFromSeed(hexToBytes(V.attestation.seedHex)).publicKey).toBe(V.attestation.publicKey);
  });
  it.each(V.records as { description: string; record: PublicRecord; expected: { valid: boolean; attestation: boolean; proofIdMatches: boolean } }[])('$description', c => {
    const r = verifyRecord(c.record);
    expect({ valid: r.valid, attestation: r.attestation, proofIdMatches: r.proofIdMatches }).toEqual(c.expected);
  });
});
