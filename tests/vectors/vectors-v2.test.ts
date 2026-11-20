/**
 * Reference vectors for veilops-range-v2 (test-vectors/veilops-range-v2.json), the encoding verified on-chain.
 * Also checked by the independent Python verifier in verifiers/python/.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { verifyPolicyV2, transcriptContextV2, ctxHashV2, bitChallengeV2, proofIdV2, scalarToLE, type PublicInputsV2 } from '@veilops/proof-engine';
import { bytesToHex, hexToBytes } from '@veilops/shared';

const V = JSON.parse(readFileSync(new URL('../../test-vectors/veilops-range-v2.json', import.meta.url), 'utf8'));
const P = (h: string) => ristretto255.Point.fromHex(h);

describe('v2 vectors: transcript', () => {
  it.each(V.contexts as { publicInputs: PublicInputsV2; transcriptContext: string; ctxHashLower: string; ctxHashUpper: string; challenge: { index: number; Ci: string; A0: string; A1: string; expectedLE: string } }[])('context and challenge', c => {
    expect(transcriptContextV2(c.publicInputs)).toBe(c.transcriptContext);
    expect(bytesToHex(ctxHashV2(c.publicInputs, 'lower'))).toBe(c.ctxHashLower);
    expect(bytesToHex(ctxHashV2(c.publicInputs, 'upper'))).toBe(c.ctxHashUpper);
    const e = bitChallengeV2(hexToBytes(c.ctxHashLower), c.challenge.index, P(c.challenge.Ci), P(c.challenge.A0), P(c.challenge.A1));
    expect(bytesToHex(scalarToLE(e))).toBe(c.challenge.expectedLE);
  });
});

describe('v2 vectors: proofs', () => {
  it.each(V.cases as { description: string; publicInputs: PublicInputsV2; proofHex: string; proofId: string; expected: boolean }[])('$description', c => {
    const bytes = hexToBytes(c.proofHex);
    expect(proofIdV2(bytes)).toBe(c.proofId);
    expect(verifyPolicyV2(c.publicInputs, bytes)).toBe(c.expected);
  });
});
