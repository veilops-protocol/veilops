import { describe, it, expect } from 'vitest';
import { seal, openText, grantAccess, generateViewingKeyPair, envelopeDigest } from '@veilops/encryption';

describe('encryption', () => {
  it('seals for recipients and opens with each recipient key', async () => {
    const owner = generateViewingKeyPair(), auditor = generateViewingKeyPair();
    const env = await seal('amount=4200', [owner.publicKey, auditor.publicKey], 'op_1');
    expect(env.ciphertext).not.toContain('4200');
    expect(await openText(env, owner.secretKey)).toBe('amount=4200');
    expect(await openText(env, auditor.secretKey)).toBe('amount=4200');
  });
  it('rejects non-recipients', async () => {
    const owner = generateViewingKeyPair(), stranger = generateViewingKeyPair();
    const env = await seal('secret', [owner.publicKey], 'op_2');
    await expect(openText(env, stranger.secretKey)).rejects.toThrow(/not an authorized recipient/);
  });
  it('detects tampering with ciphertext or associated data', async () => {
    const owner = generateViewingKeyPair();
    const env = await seal('secret', [owner.publicKey], 'op_3');
    const flipped = env.ciphertext[0] === 'A' ? 'B' + env.ciphertext.slice(1) : 'A' + env.ciphertext.slice(1);
    await expect(openText({ ...env, ciphertext: flipped }, owner.secretKey)).rejects.toThrow();
    await expect(openText({ ...env, aad: 'op_other' }, owner.secretKey)).rejects.toThrow();
  });
  it('grantAccess adds a reader without changing the ciphertext', async () => {
    const owner = generateViewingKeyPair(), late = generateViewingKeyPair();
    const env = await seal('payroll', [owner.publicKey], 'op_4');
    const env2 = await grantAccess(env, owner.secretKey, late.publicKey);
    expect(env2.ciphertext).toBe(env.ciphertext);
    expect(envelopeDigest(env2)).toBe(envelopeDigest(env));
    expect(await openText(env2, late.secretKey)).toBe('payroll');
  });
  it('uses a fresh nonce every time', async () => {
    const owner = generateViewingKeyPair();
    const a = await seal('x', [owner.publicKey], 'a'), b = await seal('x', [owner.publicKey], 'a');
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });
});
