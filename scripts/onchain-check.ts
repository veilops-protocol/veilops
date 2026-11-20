/**
 * Independently check the on-chain verification results in apps/website/data/onchain-verifications.json.
 *
 *   npx tsx scripts/onchain-check.ts [--rpc URL] [--file path]
 *
 * For every verified operation:
 *   - the Record account exists, is owned by the veilops-verifier program, and its fields match the listing
 *   - the proof bytes stored on-chain hash to the Record's proof_hash
 *   - re-verifying those on-chain bytes OFF-chain (TypeScript reference verifier) also succeeds
 *   - the finalize transaction succeeded
 * For every cheating attempt:
 *   - the transaction failed on-chain with the program's error, and no Record exists for that operation
 * Uses plain JSON-RPC; sends nothing.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { verifyPolicyV2 } from '@veilops/proof-engine';
import { bytesToHex } from '@veilops/shared';
import { decodeRecord, PROGRAM_ID, recordPda, toBase58 } from './onchain/client';

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1]! : d; };
const file = JSON.parse(readFileSync(arg('--file', 'apps/website/data/onchain-verifications.json')!, 'utf8'));
const rpcUrl = arg('--rpc', file.cluster === 'devnet' ? 'https://api.devnet.solana.com' : 'http://127.0.0.1:8899')!;

async function rpc(method: string, params: unknown[]) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    if (res.status === 429) { await new Promise(r => setTimeout(r, 2000 * (attempt + 1))); continue; }
    const body = await res.json() as { result?: unknown; error?: { message: string } };
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
  }
  throw new Error(`${method}: rate limited`);
}
const accountData = async (k: string) => {
  const v = (await rpc('getAccountInfo', [k, { encoding: 'base64', commitment: 'confirmed' }]) as { value: { owner: string; data: [string, string] } | null }).value;
  return v ? { owner: v.owner, data: new Uint8Array(Buffer.from(v.data[0], 'base64')) } : null;
};
const txMeta = async (s: string) => (await rpc('getTransaction', [s, { encoding: 'json', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]) as { meta: { err: unknown; logMessages: string[] } } | null)?.meta ?? null;

let failures = 0;
const report = (ok: boolean, label: string, detail = '') => { if (!ok) failures++; console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`); };

for (const v of file.verified) {
  const problems: string[] = [];
  const acc = await accountData(v.record);
  if (!acc) problems.push('record account missing');
  else {
    if (acc.owner !== PROGRAM_ID) problems.push(`record owned by ${acc.owner}`);
    const r = decodeRecord(acc.data, toBase58);
    if (r.operationId !== v.operationId || r.policyId !== v.policyId || r.asset !== v.asset || r.category !== v.category) problems.push('record text fields differ');
    if (r.maxAmount !== BigInt(v.maxAmount) || r.rangeBits !== v.rangeBits) problems.push('record limit differs');
    if (bytesToHex(r.commitment) !== v.commitment) problems.push('record commitment differs');
    const buf = await accountData(r.buffer);
    if (!buf) problems.push('proof buffer missing');
    else {
      if (createHash('sha256').update(buf.data).digest('hex') !== bytesToHex(r.proofHash)) problems.push('proof bytes do not match proof_hash');
      const pi = { operationId: r.operationId, policyId: r.policyId, maxAmount: Number(r.maxAmount), rangeBits: r.rangeBits, asset: r.asset, category: r.category, amountCommitment: bytesToHex(r.commitment) };
      if (!verifyPolicyV2(pi, buf.data)) problems.push('off-chain re-verification of the on-chain proof failed');
    }
  }
  const fin = await txMeta(v.transactions.finalize);
  if (!fin || fin.err) problems.push('finalize transaction missing or failed');
  report(!problems.length, `verified ${v.operationId} (${v.policyName}, limit ${v.maxAmount})`, problems.join('; '));
}

for (const r of file.rejected) {
  const problems: string[] = [];
  const meta = r.failedSignature ? await txMeta(r.failedSignature) : null;
  if (!meta) problems.push('failed transaction not found');
  else {
    if (!meta.err) problems.push('transaction did not fail');
    if (!meta.logMessages.some(l => l.includes('BitProofInvalid') || l.includes('Error Code'))) problems.push('program error not in logs');
  }
  if (await accountData(await recordPda(r.operationId))) problems.push('a Record exists for a rejected operation');
  report(!problems.length, `rejected ${r.kind} ${r.operationId}`, problems.join('; '));
}
console.log(`${failures ? 'SOME CHECKS FAILED' : 'ALL CHECKS PASSED'} against ${rpcUrl} (program ${PROGRAM_ID})`);
process.exit(failures ? 1 : 0);
