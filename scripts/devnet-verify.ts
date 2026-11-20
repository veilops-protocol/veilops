/**
 * Independently re-check every devnet anchor listed in apps/website/data/devnet-anchors.json.
 *
 * For each anchor it fetches the transaction from a public devnet RPC (plain JSON-RPC, no Solana SDK) and checks:
 *   - the transaction succeeded and is signed by the published anchor key
 *   - it contains an SPL Memo instruction whose text equals anchorMemo(record)
 *   - the record digest in the memo equals sha256(canonicalJson(record)) of the published sample record
 *   - the record itself still verifies (zero-knowledge range proof, proof id binding, Ed25519 attestation)
 *
 *   npx tsx scripts/devnet-verify.ts [rpcUrl]
 */
import { readFileSync } from 'node:fs';
import { anchorMemo, parseAnchorMemo, recordDigest, MEMO_PROGRAM_ID } from '@veilops/solana-adapter';
import { verifyRecord } from '@veilops/proof-engine';
import type { PublicRecord } from '@veilops/shared';

const rpcUrl = process.argv[2] ?? process.env.SOLANA_DEVNET_RPC ?? 'https://api.devnet.solana.com';
const anchorsFile = JSON.parse(readFileSync('apps/website/data/devnet-anchors.json', 'utf8'));
const samples = JSON.parse(readFileSync('apps/website/data/samples.json', 'utf8')) as { records: { record: PublicRecord }[] };
const byOp = new Map(samples.records.map(e => [e.record.operationId, e.record]));

async function rpc(method: string, params: unknown[]) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    if (res.status === 429) { await new Promise(r => setTimeout(r, 1500 * (attempt + 1))); continue; }
    const body = await res.json() as { result?: unknown; error?: { message: string } };
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
  }
  throw new Error(`${method}: rate limited`);
}

type ParsedTx = {
  slot: number;
  meta: { err: unknown } | null;
  transaction: { message: { accountKeys: { pubkey: string; signer: boolean }[]; instructions: { programId: string; parsed?: unknown }[] } };
};

let failures = 0;
for (const a of anchorsFile.anchors as { operationId: string; signature: string; memo: string }[]) {
  const problems: string[] = [];
  const record = byOp.get(a.operationId);
  const tx = await rpc('getTransaction', [a.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]) as ParsedTx | null;
  if (!record) problems.push('record not found in published samples');
  if (!tx) problems.push('transaction not found on devnet');
  if (tx && record) {
    if (tx.meta?.err) problems.push('transaction failed');
    const signers = tx.transaction.message.accountKeys.filter(k => k.signer).map(k => k.pubkey);
    if (!signers.includes(anchorsFile.signer)) problems.push('not signed by the published anchor key');
    const memos = tx.transaction.message.instructions.filter(i => i.programId === MEMO_PROGRAM_ID).map(i => String(i.parsed));
    const expected = anchorMemo(record);
    if (!memos.includes(expected)) problems.push(`memo mismatch (on chain: ${memos.join(' | ') || 'none'})`);
    const parsed = parseAnchorMemo(memos[0] ?? '');
    if (!parsed || parsed.digest !== recordDigest(record) || parsed.proofId !== record.proofId) problems.push('memo does not bind this record');
    if (!verifyRecord(record).valid) problems.push('record no longer verifies');
  }
  if (problems.length) failures++;
  console.log(`${problems.length ? 'FAIL' : 'PASS'} ${a.operationId} slot ${tx?.slot ?? '?'} ${a.signature.slice(0, 16)}…${problems.length ? '  ' + problems.join('; ') : ''}`);
}
console.log(`${anchorsFile.anchors.length - failures}/${anchorsFile.anchors.length} devnet anchors verified against ${rpcUrl}`);
process.exit(failures ? 1 : 0);
