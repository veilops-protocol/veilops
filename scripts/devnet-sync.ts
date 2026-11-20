/**
 * Rebuild apps/website/data/devnet-anchors.json from the chain itself.
 *
 * Reads every transaction signed by the anchor key on Solana devnet, keeps the successful ones whose memo
 * parses as a VEILOPS anchor and matches a published sample record (proof id + record digest), and writes
 * them in slot order. Nothing is sent; this only reads public data, so anyone can run it.
 *
 *   npx tsx scripts/devnet-sync.ts [rpcUrl]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parseAnchorMemo, recordDigest, anchorMemo } from '@veilops/solana-adapter';
import type { PublicRecord } from '@veilops/shared';

const rpcUrl = process.argv[2] ?? process.env.SOLANA_DEVNET_RPC ?? 'https://api.devnet.solana.com';
const outPath = 'apps/website/data/devnet-anchors.json';
const file = JSON.parse(readFileSync(outPath, 'utf8'));
const samples = JSON.parse(readFileSync('apps/website/data/samples.json', 'utf8')) as { records: { record: PublicRecord }[] };
const byProof = new Map(samples.records.map(e => [e.record.proofId, e.record]));

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

type SigInfo = { signature: string; slot: number; err: unknown; memo: string | null; blockTime: number | null };
const sigs = await rpc('getSignaturesForAddress', [file.signer, { limit: 1000, commitment: 'confirmed' }]) as SigInfo[];

const seen = new Set<string>();
const anchors = [];
for (const s of [...sigs].sort((a, b) => a.slot - b.slot)) {
  if (s.err || !s.memo) continue;
  // getSignaturesForAddress reports memos as "[len] text"
  const text = s.memo.replace(/^\[\d+\]\s*/, '');
  const parsed = parseAnchorMemo(text);
  if (!parsed) continue;
  const record = byProof.get(parsed.proofId);
  if (!record || recordDigest(record) !== parsed.digest || anchorMemo(record) !== text) continue;
  if (seen.has(record.operationId)) continue; // keep the first anchor per record
  seen.add(record.operationId);
  anchors.push({
    operationId: record.operationId, proofId: record.proofId, recordDigest: parsed.digest, memo: text, signature: s.signature,
    slot: s.slot, blockTime: s.blockTime ? new Date(s.blockTime * 1000).toISOString() : null,
  });
}

writeFileSync(outPath, JSON.stringify({ ...file, anchors }, null, 2) + '\n');
console.log(`synced ${anchors.length} anchors from ${rpcUrl} into ${outPath}`);
