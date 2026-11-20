/**
 * Anchor verified sample records on Solana DEVNET with SPL Memo transactions.
 *
 * Each memo is `veilops:<version>:<proofId>:<sha256(canonicalJson(record))>` (see @veilops/solana-adapter).
 * Devnet SOL has no monetary value; nothing is transferred, the only cost is the devnet fee.
 * Results are written to apps/website/data/devnet-anchors.json and checked by scripts/devnet-verify.ts.
 *
 *   VEILOPS_DEVNET_KEYPAIR=/path/outside/repo/devnet-keypair.json npx tsx scripts/devnet-anchor.ts [count]
 *
 * The keypair file is a solana-keygen style JSON array (64 bytes). Never commit it.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createClient, lamports, address } from '@solana/kit';
import { solanaDevnetRpc } from '@solana/kit-plugin-rpc';
import { signerFromFile } from '@solana/kit-plugin-signer';
import { getAddMemoInstruction, SUPPORTED_MEMO_PROGRAM_ADDRESSES } from '@solana-program/memo';
import { anchorMemo, recordDigest, MEMO_PROGRAM_ID } from '@veilops/solana-adapter';
import { verifyRecord } from '@veilops/proof-engine';
import type { PublicRecord } from '@veilops/shared';

const keyPath = process.env.VEILOPS_DEVNET_KEYPAIR;
if (!keyPath || !existsSync(keyPath)) throw new Error('set VEILOPS_DEVNET_KEYPAIR to a devnet keypair file (outside the repository)');
// Pin the long-established SPL Memo v2 program; the library default may point at a newer deployment.
if (!SUPPORTED_MEMO_PROGRAM_ADDRESSES.includes(address(MEMO_PROGRAM_ID))) throw new Error('memo program id not recognised');
const count = Number(process.argv[2] ?? 6);

const samples = JSON.parse(readFileSync('apps/website/data/samples.json', 'utf8')) as { records: { record: PublicRecord; status: string }[] };
const outPath = 'apps/website/data/devnet-anchors.json';
const previous = existsSync(outPath) ? JSON.parse(readFileSync(outPath, 'utf8')) : { anchors: [] };
const done = new Set<string>(previous.anchors.map((a: { operationId: string }) => a.operationId));

const candidates = samples.records
  .filter(e => e.status === 'verified' && !done.has(e.record.operationId))
  .filter(e => verifyRecord(e.record).valid) // never anchor a record that does not verify locally
  .slice(0, count);

const client = await createClient()
  .use(signerFromFile(keyPath))
  .use(solanaDevnetRpc({ transactionConfig: { version: 0 } }));
const payer = client.payer.address;

const balance = (await client.rpc.getBalance(payer).send()).value;
console.log(`devnet signer ${payer}, balance ${Number(balance) / 1e9} SOL`);
if (balance < 5_000_000n) {
  console.log('requesting a devnet airdrop (1 SOL)…');
  await client.airdrop(address(payer), lamports(1_000_000_000n));
}

const anchors = [...previous.anchors];
for (const { record } of candidates) {
  const memo = anchorMemo(record);
  const result = await client.sendTransaction([getAddMemoInstruction({ memo }, { programAddress: address(MEMO_PROGRAM_ID) })]);
  const signature = result.context.signature;
  const tx = await client.rpc.getTransaction(signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed', encoding: 'json' }).send();
  anchors.push({
    operationId: record.operationId, proofId: record.proofId, recordDigest: recordDigest(record), memo, signature,
    slot: tx ? Number(tx.slot) : null, blockTime: tx?.blockTime ? new Date(Number(tx.blockTime) * 1000).toISOString() : null,
  });
  console.log(`anchored ${record.operationId} -> ${signature}`);
}

writeFileSync(outPath, JSON.stringify({
  cluster: 'devnet',
  memoProgram: MEMO_PROGRAM_ID,
  signer: payer,
  note: 'Solana devnet only. Devnet SOL has no value. These transactions prove the anchoring path works end to end; they are not a mainnet deployment.',
  explorer: 'https://explorer.solana.com/tx/<signature>?cluster=devnet',
  anchors,
}, null, 2) + '\n');
console.log(`wrote ${outPath} (${anchors.length} anchors)`);
