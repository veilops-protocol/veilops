/**
 * Verify veilops-range-v2 proofs ON-CHAIN with the veilops-verifier program, and record two cheating attempts
 * that the program must reject.
 *
 *   VEILOPS_DEVNET_KEYPAIR=/path/keypair.json npx tsx scripts/onchain-verify.ts [--rpc URL] [--bits-per-tx N] [--out FILE]
 *
 * The amounts stay hidden: only commitments and proofs go on-chain. Results (signatures, accounts, compute
 * units) are written to apps/website/data/onchain-verifications.json; scripts/onchain-check.ts re-checks them.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { createClient, signature as sig, type Instruction } from '@solana/kit';
import { solanaRpc } from '@solana/kit-plugin-rpc';
import { signerFromFile } from '@solana/kit-plugin-signer';
import { provePolicyV2, verifyPolicyV2, type PublicInputsV2 } from '@veilops/proof-engine';
import { hexToBytes } from '@veilops/shared';
import { PROGRAM_ID, proofLen, createBufferIx, beginIx, writeIx, verifyBitsIx, finalizeIx, computeLimitIx, recordPda, verificationPda } from './onchain/client';

const arg = (name: string, def?: string) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1]! : def; };
const rpcUrl = arg('--rpc', 'https://api.devnet.solana.com')!;
const bitsPerTx = Number(arg('--bits-per-tx', '8'));
const outPath = arg('--out', 'apps/website/data/onchain-verifications.json')!;
const keyPath = process.env.VEILOPS_DEVNET_KEYPAIR;
if (!keyPath || !existsSync(keyPath)) throw new Error('set VEILOPS_DEVNET_KEYPAIR');
const CHUNK = 880;
const cluster = rpcUrl.includes('devnet') ? 'devnet' : rpcUrl.includes('127.0.0.1') || rpcUrl.includes('localhost') ? 'localnet' : 'custom';

const client = await createClient().use(signerFromFile(keyPath)).use(solanaRpc({ rpcUrl, transactionConfig: { version: 0 } }));
// For the deliberate failures: no simulation, so the rejected transaction actually lands on-chain.
const raw = await createClient().use(signerFromFile(keyPath)).use(solanaRpc({ rpcUrl, skipPreflight: true, transactionConfig: { version: 0, estimateResourceLimits: false } }));
const me = client.payer;

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
/** Poll a signature's status: 'ok', 'failed', or null if it never landed. */
async function landed(signature: string): Promise<'ok' | 'failed' | null> {
  for (let i = 0; i < 20; i++) {
    const st = await client.rpc.getSignatureStatuses([sig(signature)], { searchTransactionHistory: true }).send().catch(() => null);
    const v = st?.value[0];
    if (v && (v.confirmationStatus === 'confirmed' || v.confirmationStatus === 'finalized')) return v.err ? 'failed' : 'ok';
    await sleep(1500);
  }
  return null;
}

async function send(ixs: Instruction[]): Promise<string> {
  for (let attempt = 0; ; attempt++) {
    try { return (await client.sendTransaction(ixs)).context.signature; } catch (e) {
      const m = String((e as Error)?.message ?? '') + ' ' + JSON.stringify((e as { context?: unknown })?.context ?? {});
      // The public RPC sometimes drops the confirmation WebSocket after the transaction was sent. Check whether it
      // actually landed before retrying, so nothing is ever executed twice.
      const sent = /\(([1-9A-HJ-NP-Za-km-z]{80,90})\)/.exec(m)?.[1];
      if (sent) {
        const status = await landed(sent);
        if (status === 'ok') return sent;
        if (status === 'failed') throw e;
      }
      if (attempt < 8 && /429|blockhash|timed out|fetch failed|WebSocket|socket|estimate the compute unit/i.test(m)) { await sleep(2000 * (attempt + 1)); continue; }
      throw e;
    }
  }
}
async function cu(signature: string): Promise<number | null> {
  for (let i = 0; i < 6; i++) {
    const tx = await client.rpc.getTransaction(sig(signature), { maxSupportedTransactionVersion: 0, commitment: 'confirmed', encoding: 'json' }).send().catch(() => null);
    if (tx?.meta) return Number(tx.meta.computeUnitsConsumed ?? 0);
    await sleep(1000);
  }
  return null;
}

const opId = () => `op_${randomBytes(8).toString('hex')}`;
const bufferRent = async (n: number) => (await client.rpc.getMinimumBalanceForRentExemption(BigInt(proofLen(n))).send());

async function upload(args: Omit<PublicInputsV2, 'amountCommitment'>, proofBytes: Uint8Array, commitmentHex: string) {
  const n = args.rangeBits;
  const { buffer, ix } = await createBufferIx(me, n, await bufferRent(n));
  const begin = await send([ix, await beginIx(me, buffer.address, { ...args, commitment: hexToBytes(commitmentHex) })]);
  const writes: string[] = [];
  for (let off = 0; off < proofBytes.length; off += CHUNK) {
    writes.push(await send([await writeIx(me, buffer.address, off, proofBytes.slice(off, off + CHUNK))]));
  }
  return { buffer: buffer.address, begin, writes };
}

/* ---------------- verified operations ---------------- */
const samples = JSON.parse(readFileSync('apps/website/data/samples.json', 'utf8')) as { policies: { id: string; name: string; maxAmount: number; rangeBits: number }[] };
const policy = (name: string) => samples.policies.find(p => p.name === name)!;
const DEMOS = [
  { category: 'vendor', asset: 'USDC', policy: policy('Vendor payments'), amount: 742_500 },
  { category: 'payroll', asset: 'USDC', policy: policy('Contributor payroll'), amount: 1_250_000 },
  { category: 'treasury', asset: 'USDC', policy: policy('Treasury rebalancing'), amount: 180_000_000 },
];

const existing = existsSync(outPath) ? JSON.parse(readFileSync(outPath, 'utf8')) : null;
const verified: unknown[] = existing?.verified ?? [];
const rejected: unknown[] = existing?.rejected ?? [];
const save = () => writeFileSync(outPath, JSON.stringify({
  cluster, program: PROGRAM_ID, proofSystem: 'veilops-range-v2', operator: me.address,
  note: 'Amounts are hidden: only Pedersen commitments and zero-knowledge proofs are on-chain. Devnet only; the program is experimental and not audited.',
  verified, rejected,
}, null, 2) + '\n');

console.log(`cluster ${cluster} · program ${PROGRAM_ID} · operator ${me.address} · ${bitsPerTx} bits per verify tx`);
for (const d of DEMOS) {
  if (verified.some(v => (v as { policyName: string }).policyName === d.policy.name)) { console.log(`already verified: ${d.policy.name}`); continue; }
  const args = { operationId: opId(), policyId: d.policy.id, asset: d.asset, category: d.category, maxAmount: d.policy.maxAmount, rangeBits: d.policy.rangeBits };
  const out = provePolicyV2({ ...args, amount: d.amount });
  if (!verifyPolicyV2(out.publicInputs, out.proofBytes)) throw new Error('local verification failed');
  const up = await upload(args, out.proofBytes, out.publicInputs.amountCommitment);
  const verifies: { signature: string; range: string; bits: number; computeUnits: number | null }[] = [];
  for (const range of [0, 1] as const) {
    for (let done = 0; done < args.rangeBits; done += bitsPerTx) {
      const count = Math.min(bitsPerTx, args.rangeBits - done);
      const s = await send([await verifyBitsIx(me, up.buffer, range, count)]);
      verifies.push({ signature: s, range: range ? 'upper' : 'lower', bits: count, computeUnits: await cu(s) });
    }
  }
  const finalize = await send([await finalizeIx(me, up.buffer, args.operationId)]);
  const entry = {
    operationId: args.operationId, policyId: args.policyId, policyName: d.policy.name, category: d.category, asset: d.asset,
    maxAmount: args.maxAmount, rangeBits: args.rangeBits, commitment: out.publicInputs.amountCommitment, proofId: out.proofId, proofBytes: out.proofBytes.length,
    record: await recordPda(args.operationId), verification: await verificationPda(up.buffer), buffer: up.buffer,
    transactions: { begin: up.begin, writes: up.writes, verifies, finalize },
    finalizeComputeUnits: await cu(finalize),
    totalTransactions: 2 + up.writes.length + verifies.length,
  };
  verified.push(entry);
  save();
  console.log(`VERIFIED ON-CHAIN ${args.operationId} (${d.policy.name}, limit ${args.maxAmount}, ${args.rangeBits} bits) -> record ${entry.record}`);
}

/* ---------------- cheating attempts that must fail on-chain ---------------- */
async function attempt(kind: string, description: string, args: { operationId: string; policyId: string; asset: string; category: string; maxAmount: number; rangeBits: number }, proofBytes: Uint8Array, commitment: string) {
  const up = await upload(args, proofBytes, commitment);
  let failedSignature: string | null = null, error = '';
  try {
    const s = (await raw.sendTransaction([computeLimitIx(1_400_000), await verifyBitsIx(raw.payer, up.buffer, 0, bitsPerTx)])).context.signature;
    error = `UNEXPECTED: transaction ${s} succeeded`;
  } catch (e) {
    error = String((e as Error)?.message ?? e).slice(0, 300);
  }
  // find the failed transaction on-chain via the buffer's signature history
  for (let i = 0; i < 8 && !failedSignature; i++) {
    await sleep(1500);
    const list = await client.rpc.getSignaturesForAddress(up.buffer, { limit: 10 }).send().catch(() => []);
    const f = list.find(x => x.err);
    if (f) failedSignature = f.signature;
  }
  const logs = failedSignature
    ? (await client.rpc.getTransaction(sig(failedSignature), { maxSupportedTransactionVersion: 0, commitment: 'confirmed', encoding: 'json' }).send())?.meta?.logMessages ?? []
    : [];
  const programError = logs.find(l => l.includes('Error Message')) ?? logs.find(l => l.includes('failed')) ?? error;
  const recordExists = !!(await client.rpc.getAccountInfo(await recordPda(args.operationId)).send()).value;
  rejected.push({ kind, description, operationId: args.operationId, buffer: up.buffer, failedSignature, programError, recordExists });
  save();
  console.log(`${failedSignature && !recordExists ? 'REJECTED ON-CHAIN' : 'CHECK MANUALLY'} ${kind}: ${programError}`);
}

{
  const p = policy('Vendor payments');
  const args = { operationId: opId(), policyId: p.id, asset: 'USDC', category: 'vendor', maxAmount: p.maxAmount, rangeBits: p.rangeBits };
  const out = provePolicyV2({ ...args, amount: 900_000 });
  const tampered = out.proofBytes.slice();
  tampered[2 + 96] = tampered[2 + 96]! ^ 0x01; // flip one bit of s0 in the first lower bit proof
  await attempt('tampered-proof', 'A valid proof with a single bit flipped in one response scalar.', args, tampered, out.publicInputs.amountCommitment);
}
{
  const p = policy('Vendor payments');
  const args = { operationId: opId(), policyId: p.id, asset: 'USDC', category: 'vendor', maxAmount: p.maxAmount, rangeBits: p.rangeBits };
  const out = provePolicyV2({ ...args, amount: 900_000 });
  // Claim a stricter limit (100,000) than the proof was made for, hoping the chain accepts an amount of 900,000 under it.
  await attempt('lowered-limit', 'An honest proof for limit 15,000,000 presented as if it proved the amount is under 100,000.', { ...args, maxAmount: 100_000 }, out.proofBytes, out.publicInputs.amountCommitment);
}
console.log(`wrote ${outPath}`);
