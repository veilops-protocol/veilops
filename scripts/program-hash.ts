/**
 * Print the SHA-256 of the veilops-verifier program as deployed on-chain, and optionally compare it with a
 * local .so (e.g. the artifact of the reproducible "Program build" workflow).
 *
 *   npx tsx scripts/program-hash.ts [--rpc URL] [--so path/to/veilops_verifier.so]
 *
 * Same convention as `solana-verify get-program-hash`: the executable bytes of the ProgramData account
 * (after its 45-byte header) with trailing zero padding removed.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { toBase58 } from './onchain/client';

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1]! : d; };
const rpcUrl = arg('--rpc', 'https://api.devnet.solana.com')!;
const soPath = arg('--so');
const PROGRAM = '4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ';
async function account(pubkey: string): Promise<{ owner: string; data: Uint8Array } | null> {
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getAccountInfo', params: [pubkey, { encoding: 'base64', commitment: 'confirmed' }] }) });
  const body = await res.json() as { result?: { value: { owner: string; data: [string, string] } | null } };
  const v = body.result?.value;
  return v ? { owner: v.owner, data: new Uint8Array(Buffer.from(v.data[0], 'base64')) } : null;
}

const stripZeros = (b: Uint8Array) => { let end = b.length; while (end > 0 && b[end - 1] === 0) end--; return b.slice(0, end); };
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

const program = await account(PROGRAM);
if (!program) { console.log(`program ${PROGRAM} not found on ${rpcUrl}`); process.exit(2); }
const programData = toBase58(program.data.slice(4, 36));
const pd = await account(programData);
if (!pd) throw new Error('program data account not found');
const slot = new DataView(pd.data.buffer, pd.data.byteOffset + 4, 8).getBigUint64(0, true);
const authority = pd.data[12] === 1 ? toBase58(pd.data.slice(13, 45)) : 'none (immutable)';
const onchain = sha(stripZeros(pd.data.slice(45)));
console.log(`program        ${PROGRAM}`);
console.log(`owner          ${program.owner}`);
console.log(`program data   ${programData}`);
console.log(`deployed slot  ${slot}`);
console.log(`upgrade auth   ${authority}`);
console.log(`on-chain hash  ${onchain}`);
if (soPath) {
  const local = sha(stripZeros(new Uint8Array(readFileSync(soPath))));
  console.log(`build hash     ${local}  (${soPath})`);
  console.log(local === onchain ? 'MATCH: the deployed program is byte-identical to this build' : 'MISMATCH');
  process.exit(local === onchain ? 0 : 1);
}
