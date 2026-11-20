# veilops-verifier (Solana program)

**Status: experimental, not audited. Deployed on devnet only.**

Program ID: `4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ`

This program verifies `veilops-range-v2` zero-knowledge range proofs **on-chain**. Given a Pedersen commitment `C`, it checks that `C` hides an amount between 0 and the public limit, without learning the amount. Only a fully verified proof creates a `Record` account.

## How it works

A proof is about 10 KB, larger than one transaction, so verification takes several steps:

| Step | Instruction | What the program checks |
| --- | --- | --- |
| 1 | `begin` | Text fields, bit count, and that the limit fits the bit count. The commitment must be a valid ristretto255 point, and the proof buffer must be fresh. The program **rebuilds the transcript context from the public inputs itself**. |
| 2 | `write` | The authority uploads the proof bytes in chunks. This is only allowed before verification starts. |
| 3 | `verify_bits` | Each CDS OR-proof is checked with the curve25519 syscalls (multiscalar multiplication) and the SHA-256 syscall. All scalars must be canonical. The first call locks the buffer. |
| 4 | `finalize` | Checks `Σ 2^i·C_i = C` for the lower range and `= maxAmount·G − C` for the upper range, then creates the `Record` (one per operation id). |

Any failed check aborts the transaction, so a forged proof never reaches `finalize`. Each bit proof costs about 35k compute units, and up to 32 bits fit in one transaction.

## Build reproducibly

The **Program build** workflow builds the program inside `solanafoundation/solana-verifiable-build:3.1.10`, pinned by digest. It attests the result and compares it byte-for-byte with the program deployed on devnet:

```bash
docker run --rm -v "$PWD/onchain":/build -w /build \
  solanafoundation/solana-verifiable-build@sha256:f71be5ca7620b7e40933b7f1294fa44e01d08c1fc5ba1f375a2478f5a01580d3 \
  cargo build-sbf --manifest-path programs/veilops-verifier/Cargo.toml -- --locked
npx tsx scripts/program-hash.ts --so onchain/target/deploy/veilops_verifier.so   # prints MATCH
```

## Check the on-chain results yourself

```bash
npx tsx scripts/onchain-check.ts
```

For every verified operation, this confirms that:
- the `Record` is owned by the program
- the proof bytes stored on-chain match its `proof_hash`
- the same bytes re-verify off-chain

For every cheating attempt, it confirms that the transaction failed on-chain and that no `Record` exists.
