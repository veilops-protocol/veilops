# Verify VEILOPS yourself

You should not have to trust this project's claims. This page lists every check you can run without asking us anything.

| What | How | Needs |
| --- | --- | --- |
| The code builds and every test passes | [1. Reproducible build](#1-reproducible-build) | Node (version in `.nvmrc`), Python 3 |
| Release tarballs match the source | [1. Reproducible build](#1-reproducible-build) | same |
| Two separate implementations agree on the cryptography | [2. Test vectors and the independent verifier](#2-test-vectors-and-the-independent-verifier) | Python 3 only, no packages |
| Zero-knowledge proofs are verified by a Solana program on devnet | [3a. On-chain verification](#3a-on-chain-proof-verification-devnet) | Node, internet |
| Records are anchored on Solana devnet | [3. Solana devnet anchors](#3-solana-devnet-anchors) | Node, internet |
| Releases were built by GitHub Actions from this repository | [4. Build provenance](#4-build-provenance) | `gh` CLI |
| Commits come from the same maintainer key | [5. Signed commits](#5-signed-commits) | git |
| You are on an official channel | [6. Official channels](#6-official-channels) | a browser |

What these checks do **not** give you is an external audit. No independent cryptographic review has been done yet; see [docs/audit-scope.md](docs/audit-scope.md) for the review package and its status.

## 1. Reproducible build

```bash
git clone https://github.com/veilops-protocol/veilops && cd veilops
git checkout v0.1.1          # or any tag / commit
nvm install && nvm use       # Node version pinned in .nvmrc
bash scripts/reproduce.sh
```

`reproduce.sh` installs only from the lockfile (`npm ci`), runs typecheck, lint, the full test suite and the independent Python verifier, then packs every package and writes `dist/SHA256SUMS`.

Compare that file with:

- the `SHA256SUMS` asset attached to the [GitHub release](https://github.com/veilops-protocol/veilops/releases), and
- the checksums printed in the **Reproducible artifacts** job summary of the CI run for the same commit.

The package tarballs are byte-for-byte reproducible with the pinned Node/npm version. The Next.js website bundle is not (it embeds build ids) and is not part of the checksums.

## 2. Test vectors and the independent verifier

[`test-vectors/veilops-range-v1.json`](test-vectors/veilops-range-v1.json) and [`veilops-range-v2.json`](test-vectors/veilops-range-v2.json) fix the protocol. The v2 file is the on-chain encoding: a SHA-256 transcript with the same statement, plus 16 valid and broken cases. The v1 file covers:

- generator `H` and its hash-to-curve derivation
- Pedersen commitments for chosen `(v, r)`
- Fiat–Shamir challenges
- 16 range-proof cases and 10 policy-proof cases, valid and deliberately broken (wrong context, edited scalars, reordered or truncated bits, non-canonical scalars, invalid points, swapped proofs, a lowered limit)
- full public records, including tampered ones, with their expected verdicts

Two implementations check the same file:

| Implementation | Language | Libraries | Run |
| --- | --- | --- | --- |
| Reference, `packages/proof-engine` | TypeScript | `@noble/curves`, `@noble/hashes` | `npm test` |
| On-chain verifier (v2), `onchain/` | Rust (Solana program) | curve25519 and SHA-256 syscalls | `scripts/onchain-check.ts` |
| Independent verifier, [`verifiers/python`](verifiers/python) | Python 3 | standard library only: its own field, curve, hash-to-curve and Ed25519 code | `python3 verifiers/python/veilops_verify.py test-vectors/veilops-range-v1.json test-vectors/veilops-range-v2.json` |

The Python verifier also checks its curve code against the official RFC 9496 (ristretto255) and RFC 8032 (Ed25519) test vectors before it trusts its own results. CI runs both implementations on every commit.

The second implementation was written separately from the reference code, but by the same project. It shows that the specification is precise enough to implement twice and that both implementations agree. It is not a substitute for an independent review.

## 3. Solana devnet anchors

Six verified sample records are anchored on **Solana devnet** with SPL Memo transactions. They were published on 2026-11-20 in slots 524352545–524352580 by the anchor key [`9kpS3zvBWmA5jtatwPd4HvbJ1PgazbsBpxQA38grYQie`](https://explorer.solana.com/address/9kpS3zvBWmA5jtatwPd4HvbJ1PgazbsBpxQA38grYQie?cluster=devnet). The memo format is:

```
veilops:<version>:<proofId>:<sha256(canonicalJson(record))>
```

The anchors are listed in [`apps/website/data/devnet-anchors.json`](apps/website/data/devnet-anchors.json) and on <https://veilops.tech/trust>. To re-check all of them against a public RPC:

```bash
npx tsx scripts/devnet-verify.ts                     # default: https://api.devnet.solana.com
npx tsx scripts/devnet-verify.ts https://your-devnet-rpc
npx tsx scripts/devnet-sync.ts                       # rebuild the list from the chain itself (read-only)
```

For each anchor the script checks:

- the transaction succeeded and was signed by the published anchor key
- the memo equals the one computed from the published record
- the record still verifies (range proof, proof id, signature)

A scheduled workflow, **Devnet anchors**, runs the same check daily.

This is devnet only. Devnet SOL has no value, and nothing here is a mainnet deployment.

## 3a. On-chain proof verification (devnet)

The [`veilops-verifier`](onchain) program verifies `veilops-range-v2` zero-knowledge range proofs **inside a Solana program**. It checks every bit proof with the curve25519 (ristretto255) and SHA-256 syscalls, then checks that both bit decompositions add up to the commitment. A `Record` account is created only when the whole proof verifies. The amount is never on-chain.

| | |
| --- | --- |
| Program | [`4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ`](https://explorer.solana.com/address/4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ?cluster=devnet) |
| Deployed binary | SHA-256 `593c984b7db2a4c345797844aa803ccb99048f92526619efe01eea86c8431003` (trailing padding removed). It is byte-identical to the artifact of the reproducible [Program build](https://github.com/veilops-protocol/veilops/actions/workflows/program.yml) workflow, and that artifact has signed provenance. |
| Upgrade authority | `9kpS3zvBWmA5jtatwPd4HvbJ1PgazbsBpxQA38grYQie`. The program is still upgradable on devnet; `program-hash.ts` always prints the current authority and hash. |
| Results | [`apps/website/data/onchain-verifications.json`](apps/website/data/onchain-verifications.json): 3 proofs verified on-chain, plus 2 cheating attempts the program rejected. |

The two cheating attempts were sent without simulation, so the failures are recorded on-chain:

- **A tampered proof:** a valid proof with one bit flipped in one response scalar.
- **A lowered limit:** an honest proof made for a 15,000,000 limit, presented as proof that the amount is under 100,000.

Both failed with `BitProofInvalid`, and no `Record` exists for either.

Check everything from chain data:

```bash
npx tsx scripts/onchain-check.ts
npx tsx scripts/program-hash.ts --so veilops_verifier.so
```

For every verified operation, `onchain-check.ts` confirms that:
- the `Record` is owned by the program and its fields match
- the proof bytes stored on-chain hash to the Record's `proof_hash`
- the same bytes re-verify off-chain with the TypeScript reference

For every attempt, it confirms that the transaction failed with the program's error and that no `Record` exists.

`program-hash.ts` compares the deployed program with any build. Use the `veilops_verifier.so` artifact of the Program build workflow, or rebuild it with the pinned Docker image (see [onchain/README.md](onchain/README.md)).

The daily **Devnet anchors** workflow re-runs `onchain-check.ts`.

## 4. Build provenance

Release assets are built by the **Release** workflow and carry a signed [GitHub artifact attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations) (Sigstore). Check any downloaded file with:

```bash
gh attestation verify veilops-proof-engine-0.1.1.tgz --repo veilops-protocol/veilops
```

A passing check proves the file was produced by a GitHub Actions run of this repository at a specific commit, and not uploaded by hand.

## 5. Signed commits

From v0.1.1 onwards, commits and tags are signed with the maintainer's SSH key and show **Verified** on GitHub:

```
SHA256:0q/tLTLWz3mdlXFnfCcJbDYeJ7nHnGu37TaBa/h96m8  (ed25519, veilopsonline commit signing)
```

The public key is also committed in [`.github/allowed_signers`](.github/allowed_signers), so you can verify without relying on GitHub:

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers log --show-signature -5
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v0.1.1
```

Commits made before v0.1.1 (the initial import on 2026-11-20) are unsigned.

## 6. Official channels

| Channel | Address |
| --- | --- |
| Website | <https://veilops.tech> |
| Source code | <https://github.com/veilops-protocol> |
| Token CA (Solana) | `P8SrfF4GWpJ6muNviD7LHN8bJTTY9mhxNzrBoU2pump` ([pump.fun](https://pump.fun/coin/P8SrfF4GWpJ6muNviD7LHN8bJTTY9mhxNzrBoU2pump)) |
| X | [@Veilops_Tech](https://x.com/Veilops_Tech) |
| Security reports | [GitHub private vulnerability reporting](https://github.com/veilops-protocol/veilops/security/advisories/new) |
| Machine-readable list | <https://veilops.tech/.well-known/veilops.json> |

Any other token address is not official. The only official X account is [@Veilops_Tech](https://x.com/Veilops_Tech). VEILOPS has **no** Telegram or Discord yet. Anything else that claims to be official is not, unless it is added to this table and to `/.well-known/veilops.json` in a signed commit.
