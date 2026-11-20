# Verify VEILOPS yourself

You should not have to trust this project's claims. This page lists every check you can run without asking us anything.

| What | How | Needs |
| --- | --- | --- |
| The code builds and every test passes | [1. Reproducible build](#1-reproducible-build) | Node (version in `.nvmrc`), Python 3 |
| Release tarballs match the source | [1. Reproducible build](#1-reproducible-build) | same |
| Two separate implementations agree on the cryptography | [2. Test vectors and the independent verifier](#2-test-vectors-and-the-independent-verifier) | Python 3 only, no packages |
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

[`test-vectors/veilops-range-v1.json`](test-vectors/veilops-range-v1.json) fixes the protocol:

- generator `H` and its hash-to-curve derivation
- Pedersen commitments for chosen `(v, r)`
- Fiat–Shamir challenges
- 16 range-proof cases and 10 policy-proof cases, valid and deliberately broken (wrong context, edited scalars, reordered or truncated bits, non-canonical scalars, invalid points, swapped proofs, a lowered limit)
- full public records, including tampered ones, with their expected verdicts

Two implementations check the same file:

| Implementation | Language | Libraries | Run |
| --- | --- | --- | --- |
| Reference, `packages/proof-engine` | TypeScript | `@noble/curves`, `@noble/hashes` | `npm test` |
| Independent verifier, [`verifiers/python`](verifiers/python) | Python 3 | standard library only: its own field, curve, hash-to-curve and Ed25519 code | `python3 verifiers/python/veilops_verify.py test-vectors/veilops-range-v1.json` |

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
| Security reports | [GitHub private vulnerability reporting](https://github.com/veilops-protocol/veilops/security/advisories/new) |
| Machine-readable list | <https://veilops.tech/.well-known/veilops.json> |

VEILOPS has **no** official X/Twitter, Telegram or Discord account yet. Anything else that claims to be official is not, unless it is added to this table and to `/.well-known/veilops.json` in a signed commit.
