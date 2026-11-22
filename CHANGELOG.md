# Changelog

All notable changes to VEILOPS. Dates are UTC. The project follows [Semantic Versioning](https://semver.org); everything below 1.0 is experimental.

## [Unreleased]

### Added

- **Official token CA** `P8SrfF4GWpJ6muNviD7LHN8bJTTY9mhxNzrBoU2pump` (Solana, pump.fun), shown on the home page, footer, trust page, `VERIFY.md` §6 and `/.well-known/veilops.json`.
- **Official X account** [@Veilops_Tech](https://x.com/Veilops_Tech), listed on the trust page, in `VERIFY.md` §6, the site footer and `/.well-known/veilops.json`.

## [0.2.0] - 2026-11-20

### Added

- **On-chain zero-knowledge verification (devnet).** The `onchain/programs/veilops-verifier` Solana program, `4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ`, verifies `veilops-range-v2` range proofs inside the program:
  - every CDS bit proof is checked with the curve25519 multiscalar-multiplication and SHA-256 syscalls
  - both bit decompositions must sum to `C` and `maxAmount·G − C`
  - a `Record` is created only for a fully verified proof, one per operation id

  Three proofs were verified on devnet on 2026-11-20. Two cheating attempts, a tampered proof and a lowered limit, were rejected on-chain with `BitProofInvalid`.
- **`veilops-range-v2`** (`packages/proof-engine/src/v2.ts`): the same statement and generators as v1, re-encoded for on-chain use:
  - a SHA-256 transcript with 512-bit challenge reduction
  - a compact binary encoding (160 bytes per bit)
  - a transcript context the program rebuilds byte for byte from the public inputs
- **Reference vectors** `test-vectors/veilops-range-v2.json`, checked by the TypeScript tests and the independent Python verifier (61/61 cases across v1 and v2).
- **Reproducible program build** (`Program build` workflow): built in the pinned `solanafoundation/solana-verifiable-build:3.1.10` image, with provenance attestation. The deployed binary matches it byte for byte (`scripts/program-hash.ts`).
- **New scripts:**
  - `scripts/onchain-verify.ts` runs proofs through the program.
  - `scripts/onchain-check.ts` re-checks every result from chain data, including off-chain re-verification of the on-chain proof bytes.
- **Privacy scope** on the trust page and in `docs/security.md`: what VEILOPS hides (amounts, encrypted details) and what it does not (sender, timing, asset, limit), with the planned designs for each gap.
- **First Solana devnet anchors.** Six verified sample records were anchored with SPL Memo transactions on 2026-11-20, in slots 524352545–524352580, signed by `9kpS3zvBWmA5jtatwPd4HvbJ1PgazbsBpxQA38grYQie`. `scripts/devnet-verify.ts` confirms all six against a public RPC.
- **`scripts/devnet-sync.ts`** rebuilds the anchor list from the chain, reading only.

### Changed

- The daily devnet workflow also runs `onchain-check.ts`.
- `scripts/reproduce.sh` and the release include the v2 vectors.
- **Solana adapter:** devnet status is now `tested`. The adapter package itself still never sends; transactions are sent by the scripts.
- **`scripts/devnet-anchor.ts`** saves each anchor as soon as its transaction lands and retries on public-RPC rate limits.
- **Strict text-field check:** `validatePublicInputsV2` rejects non-string text fields, a gap the independent verifier found.

## [0.1.1] - 2026-11-20

### Added

- **Reference test vectors** in `test-vectors/veilops-range-v1.json` cover:
  - generators, commitments and Fiat–Shamir challenges
  - 16 range-proof cases and 10 policy-proof cases (valid and tampered)
  - full records

  Checked by `tests/vectors`.
- **Independent verifier** (`verifiers/python`): a standard-library-only Python implementation of:
  - ristretto255
  - RFC 9380 hash-to-curve
  - the range and policy proofs
  - Ed25519
  - record verification

  It is validated against the official RFC 9496 and RFC 8032 vectors and runs in CI on every commit.
- **Reproducible build**:
  - `scripts/reproduce.sh` and a pinned Node version in `.nvmrc`
  - byte-identical package tarballs with published `SHA256SUMS`
  - a CI job that prints the checksums
- **Release workflow** with signed GitHub artifact attestations (build provenance).
- **Solana devnet anchoring tooling**:
  - `scripts/devnet-anchor.ts` publishes SPL Memo anchors for verified sample records.
  - `scripts/devnet-verify.ts` re-checks every anchor against a public RPC.
  - A daily workflow repeats the check.
  - The first devnet anchors are **pending**: no devnet transactions have been published yet.
- **Trust documentation**:
  - `VERIFY.md`: how to check every claim yourself
  - `docs/audit-scope.md`: the package for an external review; status: not yet reviewed
  - `MAINTAINERS.md`
  - this changelog
- **Website**:
  - a `/trust` page
  - a `/.well-known/veilops.json` file listing the official channels
- **Signed commits:** commits and tags are SSH-signed from this release onwards.

### Changed

- **Domain:** the official site is now `https://veilops.tech`.
- **Solana adapter:** unchanged and still sends nothing. Devnet status stays "untested" until the first anchors are published.

## [0.1.0] - 2026-11-20

### Added

- **Proof engine (`veilops-range-v1`):**
  - Pedersen commitments on ristretto255
  - bit-decomposition zero-knowledge range proofs proving `0 ≤ amount ≤ maxAmount`
  - Ed25519 record attestation
- **Encryption:** AES-256-GCM envelopes with X25519 + HKDF key wrapping, and selective disclosure.
- **Policy engine and SDK:** a five-stage pipeline.
- **Website:** explorer over a sample dataset, verification playground, dashboard and documentation.
- **Project setup:**
  - CI: typecheck, lint, tests and build
  - CodeQL and a dependency audit
  - branch protection
