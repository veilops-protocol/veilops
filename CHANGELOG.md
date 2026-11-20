# Changelog

All notable changes to VEILOPS. Dates are UTC. The project follows [Semantic Versioning](https://semver.org); everything below 1.0 is experimental.

## [Unreleased]

### Added

- **First Solana devnet anchors.** Six verified sample records were anchored with SPL Memo transactions on 2026-11-20, in slots 524352545–524352580, signed by `9kpS3zvBWmA5jtatwPd4HvbJ1PgazbsBpxQA38grYQie`. `scripts/devnet-verify.ts` confirms all six against a public RPC, and the daily **Devnet anchors** workflow repeats that check.
- **`scripts/devnet-sync.ts`** rebuilds the anchor list from the chain, reading only.

### Changed

- **Solana adapter:** devnet status is now `tested`. The adapter package itself still never sends; transactions are sent by `scripts/devnet-anchor.ts`.
- **`scripts/devnet-anchor.ts`** saves each anchor as soon as its transaction lands and retries on public-RPC rate limits.

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
