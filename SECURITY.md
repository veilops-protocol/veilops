# Security Policy

## Project status

VEILOPS is **experimental** and **has not been audited** or externally reviewed. There are no releases and no production or mainnet deployments. Do not rely on it to protect real funds or real personal data.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` branch (`0.1.0`, unreleased) | Yes, best effort |
| Anything else | No |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report privately through GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (private vulnerability reporting).
3. Include:
   - the affected package and file, and the commit hash you tested;
   - a description of the issue and its impact (for example: forged proof accepted, amount leaked, envelope opened without a key);
   - a minimal reproduction, ideally as a vitest test;
   - any suggested fix.

A dedicated contact address, `security@veilops.online`, is planned; until it is announced as active, use GitHub Security Advisories only.

## What to expect

- We aim to acknowledge reports within a few days and to keep you informed while we investigate.
- Once a fix is ready we will publish a GitHub Security Advisory and credit you, unless you prefer to remain anonymous.
- Please give us reasonable time to fix the issue before public disclosure. We suggest 90 days, or sooner once a fix is released.

There is **no bug bounty program**. We cannot offer payment for reports.

## Scope

In scope:

- `packages/proof-engine`: soundness or zero-knowledge failures in `veilops-range-v1`, Fiat–Shamir transcript issues, malleability, verifier crashes or acceptance of malformed proofs, attestation bypass.
- `packages/encryption`: confidentiality or integrity failures of envelopes, key-wrap misuse, nonce reuse.
- `packages/policy-engine` and `packages/sdk`: a record that verifies while violating its policy, or plaintext sensitive values appearing in a `PublicRecord`.
- `packages/solana-adapter`: memo construction or parsing flaws.
- `packages/shared`: canonicalization ambiguities that allow two different records to hash or sign identically.
- The CI workflows in `.github/`.

Out of scope:

- Metadata that is documented as public in [docs/security.md](docs/security.md) (category, asset, mode, timestamps, policy limit, commitment, envelope digest, recipient in `amount-only` mode).
- Compromise of the operator's own Ed25519 signing key or X25519 viewing keys.
- The proof size and linear verification cost, which are documented limitations.
- Vulnerabilities in third-party dependencies with no demonstrated impact on VEILOPS (please report those upstream; `npm audit` runs in CI).
- The `apps/website` marketing site, unless it exposes keys or user data.
- Social engineering, denial of service against infrastructure, and physical attacks.

## Safe harbor

We will not pursue action against researchers who act in good faith, avoid privacy violations and data destruction, and give us a reasonable chance to fix issues before disclosure.
