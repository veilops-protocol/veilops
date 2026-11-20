# Contributing to VEILOPS

Thank you for considering a contribution. VEILOPS is early (Phase 01, experimental), so reviews, bug reports and careful questions are as valuable as code.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

1. **Security issues are never filed publicly.** Use the private process in [SECURITY.md](SECURITY.md).
2. **Honesty over polish.** Never upgrade a status label (`planned` → `experimental` → `implemented`) without code and tests that justify it. Do not describe the attestation signature as a zero-knowledge proof, do not call the range proof succinct or audited, and do not claim network deployments that have not happened. The `ImplementationStatus` type in `@veilops/shared` defines the labels.
3. **No new cryptographic primitives by hand.** Build on `@noble/curves`, `@noble/hashes` and WebCrypto. Changes to a proof system or transcript require a new version identifier (for example `veilops-range-v2`) rather than silently changing `veilops-range-v1`.
4. **Small, focused pull requests** with tests.

## Development setup

```bash
nvm use            # Node 22, from .nvmrc
npm ci
npm test           # vitest
npm run typecheck  # tsc over packages, tests, scripts, examples (+ website)
npm run lint       # eslint over packages, tests, examples, scripts
```

Run an example end to end:

```bash
npx tsx examples/basic-operation.ts
npx tsx examples/selective-disclosure.ts
```

See the [developer guide](docs/developer-guide.md) for the package layout and APIs.

## Making a change

1. Open an issue first for anything larger than a small fix, so the approach can be agreed before you invest time.
2. Fork the repository and create a branch: `feat/<short-name>`, `fix/<short-name>` or `docs/<short-name>`.
3. Write or update tests:
   - `tests/unit/` for a single package,
   - `tests/integration/` for the SDK lifecycle,
   - `tests/security/` for tampering, malformed input and negative cases. Every verifier change needs a negative test.
4. Make sure `npm run typecheck`, `npm run lint` and `npm test` pass locally.
5. Update the relevant document in `docs/` when behaviour, record format or security properties change.
6. Open a pull request using the template and describe what changed, why, and how it was tested.

## Commit messages

Use the imperative mood and a short scope prefix, for example:

```text
proof-engine: reject proofs whose bit count differs from rangeBits
docs: clarify metadata exposure in amount-only mode
```

## Coding conventions

- TypeScript, ES modules, `strict` and `noUncheckedIndexedAccess` enabled (see `tsconfig.base.json`).
- Formatting follows `.editorconfig`: 2 spaces, LF, UTF-8, final newline.
- Verifiers must never throw on malformed input; they return `false` or an invalid report.
- Secret scalars use constant-time multiplication (`mulSecret`); variable-time helpers (`mulPublic`) are for public values only.
- No network calls and no key persistence inside the packages.
- Anything that is hashed or signed goes through `canonicalJson`.

## Reviews

Maintainers aim to give a first response to issues and pull requests, but there is no guaranteed turnaround while the project is small. Cryptography-related changes need at least one reviewer who is not the author.

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the license of this project.
