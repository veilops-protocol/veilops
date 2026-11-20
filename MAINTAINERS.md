# Maintainers

VEILOPS is maintained **pseudonymously**. We do not publish real names. Instead of asking you to trust identities, the project gives you continuity you can verify yourself:

| Maintainer | GitHub | Role | Commit-signing key (SSH, ed25519) |
| --- | --- | --- | --- |
| veilopsonline | [@veilopsonline](https://github.com/veilopsonline) | Lead maintainer: protocol, cryptography, website | `SHA256:0q/tLTLWz3mdlXFnfCcJbDYeJ7nHnGu37TaBa/h96m8` |

## How to check that a change really comes from the maintainers

1. **Signed commits and tags.** From v0.1.1 onwards, every commit and tag on `main` is signed with the key above, and GitHub shows it as **Verified**. A change signed with a different key does not come from this maintainer. The key is published in [`.github/allowed_signers`](.github/allowed_signers): `git -c gpg.ssh.allowedSignersFile=.github/allowed_signers log --show-signature`.
2. **Build provenance.** Release files carry a GitHub artifact attestation that ties them to a workflow run of `veilops-protocol/veilops`. See [VERIFY.md §4](VERIFY.md#4-build-provenance).
3. **Two-way links.** <https://veilops.tech> links to the GitHub organization, and the organization links back. The list of official channels lives in [VERIFY.md §6](VERIFY.md#6-official-channels) and <https://veilops.tech/.well-known/veilops.json>. Changes to that list are only valid in a signed commit.
4. **History.** [CHANGELOG.md](CHANGELOG.md) records every release with its date. The project started on 2026-11-20; there is no older history.

## Key changes

If the signing key ever changes, the old key will sign a commit announcing the new one, and this file will list both. A key that appears without that announcement is not ours.

## Contact

- **Security issues:** [private vulnerability reporting](https://github.com/veilops-protocol/veilops/security/advisories/new)
- **Everything else:** GitHub issues on [veilops-protocol/veilops](https://github.com/veilops-protocol/veilops/issues)
