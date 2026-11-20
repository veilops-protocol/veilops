#!/usr/bin/env bash
# Reproduce the VEILOPS release artifacts from source and print their SHA-256 checksums.
#
#   git clone https://github.com/veilops-protocol/veilops && cd veilops
#   git checkout <tag>            # e.g. v0.1.1
#   bash scripts/reproduce.sh
#
# Compare dist/SHA256SUMS with the SHA256SUMS file attached to the GitHub release (and the CI job summary).
# The package tarballs are byte-for-byte reproducible with the pinned Node/npm version in .nvmrc.
# The Next.js website build is NOT bit-for-bit reproducible (build ids, timestamps) and is not part of the sums.
set -euo pipefail
cd "$(dirname "$0")/.."

want="v$(cat .nvmrc)"
have="$(node -v)"
if [ "$have" != "$want" ]; then
  echo "Node $want is required for byte-identical tarballs (found $have). Try: nvm install && nvm use" >&2
  exit 1
fi
echo "toolchain: node $have, npm $(npm -v)"

echo "== install (lockfile only)"; npm ci --no-audit --no-fund >/dev/null
echo "== typecheck";  npm run -s typecheck
echo "== lint";       npm run -s lint
echo "== tests";      npm test --silent
if command -v python3 >/dev/null; then
  echo "== independent Python verifier"; python3 verifiers/python/veilops_verify.py test-vectors/veilops-range-v1.json --quiet
else
  echo "== python3 not found: skipping the independent verifier (CI always runs it)"
fi

echo "== pack"
rm -rf dist && mkdir -p dist
for p in shared encryption policy-engine proof-engine sdk solana-adapter; do
  npm pack -w "packages/$p" --pack-destination dist --silent >/dev/null
done
cp test-vectors/veilops-range-v1.json dist/
( cd dist && shasum -a 256 *.tgz veilops-range-v1.json > SHA256SUMS 2>/dev/null || sha256sum *.tgz veilops-range-v1.json > SHA256SUMS )
echo "== dist/SHA256SUMS"; cat dist/SHA256SUMS
echo "source commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
