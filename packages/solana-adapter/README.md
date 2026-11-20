# @veilops/solana-adapter

**Status: experimental. Never sends a transaction itself. Tested on devnet (6 anchors via `scripts/devnet-anchor.ts`); not on testnet or mainnet.** Not published to npm.

Builds an SPL Memo instruction that anchors a VEILOPS record:

```text
veilops:<version>:<proofId>:<sha256(canonicalJson(record))>
```

so that a record's existence could later be checked against a slot. Signing and sending stay with the caller's wallet.

```ts
import { buildAnchorInstruction, anchorMemo, parseAnchorMemo, recordDigest, MEMO_PROGRAM_ID, CLUSTER_STATUS } from '@veilops/solana-adapter';

const ix = buildAnchorInstruction(record, signerBase58);
// ix = { programId: MEMO_PROGRAM_ID, keys: [{ pubkey: signer, isSigner: true, isWritable: false }], data }
// Convert to your Solana client's instruction type yourself.
parseAnchorMemo(anchorMemo(record)); // { version, proofId, digest }
CLUSTER_STATUS; // { devnet: 'tested', testnet: 'untested', 'mainnet-beta': 'untested' }
```

On-chain proof verification lives in [`onchain/`](../../onchain) (the `veilops-verifier` program, devnet). Planned: Token-2022 confidential transfer integration. License: Apache-2.0.
