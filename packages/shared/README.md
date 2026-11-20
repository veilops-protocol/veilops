# @veilops/shared

**Status: implemented.** Not published to npm; consumed as a workspace package.

Types, encoding and identifier helpers shared by every VEILOPS package. It makes no cryptographic decisions.

## Exports

- `PROTOCOL_VERSION` (`'veilops/0.1'`) and `ImplementationStatus` (`implemented | experimental | simulated | planned`).
- Types: `OperationInput` (private input), `PublicRecord` (publishable record), `OperationCategory`, `ConfidentialityMode`, `VerificationStatus`.
- `canonicalJson(value)`: deterministic JSON with recursively sorted keys; `undefined` keys dropped, bigints as strings, non-finite numbers rejected. Everything VEILOPS hashes or signs goes through it.
- `sha256Hex`, `contentId(prefix, content)`, `randomId(prefix)`, `shortHex`.
- `toBase64`, `fromBase64`, and re-exports of `bytesToHex`, `hexToBytes`, `utf8ToBytes`, `randomBytes`, `concatBytes` from `@noble/hashes`.

```ts
import { canonicalJson, contentId } from '@veilops/shared';
canonicalJson({ b: 1, a: 2 });          // '{"a":2,"b":1}'
contentId('pol', { name: 'vendors' });  // 'pol_<20 hex>'
```

See [docs/protocol.md](../../docs/protocol.md) for the `PublicRecord` field reference. License: Apache-2.0.
