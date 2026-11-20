# @veilops/policy-engine

**Status: implemented, unit-tested.** Not published to npm.

Declarative policies for confidential operations. A policy has:

- **public rules** anyone can check from a `PublicRecord`: `category.allowed`, `asset.allowed`, `mode.minimum`;
- **confidential rules** checked by the operator on plaintext: `amount.integer` and `amount.withinLimit`. The limit rule is also enforced publicly by the `veilops-range-v1` range proof from `@veilops/proof-engine`, without revealing the amount.

## API

```ts
import { definePolicy, evaluate, evaluatePublic, policyId } from '@veilops/policy-engine';

const policy = definePolicy({
  name: 'vendors',
  maxAmount: 1_000_000,          // required; < 2^rangeBits
  allowedCategories: ['vendor'], // default: all five categories
  allowedAssets: ['USDC'],       // default: USDC, SOL, USDT, PYUSD
  minimumMode: 'amount-and-recipient', // default: amount-only
  rangeBits: 32,                 // default 32, allowed 1..48
});

evaluate(policy, input);         // { policyId, passed, checks[] } on plaintext
evaluatePublic(policy, record);  // public rules only
policyId(policy);                // 'pol_' + 16 hex of SHA-256(canonicalJson(policy))
```

`definePolicy` and `validatePolicy` throw on invalid policies. Note that only `policy.id`, `maxAmount` and `rangeBits` are published in a record, so a verifier cannot recompute the id without the full policy. License: Apache-2.0.
