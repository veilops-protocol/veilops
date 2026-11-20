# @veilops/encryption

**Status: implemented, unit-tested, not externally reviewed.** Not published to npm.

Envelope encryption for operation details, with selective disclosure. Runs in browsers and Node (requires WebCrypto `crypto.subtle`).

- Payload: AES-256-GCM, random 256-bit data key, random 96-bit nonce, associated data bound to the operation id.
- Key wrapping: per recipient, ephemeral X25519 ECDH, HKDF-SHA256 (`info = "veilops/kek/v1"`) to a key-encryption key, AES-256-GCM wrap of the data key.

## API

| Function | Purpose |
| --- | --- |
| `generateViewingKeyPair()` | X25519 key pair `{ publicKey: hex, secretKey: Uint8Array }` |
| `seal(plaintext, recipients, aad)` | Encrypt for one or more X25519 public keys |
| `open(envelope, secretKey)` / `openText(...)` | Decrypt; throws for non-recipients or tampered data |
| `grantAccess(envelope, ownerSecret, newRecipient)` | Add a reader without re-encrypting the payload |
| `envelopeDigest(envelope)` | SHA-256 over ciphertext, nonce and aad; published in the record. Does not cover key wraps |

```ts
import { generateViewingKeyPair, seal, openText, grantAccess } from '@veilops/encryption';

const owner = generateViewingKeyPair(), auditor = generateViewingKeyPair();
const env = await seal('amount=4200', [owner.publicKey], 'op_1');
const shared = await grantAccess(env, owner.secretKey, auditor.publicKey);
await openText(shared, auditor.secretKey); // 'amount=4200'
```

Limitations: no sender authentication inside the envelope, no forward secrecy, no revocation. See [docs/cryptography.md](../../docs/cryptography.md#6-envelope-encryption). License: Apache-2.0.
