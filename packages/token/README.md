# @kokuin/token

## Installation

```sh
npm install @kokuin/token
```

## Crypto provider migration to 0.7.0

`CryptoOptions` exports `{ crypto?: CryptoProvider }`.
`createSigningIdentityForDID(id, privateKey, options?)`, `createSigningIdentity(privateKey, options?)`,
`createFullIdentity(privateKey, options?)` and `randomIdentity(options?)` capture the selected provider.
They retain their synchronous return contracts. `createIdentity(input)` gains `input.crypto?` and remains asynchronous.
`signToken` uses the identity's captured signer without a per-token provider override.

`VerifyTokenOptions` and `VerifySignedPayloadInput` gain `crypto?`.
`getVerifier(algorithm, verifiers?, options?)` appends provider options and retains its return type.
Custom algorithm overrides take precedence and own their policy. Missing overrides use strict `nobleCrypto` by default.
Verification caches isolate provider, verifier and resolution policy. Cross-policy verified objects require reverification.
`isVerifiedToken` indicates prior verification, not acceptance under every policy.
Provider errors propagate unchanged. Strict verification rejects crafted signatures previously accepted only under ZIP-215.
There is no historical rescan or version gate.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new UnresolvableIssuerError` | `UnresolvableIssuerErrorParams` | `message, options?` |
| `new IssuerKeyNotFoundError` | `IssuerKeyNotFoundErrorParams` | `message, options?` |

`Identity.id` and `KeyEntry.keyID` no longer use TypeScript `readonly`. Existing runtime getters remain unchanged.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
