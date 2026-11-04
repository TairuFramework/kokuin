# @kokuin/controller

## Installation

```sh
npm install @kokuin/controller
```

## Crypto provider migration to 0.3.0

Signing, verification, folding, history, log helpers, device revocation and controller identity construction now return Promises.
Positional APIs append `CryptoOptions`. Existing builder parameter objects gain `crypto?: CryptoProvider`.
`createControllerResolver` remains synchronous and captures `crypto?` alongside `loadLog` and `history?`.
`provideControllerIdentity` remains asynchronous and now forwards `crypto?`.
`didFor`, `didFromInception`, canonicalisation, derivation, SHA-256 digests and profile enumeration remain synchronous.

The [complete Promise migration list](../../docs/reference/crypto-provider.md#controller-promise-migration) includes public and internal source-module operations.
Strict default verification rejects crafted ZIP-215-only signatures on reverification. No historical rescan or version gate is introduced.
Success memos isolate providers. Stored epoch authentication remains a trusted-storage boundary, without provider-switch reauthentication.
Provider failures propagate unchanged and remain retryable.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `deriveKeyMaterial` | `DeriveKeyMaterialParams` | `seed, path, alg, length?` |
| `mergeLogs` | `MergeLogsParams` | `did, left, right, options?` |
| `verifySignatures` | `VerifySignaturesParams` | `event, sigs, keys, options?` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?, options?` |
| `deviceRevokeIndices` | `DeviceRevokeIndicesParams` | `did, chain, subject, options?` |
| `deviceRevokeIndex` | `DeviceRevokeIndexParams` | `did, chain, subject, options?` |

`EpochSignatureSigner` names the existing root-or-member signer union for `verifyEpochSignature`.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
