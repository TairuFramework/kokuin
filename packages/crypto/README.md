# @kokuin/crypto

Strict asynchronous crypto operations implemented with noble.
This package imports no React Native modules and requires no Rust toolchain.

```ts
import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoProvider } from '@kokuin/crypto'

export async function signMessage(seed: Uint8Array, message: Uint8Array) {
  return nobleCrypto.sign({ alg: 'EdDSA', privateKey: seed, message })
}
```

`CryptoProvider` supplies `sign`, `signBatch`, `verify`, `verifyBatch`, `blake3` and `blake3Batch`.
All methods return Promises. Noble computation still runs synchronously on the calling thread.
Inputs are consumed before the Promise returns, preserving caller mutations after invocation.

Ed25519 signing accepts 32-byte seeds. Verification rejects noncanonical encodings and small-order or mixed-order points.
ES256 verification accepts compact 64-byte signatures and compressed or uncompressed SEC1 keys.
It hashes raw messages exactly once with SHA-256 and rejects high-S signatures.
Malformed signatures or keys resolve `false`. Unsupported algorithms reject with `TypeError`.
Detached buffers and shared buffers reject with `TypeError`.

blake3 output lengths must be integers from 1 through 65536. Invalid lengths reject with `RangeError`.
Empty batches resolve empty arrays. Batch results preserve input order and own independent output storage.

Identity, token, controller, records and vault APIs accept this provider through explicit options.
Applications can use its standalone methods or pass the structural contract to their own code.
Native route qualification still requires stored measurements and final physical-device retesting.

## Provider adoption

Identity, controller, record and vault APIs now accept this provider contract.
The six methods remain asynchronous. Verification now takes a named object. Strict noble caches public-key validation in a bounded 256-entry cache.
Every signature point still receives strict validation. Applications must keep provider behaviour immutable throughout its lifetime.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

`CryptoProvider.verify` now accepts one `VerifyItem`: `{ alg, signature, message, publicKey }`.
`sign`, `signBatch`, `blake3` and `blake3Batch` take flat params objects.
`verifyBatch` retains its single array argument.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

| API | Named params type | Previous positional form |
| --- | --- | --- |
| `CryptoProvider.sign` | `CryptoProviderSignParams` | `sign(alg, privateKey, message)` |
| `CryptoProvider.signBatch` | `CryptoProviderSignBatchParams` | `signBatch(alg, items)` |
| `CryptoProvider.blake3` | `CryptoProviderBlake3Params` | `blake3(input, dkLen)` |
| `CryptoProvider.blake3Batch` | `CryptoProviderBlake3BatchParams` | `blake3Batch(inputs, dkLen)` |
