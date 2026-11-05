# @kokuin/crypto-napi

Strict asynchronous crypto provider for Node.js, backed by the kokuin Rust core (`crates/kokuin-crypto`) through Node-API.
It implements the `@kokuin/crypto` `CryptoProvider` contract and falls back to `@kokuin/crypto-node` when no native binary loads.

```ts
import { createNapiCrypto } from '@kokuin/crypto-napi'

const crypto = createNapiCrypto()
crypto.backend // 'napi', or 'node' after a fallback; `crypto.failure` then says why
const signature = await crypto.sign({ alg: 'EdDSA', privateKey: seed, message })
```

| Call | Route |
| --- | --- |
| Ed25519 `sign`, Ed25519 `verify`, `blake3` | Native, on the calling thread |
| ES256 `verify` and ES256 items of `verifyBatch` | `nodeCrypto` (OpenSSL), about three times faster than the Rust P-256 verifier |
| `verifyBatch` with two or more Ed25519 items | Native on the libuv thread pool; inputs are copied before the Promise returns |
| One-item `verifyBatch`, `signBatch` up to 32 items, `blake3Batch` up to 1 MiB | Native, on the calling thread, where the pool hop costs more than it saves |
| Larger `signBatch` and `blake3Batch` | Native on the libuv thread pool |

The routes come from the [Node crypto benchmark gate](../../docs/reference/crypto-node-benchmark.md).

Measured through the provider on one x86_64 container with Node 22, against strict noble:
Ed25519 signing is about 18× faster, Ed25519 verification about 25×, and blake3 on 64 KiB about 110×.
A batch of 32 Ed25519 verifications costs about 113 µs per item and keeps the event loop free.

The backend is chosen once, when `createNapiCrypto()` runs. A missing binary, a binary built for another ABI version
or one that fails to load selects `nodeCrypto`. A native failure after construction rejects; it never falls back.

Arguments are validated in JavaScript exactly as `nobleCrypto` validates them, so every backend raises the same errors.
Every backend accepts and rejects exactly the same signatures: the shared corpus and the pinned upstream vectors run
against the Rust core, strict noble, `nodeCrypto` and this provider.

Prebuilt binaries are not published yet. In this repository, `pnpm --filter @kokuin/crypto-napi run build:native`
compiles one for the current host into `native/`. Requires Node.js 22 or later.

## Named params migration

`CryptoProvider.verify` now accepts one `VerifyItem`: `{ alg, signature, message, publicKey }`.
`sign`, `signBatch`, `blake3` and `blake3Batch` take flat params objects.
`verifyBatch` retains its single array argument.

| Export | Named params type | Fields |
| --- | --- | --- |
| `NapiBinding.sign` | `NapiBindingSignParams` | `seed, message` |
| `NapiBinding.signBatch` | `Array<NapiBindingSignParams>` | `seeds, messages` |
| `NapiBinding.blake3` | `NapiBindingBlake3Params` | `input, length` |
| `NapiBinding.blake3Batch` | `NapiBindingBlake3BatchParams` | `inputs, length` |
| `NapiBinding.verify` | `NapiVerifyParams` | `es256, signature, message, publicKey` |
| `NapiBinding.verifyBatch` | `Array<NapiVerifyParams>` | `es256, signatures, messages, publicKeys` |

`NapiBinding` accepts named signing, hashing and verification objects. The loader adapts them to the unchanged positional native ABI.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

| API | Named params type | Previous positional form |
| --- | --- | --- |
| `CryptoProvider.sign` | `CryptoProviderSignParams` | `sign(alg, privateKey, message)` |
| `CryptoProvider.signBatch` | `CryptoProviderSignBatchParams` | `signBatch(alg, items)` |
| `CryptoProvider.blake3` | `CryptoProviderBlake3Params` | `blake3(input, dkLen)` |
| `CryptoProvider.blake3Batch` | `CryptoProviderBlake3BatchParams` | `blake3Batch(inputs, dkLen)` |
