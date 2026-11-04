# @kokuin/crypto-napi

Strict asynchronous crypto provider for Node.js, backed by the kokuin Rust core (`crates/kokuin-crypto`) through Node-API.
It implements the `@kokuin/crypto` `CryptoProvider` contract and falls back to `@kokuin/crypto-node` when no native binary loads.

```ts
import { createNapiCrypto } from '@kokuin/crypto-napi'

const crypto = createNapiCrypto()
crypto.backend // 'napi', or 'node' after a fallback; `crypto.failure` then says why
const signature = await crypto.sign('EdDSA', seed, message)
```

| Call | Route |
| --- | --- |
| Ed25519 `sign`, Ed25519 `verify`, `blake3` | Native, on the calling thread |
| ES256 `verify` | `nodeCrypto` (OpenSSL), which is faster than the Rust P-256 verifier |
| `signBatch`, `verifyBatch`, `blake3Batch` | Native on the libuv thread pool; inputs are copied before the Promise returns |

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
