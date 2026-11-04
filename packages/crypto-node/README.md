# @kokuin/crypto-node

Strict asynchronous crypto provider for Node.js.
It implements the `@kokuin/crypto` `CryptoProvider` contract, using `node:crypto` (OpenSSL) where it can meet that contract.
It needs no native addon, no Rust toolchain and no install scripts.

```ts
import { nodeCrypto } from '@kokuin/crypto-node'

const signature = await nodeCrypto.sign('EdDSA', seed, message)
```

| Operation | Backend | Why |
| --- | --- | --- |
| Ed25519 signing | `node:crypto` | Deterministic under RFC 8032, so its output is byte-identical to noble's. |
| ES256 verification | `node:crypto`, plus a low-S check | OpenSSL checks the scalar ranges and the curve; it accepts high-S signatures, so the provider rejects them first. |
| Ed25519 verification | strict noble | OpenSSL accepts small-order and mixed-order points that the contract rejects. |
| blake3 | strict noble | `node:crypto` has no blake3. |

Measured on one x86_64 container with Node 22, including key import on every call: Ed25519 signing is about 8× faster than noble, and ES256 verification about 15× faster.
Ed25519 verification and blake3 run at noble speed.

Inputs, errors and batch semantics match `nobleCrypto`.
Every method consumes its inputs before its Promise returns, and outputs are plain, independently owned `Uint8Array`s.
Computation still runs synchronously on the calling thread.

Signing imports each seed into an OpenSSL key object and zeroes its own DER copy afterwards.
OpenSSL keeps its copy until the key object is garbage-collected, just as noble leaves key material on the JavaScript heap.

Requires Node.js 22 or later. Electron, Bun and Deno ship different `node:crypto` implementations and are untested.
Existing kokuin identity, token, controller and records APIs do not yet accept a provider.
