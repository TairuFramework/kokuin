# @kokuin/crypto

Strict asynchronous crypto operations implemented with noble.
This package imports no React Native modules and requires no Rust toolchain.

```ts
import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoProvider } from '@kokuin/crypto'

export async function signMessage(seed: Uint8Array, message: Uint8Array) {
  return nobleCrypto.sign('EdDSA', seed, message)
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

Existing kokuin identity, token, controller and records APIs do not yet accept this provider.
Applications can use its standalone methods or pass the structural contract to their own code.
Native performance and public API migration remain subject to physical-device measurements.
