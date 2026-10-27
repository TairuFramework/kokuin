# Standalone crypto providers

`@kokuin/crypto` exports the `CryptoProvider` contract and strict `nobleCrypto` implementation.
`@kokuin/crypto-native` exports `createNativeCrypto()` for explicit Nitro construction.
Both packages are prepared at version 0.1.0. Publishing is a separate step.

Provider injection into existing token, controller and records APIs remains pending.
Applications can use the standalone methods or accept the structural provider contract in their own code.
Physical-device performance measurements remain pending.

## Installation

After a registry release, portable consumers install `@kokuin/crypto`.
React Native consumers install `@kokuin/crypto-native` and `react-native-nitro-modules@0.37.1`.
Native consumers rebuild their application after installation.
The package includes Rust libraries. Consumers need no Rust toolchain or crate downloads.

Before publication, the native crypto packages workflow produces a `crypto-provider-packages` artifact containing both public tarballs.
Local tarball installations must override the unpublished portable dependency:

```yaml
# Consumer pnpm-workspace.yaml
overrides:
  '@kokuin/crypto': 'file:./kokuin-crypto-0.1.0.tgz'
```

```sh
pnpm add ./kokuin-crypto-0.1.0.tgz
pnpm add ./kokuin-crypto-native-0.1.0.tgz react-native-nitro-modules@0.37.1
```

Portable applications require only the first command.
Registry installations resolve the portable dependency normally after publication.

## Construction and methods

```ts
import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoProvider } from '@kokuin/crypto'
import { createNativeCrypto } from '@kokuin/crypto-native'

const portable: CryptoProvider = nobleCrypto
const native: CryptoProvider = createNativeCrypto()
```

Portable consumers import only the portable package. Its dependency graph contains no Nitro or native binaries.
Noble computes synchronously on the calling thread before returning its Promise.
The native provider copies inputs synchronously and dispatches computation to a native worker.

| Method | Input | Result |
| --- | --- | --- |
| `sign` | `'EdDSA'`, seed, raw message | Signature bytes |
| `signBatch` | `'EdDSA'`, array of `{ privateKey, message }` | Ordered signature arrays |
| `verify` | Algorithm, signature, raw message, public key | Boolean |
| `verifyBatch` | Array of `{ alg, signature, message, publicKey }` | Ordered booleans |
| `blake3` | Input bytes, output length | Hash bytes |
| `blake3Batch` | Array of inputs, shared output length | Ordered hash arrays |

Every result is asynchronous. Empty batches resolve empty arrays, while still validating algorithm and output-length arguments.
Inputs support ordinary `Uint8Array` subarrays. Detached and shared-memory-backed buffers reject with `TypeError`.
Mutations after invocation cannot change the operation's input. Outputs own independent storage.

Ed25519 seeds and public keys contain 32 bytes. Signatures contain 64 bytes.
Verification rejects noncanonical encodings, noncanonical scalars, small-order points and mixed-order points in both A and R.
ES256 accepts compact 64-byte signatures and compressed 33-byte or uncompressed 65-byte SEC1 keys.
It hashes raw messages once with SHA-256 and rejects high-S signatures without normalising them.
Malformed signatures and keys resolve `false`. Unsupported algorithms and invalid signing seeds reject with `TypeError`.
blake3 output lengths must be integers from 1 through 65536. Invalid lengths reject with `RangeError`.

## Native targets and failures

Supported libraries cover iOS 16.4+, arm64 devices, arm64/x86_64 simulators, and Android API 24+, arm64-v8a and x86_64.
The tested peers are React Native 0.88 and Nitro 0.37.1.
Expo applications require a native build rather than Expo Go.

Missing native registration and incompatible ABIs fail construction.
Native execution failures reject their Promises. They never invoke noble as a fallback.
All standalone native operations currently use Rust. Performance-based routing decisions remain pending.
Native seed copies are erased after success, failure or rejected dispatch. JavaScript seed buffers remain caller-owned.

## Consumer verification

From the repository, prepare both platform libraries using the [benchmark build instructions](crypto-benchmark-spike.md).
Build the portable and private conformance packages:

```sh
pnpm --filter @kokuin/crypto-conformance... build
node scripts/verify-crypto-consumer.mjs
```

The verification script packs providers and installs independent portable and mobile fixtures outside the repository.
It checks packed files, published dependency ranges, portable known answers and the absence of Cargo and Nitro in portable execution.
Its final JSON reports fixture paths and a `consumerPATH` containing host tools without Rust.
The mobile fixture runs shared conformance checks against both providers.

Use the reported `consumerPATH` for platform builds:

```sh
PATH='<consumerPATH>' pnpm --dir '<mobile>' exec expo prebuild --no-install
PATH='<consumerPATH>' pnpm --dir '<mobile>/ios' exec pod install
PATH='<consumerPATH>' pnpm --dir '<mobile>' ios:release --device '<simulator-UDID>'
PATH='<consumerPATH>' pnpm --dir '<mobile>' android:release --device '<emulator-serial>'
maestro --device '<device>' test scripts/crypto-consumer/conformance.yaml
```

The native package's prepack checks require matching binary hashes and source fingerprints, generated glue and complete licence notices.
The private conformance package is a test fixture. It is not a published dependency of either provider.

See [consumer verification](crypto-consumer-verification.md) for the recorded build and runtime evidence.
