# @kokuin/crypto-native

An explicit Nitro provider for Ed25519 signing and verification, ES256 verification and blake3 hashing.
The package implements `CryptoProvider` from `@kokuin/crypto`.
It runs cryptographic work on a native worker and returns Promises.

This provider is experimental. The complete physical-device benchmark gate remains pending.
Correctness checks on simulators and emulators do not establish latency improvements.

After publication, install the provider and its tested Nitro peer:

```sh
pnpm add @kokuin/crypto-native react-native-nitro-modules@0.37.1
```

Rebuild the native application after installation. Expo Go cannot load this module.
Consumers link the shipped Rust libraries without installing Cargo, rustup or a Rust toolchain.

```ts
import { createNativeCrypto } from '@kokuin/crypto-native'

const crypto = createNativeCrypto()

export async function signMessage(seed: Uint8Array, message: Uint8Array) {
  return crypto.sign('EdDSA', seed, message)
}
```

Construction throws when native registration is missing or the ABI is incompatible.
Native errors reject the operation. They never trigger fallback to noble.
Every operation uses the native implementation, including every item in a batch.
No operation routes have been selected through performance measurements yet.

Supported targets are iOS 16.4+, arm64 devices and arm64/x86_64 simulators, and Android API 24+, arm64-v8a and x86_64.
The tested JavaScript peers are React Native 0.88 and Nitro 0.37.1.
Applications still need their platform's normal Xcode or Android build environment.
Android builds honour the supported subset requested through `reactNativeArchitectures`, including ARM64-only physical-device builds.

Inputs preserve byte offsets and lengths. Native owners copy them synchronously before dispatch.
Seed-bearing native copies are erased on success, failure and rejected dispatch.
JavaScript seed buffers remain caller-owned. Returned output buffers retain their Rust allocation until released.

The portable package documents the shared verification, encoding, batch and argument-validation contract.
Existing kokuin identity, token, controller and records APIs have not yet migrated to provider injection.

Repository maintainers must build both platform libraries before packing.
The prepack check rejects missing or stale binaries and includes dependency licence notices.
Publishing remains a separate action from building or packing this branch.
