# Standalone crypto providers

`@kokuin/crypto` exports the `CryptoProvider` contract and strict `nobleCrypto` implementation.
`@kokuin/crypto-native` exports `createNativeCrypto()` for explicit Nitro construction.
Both packages are prepared at version 0.1.0. Publishing is a separate step.

Token identities, token verification, capabilities, revocations and JWE envelope verification accept provider injection.
Controller and records provider migration remains pending.
Applications can use the standalone methods or accept the structural provider contract in their own code.
The complete physical-device benchmark gate remains pending.
An [exploratory physical Android probe](crypto-benchmarks/2026-10-27-android-probe/README.md) records initial results.

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

## Identity and token provider selection

All default routes use strict `nobleCrypto`. Native routing awaits a stored, measured route manifest.
There is no mutable global provider selection or dynamic fallback.

```ts
import { nobleCrypto } from '@kokuin/crypto'
import { createSigningIdentity, verifyToken } from '@kokuin/token'

const identity = createSigningIdentity(seed, { crypto: nobleCrypto })
const signed = await identity.signToken({ aud: serviceDID })
const verified = await verifyToken(signed, { crypto: nobleCrypto, audience: serviceDID })
```

`CryptoOptions` is exported from token and contains `crypto?: CryptoProvider`.
`createSigningIdentityForDID`, `createSigningIdentity`, `createFullIdentity` and `randomIdentity` accept appended options.
`createIdentity` accepts `crypto` in its input object. Identity construction retains its existing return type.
Each identity captures its provider. `signToken` always uses the supplied identity's signer.
Public-key derivation, key agreement, randomness, browser WebCrypto signing and Ledger signing retain their existing paths.

`VerifyTokenOptions` and `VerifySignedPayloadInput` accept `crypto`.
`getVerifier(algorithm, verifiers?, options?)` uses an override first, then the selected provider for any missing algorithm.
Custom overrides own their verification policy and bypass the signature memo.
Mutating an override object during verification cannot change the captured policy.

Signature memo entries share aggregate count and byte bounds across providers and algorithms.
Only successful verification is cached. Provider failures propagate and remain retryable.
Verified token objects retain provider, verifier and resolution provenance.
Cross-policy use re-verifies them. Time, audience, historic-key and mutation checks still apply.
`isVerifiedToken` indicates prior verification, without promising acceptance under another policy.

## Capability and envelope options

Pass `crypto` through `CreateCapabilityOptions` for parent verification and `DelegationChainOptions` for chain checks.
Capability creation still signs through its supplied identity.
`RevocationOptions` captures `crypto` in both memory-backend and checker construction.
Revocation verification always retains `historic: true`. Operational provider errors propagate unchanged through invalid-record refusal paths.

`UnwrapOptions` accepts `crypto` for JWS, JWS-in-JWE and JWE-in-JWS verification.
`WrapOptions` remains signer-driven. Encryption and key agreement do not use this provider.

This coordinated 0.x minor cutover rejects crafted signatures previously accepted only under ZIP-215 when reverified.
No historical rescan, compatibility switch or version gate is introduced.
Canonical signing bytes and ordinary deterministic signatures remain unchanged.
Strict subgroup checks can increase pure-JavaScript verification cost.
Expanded conformance and final physical workload retesting remain release qualifications.

## Shared corpus and backend agreement

`packages/crypto-conformance/vectors/corpus.json` holds every pure-data case with its expected outcome.
It covers Ed25519 signing, invalid seeds, Ed25519 and ES256 verification, blake3 known answers and invalid output lengths.
Batch membership, snapshot, ownership and argument-validation cases remain TypeScript code in `cryptoConformance`.

The Rust crypto checks workflow (`.github/workflows/crypto-rust.yml`) enforces two runs of the same file on every pull request:

- `cargo test --workspace --locked --offline` runs `crates/kokuin-crypto/tests/corpus.rs` against the Rust core.
- `pnpm --filter @kokuin/crypto-conformance run test` runs `cryptoConformance(nobleCrypto)`.

Both runs assert the recorded outcome for every vector, so noble and the Rust core agree on the whole corpus.
CI does not run the corpus through the Nitro provider. The Expo end-to-end app and the packed mobile consumer run it on devices.

Every rejected vector names, per backend, the deliberately weakened verifiers that accept it.
Each side rebuilds its verifier with exactly one guard removed.
It asserts that the failing vectors are exactly those naming that weakening.

| Guard | Noble weakening | Rust weakening |
| --- | --- | --- |
| Ed25519 subgroup check on A | `subgroup-a` | `subgroup` (dalek `verify_strict` alone) |
| Ed25519 subgroup check on R | `subgroup-r` | Not isolable: a cofactorless check rejects a torsioned R when A is torsion-free |
| Ed25519 canonical S | `s-range` | `s-range` |
| ES256 low-S | `low-s` | `low-s` |
| ES256 r and s below n | `scalar-range` | `scalar-range` |
| ES256 non-zero r and s | `zero-scalars` (CVE-2022-21449 inverse) | Not implemented |

Rust additionally checks that an unguarded cofactored verifier accepts every Ed25519 forgery.
This proves that the k ≢ 0 (mod 4) mixed-order and small-order vectors are real forgeries, even though dalek's cofactorless equation rejects them too.
Only the k ≡ 0 (mod 4) mixed-order key vector certifies the Rust subgroup guard.

Some guards have no single-guard vector.
Every non-canonical Ed25519 encoding decodes to a small-order or torsioned point, so the canonical-encoding check is never the sole guard.
ES256 r = 0 or s = 0 alone also fails the verification equation.

## Native targets and failures

Supported libraries cover iOS 16.4+, arm64 devices, arm64/x86_64 simulators, and Android API 24+, arm64-v8a and x86_64.
The tested peers are React Native 0.88 and Nitro 0.37.1.
Expo applications require a native build rather than Expo Go.

Missing native registration and incompatible ABIs fail construction: `createNativeCrypto()` throws, and
nothing fails earlier. Android ships `libKokuinCrypto.so` only for arm64-v8a and x86_64; other entries in
`reactNativeArchitectures` are dropped from the native build, so armeabi-v7a and x86 APK slices omit the library.
On such a device `CryptoPackage` catches the `UnsatisfiedLinkError`, logs it and lets the app start, so apps that
never call `createNativeCrypto()` are unaffected. The Android build fails only when `reactNativeArchitectures`
names neither arm64-v8a nor x86_64. iOS links the library statically, so a missing slice fails at link time.
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
