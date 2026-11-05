# Crypto providers and adoption

`@kokuin/crypto` exports the `CryptoProvider` contract and strict `nobleCrypto` implementation.
`@kokuin/crypto-native` exports `createNativeCrypto()` for explicit Nitro construction.
`@kokuin/crypto-node` exports `nodeCrypto`, which runs part of the contract on `node:crypto` (see [Node provider](#node-provider)).
`@kokuin/crypto-napi` exports `createNapiCrypto()`, the Rust core through Node-API (see [Node-API provider](#node-api-provider)).
All four packages are prepared at version 0.1.0. Publishing is a separate step.

Token identities, token verification, capabilities, revocations and JWE envelope verification accept provider injection.
Controller, records, vault and software identity stores also accept provider injection.
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
| `verify` | `VerifyItem`: `{ alg, signature, message, publicKey }` | Boolean |
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

## Node provider

`nodeCrypto` from `@kokuin/crypto-node` runs Ed25519 signing and ES256 verification through `node:crypto`.
Ed25519 verification and blake3 delegate to strict noble.
OpenSSL accepts small-order and mixed-order Ed25519 points that the contract rejects, and `node:crypto` has no blake3.
Ed25519 signing is deterministic, so OpenSSL and noble produce identical signatures.
OpenSSL accepts high-S ES256 signatures, so the provider rejects the high half before calling it.
OpenSSL itself enforces non-zero in-range scalars, curve membership and the ECDSA equation.

The provider passes the shared conformance suite. Its tests also compare it with strict noble on random inputs,
including high-S, mutated-message and wrong-key cases, and show that OpenSSL alone accepts the high-S corpus vector.
With key import on every call, Ed25519 signing measured about 8× and ES256 verification about 15× faster than noble
on one x86_64 container with Node 22. It needs no native addon and runs synchronously on the calling thread.

## Node-API provider

`createNapiCrypto()` from `@kokuin/crypto-napi` loads `crates/kokuin-crypto-napi`, a napi-rs binding over the Rust core.
The [Node crypto benchmark gate](crypto-node-benchmark.md) set its routes:

- Ed25519 sign and verify and blake3 single calls run natively on the calling thread.
- ES256 verification, single or batched, uses `nodeCrypto`, whose OpenSSL verifier is about three times faster than the Rust one.
- Ed25519 verify batches of two or more run natively on the libuv pool, after copying their inputs on the calling thread.
- One-item verify batches, sign batches of up to 32 items, and blake3 batches of up to 1 MiB run natively on the calling thread.
  There, the pool hop costs more than it saves.

The backend is chosen once, at construction. A missing binary, an ABI mismatch or a load error selects `nodeCrypto`,
and the returned provider reports `backend: 'node'` with the failure. Unlike the mobile provider, Node falls back,
because it has a conformant pure-JavaScript route and an unsupported platform must not fail installation.
A native failure after construction rejects without falling back.

Through the provider on one x86_64 container with Node 22: Ed25519 signing about 18× faster than strict noble,
Ed25519 verification about 25×, blake3 on 64 KiB about 110×, and a batch of 32 Ed25519 verifications about 113 µs per item.
The Rust crypto checks workflow builds the binding and runs both conformance suites through it.
The benchmark gate runs on x86_64 and arm64 CI runners. Prebuilt per-platform binaries are follow-up work.

## Identity and token provider selection

Omitting `crypto` selects strict `nobleCrypto`. Node and native providers are selected explicitly.
There is no mutable global provider selection, and a provider never changes behaviour after construction.

```ts
import { nobleCrypto } from '@kokuin/crypto'
import { createSigningIdentity, verifyToken } from '@kokuin/token'

const identity = createSigningIdentity({ privateKey: seed, crypto: nobleCrypto })
const signed = await identity.signToken({ payload: { aud: serviceDID } })
const verified = await verifyToken({ token: signed, crypto: nobleCrypto, audience: serviceDID })
```

`CryptoOptions` is exported from token and contains `crypto?: CryptoProvider`.
`createSigningIdentityForDID`, `createSigningIdentity`, `createFullIdentity` and `randomIdentity` accept top-level params fields.
`createIdentity` accepts `crypto` in its input object. Identity construction retains its existing return type.
Each identity captures its provider. `signToken` always uses the supplied identity's signer.
Public-key derivation, key agreement, randomness, browser WebCrypto signing and Ledger signing retain their existing paths.

`VerifyTokenOptions` and `VerifySignedPayloadInput` accept `crypto`.
`getVerifier(params: GetVerifierParams)` uses an override first, then the selected provider for any missing algorithm.
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

## Pinned upstream vectors

`packages/crypto-conformance/vectors/external.json` adds pinned upstream sets to the hand-written corpus:

| Set | Cases | Expected outcome |
| --- | --- | --- |
| Wycheproof Ed25519 | 210 | `valid` accepts. `invalid` and `acceptable` reject, since `acceptable` means a small-order or mixed-order key. |
| Wycheproof ECDSA P-256 (P1363) | 262, each with uncompressed and compressed keys | `valid` accepts unless s > n / 2. `invalid` rejects. 70 upstream-valid signatures are high-S. |
| SUPERCOP Ed25519 `sign.input`, including RFC 8032 TEST 1–3 | 94 signatures, each also verified | Exact signature bytes, then acceptance. |
| Official blake3 | 35 input lengths, 0 to 102,400 bytes | The first 32 and 131 output bytes. |

Expected outcomes come from upstream verdicts and this policy, never from a provider.
`scripts/import-crypto-vectors.mjs` regenerates the file and checks each upstream file's SHA-256.
[`NOTICE.md`](../../packages/crypto-conformance/vectors/NOTICE.md) records revisions, licences and every deviation.

`externalConformance(provider)` groups the sets into one case per source, checking single calls and one large batch.
It is separate from `cryptoConformance` so the on-device checks stay fast.
`@kokuin/crypto-conformance` runs it against strict noble, `@kokuin/crypto-node` against `nodeCrypto`,
and `crates/kokuin-crypto/tests/external.rs` against the Rust core. Each of the three agrees on every case.

The weakened noble verifiers show which upstream set catches each guard:

| Guard | Caught by |
| --- | --- |
| `subgroup-a` | Wycheproof Ed25519 |
| `s-range` | Wycheproof Ed25519 |
| `low-s` | Wycheproof ECDSA P-256 |
| `scalar-range` | Wycheproof ECDSA P-256 |
| `zero-scalars` | Wycheproof ECDSA P-256 |
| `subgroup-r` | None: Wycheproof has no torsioned R with a torsion-free A, so only the hand-written corpus covers it. |

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

## Integrated adoption

Omitted `crypto` resolves to strict `nobleCrypto`. Pass one resolved provider through identities, resolvers and verification constructors.
The six-method `CryptoProvider` contract comes from `@kokuin/crypto`.
`createNativeCrypto()` from `@kokuin/crypto-native` constructs the standalone Nitro provider explicitly.
Portable packages require no Nitro dependency. No Node N-API or browser WASM backend is delivered.

Default integration routes remain noble. No measured manifest is supplied with this migration.
Standalone native methods execute Rust, but that fact does not qualify integrated native routes.
Native selection needs stored measurements, exact route counters, expanded mobile conformance and final physical workload retesting.
Registration, ABI and execution failures propagate. Route composition must never catch failures and retry on noble.

Browser WebCrypto and Ledger APDU signing retain their existing paths. Their constructors gain no crypto option.
Public-key derivation, key agreement, SHA-256, X25519, HKDF, AES-GCM, BIP39 and randomness remain outside provider selection.

### Verification policy and storage boundary

This is a coordinated 0.x minor cutover, including controller and records.
Crafted signatures accepted only under the previous ZIP-215 policy become invalid when reverified.
There is no historical rescan, compatibility switch or version gate.
Strict Ed25519 rejects noncanonical encodings, noncanonical scalars, small-order points and mixed-order points in both A and R.
ES256 receives raw messages, hashes once and rejects high-S compact signatures.
Ordinary deterministic signatures and canonical bytes remain unchanged.

Algorithm-specific custom verifiers take precedence. Missing overrides use the selected provider.
Custom overrides own their verification policy. They may deliberately accept signatures the default provider rejects.
Provider operational failures propagate unchanged. They must not become malformed-input refusals or trigger dynamic fallback.
False results and rejected operations never enter success caches.
Application verification caches need equivalent provider, verifier and resolution-policy isolation.

Controller history trusts stored epoch authentication. Changing providers does not reauthenticate those stored copies.
Only authoritative accepted logs belong in that trusted storage. Untrusted presentations must pass authoritative verification before persistence.
Provider-isolated fold memos prevent cross-provider success reuse without changing this durable storage contract.

Providers must remain behaviourally immutable throughout their lifetime. Constructors capture references, not copies of provider implementations.
Replacing caller option fields cannot change captured policy. Mutating provider internals violates the contract.

### Controller Promise migration

Public APIs with two or more arguments take one flat params object. Options fields sit at the top level.
`CryptoOptions` comes from `@kokuin/token`. Every result below now requires `await`.

| Export | Arguments after migration | Result |
| --- | --- | --- |
| `createInception` | `CreateInceptionParams` | `Promise<SignedEvent<InceptionEvent>>` |
| `verifyInception` | `VerifyInceptionParams` | `Promise<boolean>` |
| `verifySignatures` | `{ event, sigs, keys, crypto? }` | `Promise<boolean>` |
| `createRotate` | `CreateRotateParams` including `crypto?` | `Promise<SignedEvent<RotateEvent>>` |
| `verifyRotate` | `VerifyRotateParams` | `Promise<boolean>` |
| `createReset` | `{ seed, profile, gen, snapshot?, crypto? }` | `Promise<SignedEvent<RotateEvent>>` |
| `verifyReset` | `VerifyResetParams` | `Promise<boolean>` |
| `createAdd` | `CreateAddParams` including `crypto?` | `Promise<SignedEvent<AddEvent>>` |
| `createRenew` | `CreateRenewParams` including `crypto?` | `Promise<SignedEvent<RenewEvent>>` |
| `createRemove` | `CreateRemoveParams` including `crypto?` | `Promise<SignedEvent<RemoveEvent>>` |
| `createRevoke` | `CreateRevokeParams` including `crypto?` | `Promise<SignedEvent<RevokeEvent>>` |
| `verifyEpochSignature` | `VerifyEpochSignatureParams` | `Promise<boolean>` |
| `foldLog` | `FoldLogParams` | `Promise<FoldResult>` |
| `resolveBranches` | `ResolveBranchesParams` | `Promise<ResolveResult>` |
| `authoritativeLog` | `{ did, loaded, seen, context, crypto? }` | `Promise<AuthoritativeLog>` |
| `epochHeads` | `EpochHeadsParams` | `Promise<Array<string>>` |
| `mergeLogs` | `{ did, left, right, crypto? }` | `Promise<ControllerLog>` |
| `pruneLog` | `PruneLogParams` | `Promise<ControllerLog>` |
| `deviceRevokeIndices` | `{ did, chain, subject, crypto? }` | `Promise<Array<number>>` |
| `deviceRevokeIndex` | `{ did, chain, subject, crypto? }` | `Promise<number \| undefined>` |
| `createDeviceRevoke` | `CreateDeviceRevokeParams` including `crypto?` | `Promise<SignedEvent>` |
| `createControllerIdentity` | `{ seed, profile, log, crypto? }` | `Promise<FullIdentity>` |
| `createControllerIdentityWithKey` | `{ privateKey, log, crypto? }` | `Promise<SigningIdentity>` |

`provideControllerIdentity({ entry, profile, logStore, crypto? })` already returns `Promise<FullIdentity>` and now forwards the provider.
`createControllerResolver({ loadLog, history?, crypto? })` remains synchronous. Its resolution methods remain asynchronous.
`createRotate` still requires a complete `snapshot`. Epoch builders retain their existing head, parent and signer fields.
`createReset({ seed, profile, gen, snapshot?, crypto? })` makes the snapshot optional within its params object.

The following source-module exports also became asynchronous. They are internal propagation points, without public package subpath exports.

| Source module | Function | Result |
| --- | --- | --- |
| `events.ts` | `signEvent(event, privateKeys, options?)` | `Promise<Array<string>>` |
| `epoch.ts` | `foldEpochDetailed(params)` | `Promise<FoldEpochDetail \| FoldEpochRefusal>` |
| `epoch.ts` | `foldEpoch(params)` | `Promise<FoldEpochResult \| FoldEpochRefusal>` |
| `log.ts` | `foldHeld({ did, log, limits?, crypto? })` | `Promise<HeldFold \| Extract<FoldResult, { ok: false }>>` |
| `log.ts` | `withEpoch({ did, states, events, limits?, trusted?, crypto? })` | `Promise<HeldFold \| Extract<FoldResult, { ok: false }>>` |
| `history.ts` | `authoritativeLogWithin(params, limits?)` | `Promise<AuthoritativeLog>` |
| `fold-memo.ts` | `memoizedAuthoritativeLog(params, limits?)` | `Promise<AuthoritativeLog>` |
| `state.ts` | `currentState({ did, log, context, crypto? })` | `Promise<KeyState>` |

`FoldEpochParams` and `AuthoritativeLogParams` include `crypto?`.
Internal `createControllerResolverWithin` remains synchronous and accepts the extended resolver options.
`didFor`, `didFromInception`, canonicalisation, SHA-256 digests, key derivation and `enumerateProfiles` remain synchronous.
`appliedCopies`, `keyStateAt`, `snapshotOf`, state-view selectors and memory-store construction also remain synchronous.

### Identity-store options

| Package target | Provider entry points |
| --- | --- |
| node 0.5.0 | `NodeKeyStoreParams.crypto?`, constructor and `NodeKeyStore.open(params)` |
| electron 0.5.0 | `ElectronKeyStoreParams.crypto?`, constructor and `ElectronKeyStore.open(params?)` |
| expo 0.5.0 | Constructor and `ExpoKeyStore.open(options?)` accept `StoreEntryOptions & { crypto?: CryptoProvider }` |
| deterministic 0.3.0 | `HDKeyStoreParams.crypto?`, constructor, `fromSeed({ seed, basePath?, crypto? })`, `fromMnemonic({ mnemonic, basePath?, crypto? })` |

HD factory options retain `basePath?` alongside `crypto?`.
Node, Electron and Expo reject reopening cached stores with a different resolved provider reference.
Omission and explicit `nobleCrypto` are equivalent. Omission after custom-provider selection is a conflict.
Same-reference reopen succeeds. Equivalent-looking replacement provider objects still conflict.
`provideIdentitySync` on Node, Electron and Expo remains synchronous. Identity signing remains asynchronous.
Expo strips `crypto` before passing entry options to SecureStore.

### Record and vault adoption

Records hashing, range summaries and requester reconciliation now require awaits.
Verified operations carry `contentDigest` for synchronous decisions. Payload checks must finish before persistence.
The [records reference](records.md#records-migration-to-030) lists exact signatures and context options.
The [vault migration notes](../../packages/vault/README.md#crypto-provider-migration-to-020) list digest, ID, metadata and decoder changes.

`createVaultRecords` and `createVaultCoordinator` remain synchronous. Both capture `crypto?` from their parameter objects.
Replicated coordinators inherit the outer provider into nested `records` options.
An explicit unequal nested provider throws `TypeError` before provider or storage work.
Omitting the outer provider selects noble, so an explicit custom nested provider also conflicts.

```ts
const records = createVaultRecords({ ...recordsParams, crypto })
const coordinator = createVaultCoordinator({
  ...coordinatorParams,
  mode: 'replicated',
  crypto,
  records: { ...coordinatorParams.records, crypto },
})
```

These examples assume existing replicated configuration and imported factories.
The raw SQL store needs no provider option or schema change.
`createDelegationRevocationChecker(params: CreateDelegationRevocationCheckerParams)` captures the provider through tracked revocation wrappers.
Store-controller still accepts asynchronous merge callbacks. Its callback must await authoritative verification before reading `.log`.

## Named params migration

Verification uses `verify({ alg, signature, message, publicKey })` across all providers.
`VerifyItem` is the shared input type. Signing retains its three positional arguments.

### @kokuin/browser

| Export | Named params type | Fields |
| --- | --- | --- |
| `new BrowserKeyStore` | `BrowserKeyStoreConstructorParams` | `getStore` |

### @kokuin/capability

| Export | Named params type | Fields |
| --- | --- | --- |
| `createCapability` | `CreateCapabilityParams` | `signer, payload, header?, crypto?` |
| `new TokenRevokedError` | `TokenRevokedErrorParams` | `jti, options?` |

### @kokuin/controller

| Export | Named params type | Fields |
| --- | --- | --- |
| `deriveKeyMaterial` | `DeriveKeyMaterialParams` | `seed, path, alg, length?` |
| `mergeLogs` | `MergeLogsParams` | `did, left, right, crypto?` |
| `verifySignatures` | `VerifySignaturesParams` | `event, sigs, keys, crypto?` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?, crypto?` |
| `deviceRevokeIndices` | `DeviceRevokeIndicesParams` | `did, chain, subject, crypto?` |
| `deviceRevokeIndex` | `DeviceRevokeIndexParams` | `did, chain, subject, crypto?` |

### @kokuin/controller-conformance

| Export | Named params type | Fields |
| --- | --- | --- |
| `ControllerImplementation.createRotate` | `CreateRotateParams` | `seed, profile, did, prior, snapshot` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?` |
| `ControllerImplementation.authorityPrivateKey` | `AuthorityPrivateKeyParams` | `seed, profile, gen, seq` |

### @kokuin/crypto-napi

| Export | Named params type | Fields |
| --- | --- | --- |
| `NapiBinding.sign` | `NapiBindingSignParams` | `seed, message` |
| `NapiBinding.signBatch` | `NapiBindingSignBatchParams` | `seeds, messages` |
| `NapiBinding.blake3` | `NapiBindingBlake3Params` | `input, length` |
| `NapiBinding.blake3Batch` | `NapiBindingBlake3BatchParams` | `inputs, length` |
| `NapiBinding.verify` | `NapiVerifyParams` | `es256, signature, message, publicKey` |
| `NapiBinding.verifyBatch` | `NapiVerifyBatchParams` | `es256, signatures, messages, publicKeys` |

### @kokuin/ledger-device

| Export | Named params type | Fields |
| --- | --- | --- |
| `new LedgerError` | `LedgerErrorParams` | `message, statusCode` |
| `new LedgerDisconnectedError` | `LedgerDisconnectedErrorParams` | `cause?` |

### @kokuin/oauth

| Export | Named params type | Fields |
| --- | --- | --- |
| `new OAuthTokenError` | `OAuthTokenErrorParams` | `status, code?, description?` |

### @kokuin/records

| Export | Named params type | Fields |
| --- | --- | --- |
| `new RecordClaimError` | `RecordClaimErrorParams` | `message` |
| `new RecordOpSigningError` | `RecordOpSigningErrorParams` | `message` |
| `signRecordOp` | `SignRecordOpParams` | `identity, claim, opKind, crypto?` |
| `verifyRecordOp` | `VerifyRecordOpParams` | `opJWT, opKind, methods?, crypto?` |
| `verifySignedRecord` | `VerifySignedRecordParams` | `record, opKind, methods?, crypto?` |
| `recordDecisionDigest` | `RecordDecisionDigestParams` | `record, opKind, methods?, crypto?` |
| `compareRecordOps` | `CompareRecordOpsParams` | `incoming, stored, policy, onEqual?` |
| `new RecordTypeGraphError` | `RecordTypeGraphErrorParams` | `message` |
| `new RecordContentRefusalError` | `RecordContentRefusalErrorParams` | `message` |
| `new RecordRangeError` | `RecordRangeErrorParams` | `message, options?` |
| `splitRange` | `SplitRangeParams` | `leaves, rangeBounds, leafThreshold, crypto?` |
| `advanceRecordPull` | `AdvanceRecordPullParams` | `state, local, response, crypto?` |

### @kokuin/store-delegation

| Export | Named params type | Fields |
| --- | --- | --- |
| `new VerifiedRevocationError` | `VerifiedRevocationErrorParams` | `message, options?` |

### @kokuin/store-vault

| Export | Named params type | Fields |
| --- | --- | --- |
| `new VaultNotAuthorized` | `VaultNotAuthorizedParams` | `verb` |

### @kokuin/token

| Export | Named params type | Fields |
| --- | --- | --- |
| `new UnresolvableIssuerError` | `UnresolvableIssuerErrorParams` | `message, options?` |
| `new IssuerKeyNotFoundError` | `IssuerKeyNotFoundErrorParams` | `message, options?` |

### @kokuin/vault

| Export | Named params type | Fields |
| --- | --- | --- |
| `new VaultError` | `VaultErrorParams` | `message, options` |
| `new NoAvailableFactor` | `NoAvailableFactorParams` | `kind` |
| `new InvalidVaultFactors` | `InvalidVaultFactorsParams` | `reason` |
| `new UnsupportedVaultSuite` | `UnsupportedVaultSuiteParams` | `suite` |
| `new VaultTampered` | `VaultTamperedParams` | `message, options?` |
| `new VaultSecretRejected` | `VaultSecretRejectedParams` | `kinds, options?` |
| `new VaultPinRejected` | `VaultPinRejectedParams` | `keyID, options` |
| `KeyCache.set` | `KeyCacheSetParams` | `keyID, contentKey, keyVersion, branchID` |

Constructors now take one named object. Existing zero-argument constructors remain unchanged.

`VaultSecretUnverifiableParams` names the existing `UnverifiableWrapping` constructor object without changing its shape.

## Complete flat params migration

Each listed API takes one object. Existing options types remain exported, with their fields at the top level.

Single-argument and zero-argument APIs retain their calling convention.

| API | Named params type | Previous positional form |
| --- | --- | --- |
| `controller-conformance.runControllerConformance` | `RunControllerConformanceParams` | `runControllerConformance(suite: ConformanceSuite, impl: ControllerImplementation)` |
| `ledger-device.encodeSignMessageChunks` | `EncodeSignMessageChunksParams` | `encodeSignMessageChunks(pathBytes: Uint8Array, message: Uint8Array)` |
| `ledger-device.createLedgerIdentityProvider` | `CreateLedgerIdentityProviderParams` | `createLedgerIdentityProvider(transport: LedgerTransport, options?: LedgerIdentityProviderOptions)` |
| `store-controller.createControllerStore` | `CreateControllerStoreParams` | `createControllerStore(db: Kysely<ControllerStoreTables>, adapter: Adapter, context: StoreContext)` |
| `controller.isCanonicalizable` | `IsCanonicalizableParams` | `isCanonicalizable(value: unknown, depth = 1)` |
| `controller.verifyDigest` | `VerifyDigestParams` | `verifyDigest(digest: string, value: unknown)` |
| `controller.withinCanonicalDepth` | `WithinCanonicalDepthParams` | `withinCanonicalDepth(value: unknown, depth = 1)` |
| `controller.agreementPath` | `AgreementPathParams` | `agreementPath(profile: number, gen: number, seq: number)` |
| `controller.authorityPath` | `AuthorityPathParams` | `authorityPath(profile: number, gen: number, seq: number)` |
| `controller.deriveKeyPair` | `DeriveKeyPairParams` | `deriveKeyPair(seed: Uint8Array, path: string, alg: string)` |
| `controller.verifyEpochSignature` | `VerifyEpochSignatureParams` | `verifyEpochSignature(signed: SignedEvent<EpochEvent>, signer: EpochSignatureSigner, options: CryptoOptions = {})` |
| `controller.createInception` | `CreateInceptionParams` | `createInception(seed: Uint8Array, profile: number, options: CryptoOptions = {})` |
| `controller.didFor` | `DidForParams` | `didFor(seed: Uint8Array, profile: number)` |
| `controller.verifyInception` | `VerifyInceptionParams` | `verifyInception(signed: SignedEvent<InceptionEvent>, did: string, options: CryptoOptions = {})` |
| `controller.verifyReset` | `VerifyResetParams` | `verifyReset(signed: SignedEvent<RotateEvent>, inception: InceptionEvent, options: CryptoOptions = {})` |
| `controller.verifyRotate` | `VerifyRotateParams` | `verifyRotate(signed: SignedEvent<RotateEvent>, prior: { digest: string; n: Array<string> }, options: CryptoOptions = {})` |
| `controller.foldLog` | `FoldLogParams` | `foldLog(did: string, input: ControllerLog, options: CryptoOptions = {})` |
| `controller.keyStateAt` | `KeyStateAtParams` | `keyStateAt(result: FoldResult, position: number)` |
| `controller.snapshotOf` | `SnapshotOfParams` | `snapshotOf(state: KeyState, drop: { deny?: Iterable<string>; members?: Iterable<string> } = {})` |
| `controller.encodeKey` | `EncodeKeyParams` | `encodeKey(publicKey: Uint8Array, alg: KeyAlgorithm)` |
| `controller.epochHeads` | `EpochHeadsParams` | `epochHeads(did: string, log: ControllerLog, options: CryptoOptions = {})` |
| `controller.pruneLog` | `PruneLogParams` | `pruneLog(did: string, input: ControllerLog, options: CryptoOptions = {})` |
| `controller.enumerateProfiles` | `EnumerateProfilesParams` | `enumerateProfiles(seed: Uint8Array, count: number)` |
| `controller.resolveBranches` | `ResolveBranchesParams` | `resolveBranches(did: string, chains: Array<Array<SignedEvent>>, options: CryptoOptions = {})` |
| `jwe.createTokenEncrypter` | `CreateTokenEncrypterParams` | `createTokenEncrypter(recipient: Uint8Array, options: EncryptOptions)` |
| `jwe.deriveSharedSecretAsync` | `DeriveSharedSecretAsyncParams` | `deriveSharedSecretAsync(recipient: string, options: ResolveRecipientOptions)` |
| `jwe.createTokenEncrypterAsync` | `CreateTokenEncrypterAsyncParams` | `createTokenEncrypterAsync(recipient: string, options: ResolveRecipientOptions)` |
| `jwe.encryptToken` | `EncryptTokenParams` | `encryptToken(encrypter: TokenEncrypter, plaintext: Uint8Array)` |
| `jwe.decryptToken` | `DecryptTokenParams` | `decryptToken(decrypter: KeyAgreementIdentity, jwe: string)` |
| `jwe.wrapEnvelope` | `WrapEnvelopeParams` | `wrapEnvelope(mode: EnvelopeMode, payload: Record<string, unknown>, options: WrapOptions)` |
| `jwe.unwrapEnvelope` | `UnwrapEnvelopeParams` | `unwrapEnvelope(message: string, options: UnwrapOptions)` |
| `store-vault.createVaultStore` | `CreateVaultStoreParams` | `createVaultStore(db: Kysely<VaultStoreTables>, adapter: Adapter, context: StoreContext)` |
| `store-vault.getVaultRecordsStore` | `GetVaultRecordsStoreParams` | `getVaultRecordsStore(provider: StoreProvider, opKind?: string)` |
| `vault.decodeVaultRecord` | `DecodeVaultRecordParams` | `decodeVaultRecord(record: Pick<SignedRecord, 'type' \| 'id' \| 'owner' \| 'hlc' \| 'payload'>, recordMeta: Record<string, unknown>, options?: CryptoOptions)` |
| `vault.encodeVaultRecordPayload` | `EncodeVaultRecordPayloadParams` | `encodeVaultRecordPayload(type: Type, payload: VaultRecordPayloads[Type])` |
| `vault.vaultRecordMeta` | `VaultRecordMetaParams` | `vaultRecordMeta(type: Type, claim: RecordClaim, options?: CryptoOptions)` |
| `vault.vaultRevocationRecordID` | `VaultRevocationRecordIDParams` | `vaultRevocationRecordID(keyID: string, recipientDID: string)` |
| `vault.compareVaultBranches` | `CompareVaultBranchesParams` | `compareVaultBranches(left: VerifiedRecordOp, right: VerifiedRecordOp)` |
| `vault.digestParts` | `DigestPartsParams` | `digestParts(parts: Array<string>, options?: CryptoOptions)` |
| `vault.vaultKeyDigest` | `VaultKeyDigestParams` | `vaultKeyDigest(key: VaultKeyDigestInput, options?: CryptoOptions)` |
| `vault.vaultWrappingDigest` | `VaultWrappingDigestParams` | `vaultWrappingDigest(wrapping: VaultWrappingDigestInput, options?: CryptoOptions)` |
| `vault.vaultEntriesDigest` | `VaultEntriesDigestParams` | `vaultEntriesDigest(entries: ReadonlyArray<VaultEntryDigestInput>, options?: CryptoOptions)` |
| `vault.vaultEntryDigest` | `VaultEntryDigestParams` | `vaultEntryDigest(entry: VaultEntryDigestInput, options?: CryptoOptions)` |
| `vault.descriptorDigest` | `DescriptorDigestParams` | `descriptorDigest(descriptors: Array<FactorDescriptor>, options?: CryptoOptions)` |
| `vault.wrappingNamesExcludedRecipient` | `WrappingNamesExcludedRecipientParams` | `wrappingNamesExcludedRecipient(wrapping: { recipientDID: string \| null; factors: ReadonlyArray<FactorDescriptor> }, excluded: ReadonlySet<string>)` |
| `vault.satisfiableFactors` | `SatisfiableFactorsParams` | `satisfiableFactors(descriptors: Array<FactorDescriptor>, identity: KeyAgreementIdentity \| null)` |
| `vault.factorsFromDescriptors` | `FactorsFromDescriptorsParams` | `factorsFromDescriptors(descriptors: Array<FactorDescriptor>, inputs?: FactorInputs)` |
| `vault.createVaultKeyID` | `CreateVaultKeyIDParams` | `createVaultKeyID(owner: string \| Uint8Array, unique: Uint8Array, options?: CryptoOptions)` |
| `vault.createVaultKeyReference` | `CreateVaultKeyReferenceParams` | `createVaultKeyReference(owner: string, unique: Uint8Array, options?: CryptoOptions)` |
| `vault.vaultKeyVersionReader` | `VaultKeyVersionReaderParams` | `vaultKeyVersionReader(store: RecordStoreAdapter, input: Pick<VaultRecordTypeParams, 'opKind' \| 'methods' \| 'crypto'>)` |
| `vault.vaultProofAuthorizer` | `VaultProofAuthorizerParams` | `vaultProofAuthorizer(input: VaultRecordTypeParams, store: RecordStoreAdapter, transportContext?: unknown)` |
| `token.getDID` | `GetDIDParams` | `getDID(codec: Uint8Array, publicKey: Uint8Array)` |
| `token.createFullIdentity` | `CreateFullIdentityParams` | `createFullIdentity(privateKey: Uint8Array, options: CryptoOptions = {})` |
| `token.createKeyAgreementIdentityForDID` | `CreateKeyAgreementIdentityForDIDParams` | `createKeyAgreementIdentityForDID(id: DIDString, x25519PrivateKey: Uint8Array)` |
| `token.createSigningIdentity` | `CreateSigningIdentityParams` | `createSigningIdentity(privateKey: Uint8Array, options: CryptoOptions = {})` |
| `token.createSigningIdentityForDID` | `CreateSigningIdentityForDIDParams` | `createSigningIdentityForDID(id: DIDString, privateKey: Uint8Array, options: CryptoOptions = {})` |
| `token.findMethodResolver` | `FindMethodResolverParams` | `findMethodResolver(registry: MethodRegistry, did: string)` |
| `token.verifyMultihash` | `VerifyMultihashParams` | `verifyMultihash(multihash: Uint8Array, bytes: Uint8Array)` |
| `token.decodePeer4` | `DecodePeer4Params` | `decodePeer4(longForm: string, options: DecodePeer4Options = {})` |
| `token.assertTimeClaimsValid` | `AssertTimeClaimsValidParams` | `assertTimeClaimsValid(payload: TimeClaimsPayload, options: TimeValidationOptions = {})` |
| `token.createUnsignedToken` | `CreateUnsignedTokenParams` | `createUnsignedToken(payload: Payload, header?: Header)` |
| `token.signToken` | `SignTokenParams` | `signToken(signer: SigningIdentity, token: Token<Payload, Header>)` |
| `token.verifyToken` | `VerifyTokenParams` | `verifyToken(token: Token<Payload> \| string, options?: VerifyTokenOptions & { allowUnsigned?: false })` |
| `token.concatBytes` | `ConcatBytesParams` | `concatBytes(a: Uint8Array, b: Uint8Array)` |
| `token.getVerifier` | `GetVerifierParams` | `getVerifier(algorithm: SignatureAlgorithm, verifiers: Verifiers = {}, options: CryptoOptions = {})` |
| `store-delegation.createDelegationStore` | `CreateDelegationStoreParams` | `createDelegationStore(db: Kysely<DelegationStoreTables>, adapter: Adapter, context: StoreContext)` |
| `store-delegation.createDelegationRevocationChecker` | `CreateDelegationRevocationCheckerParams` | `createDelegationRevocationChecker(api: DelegationStoreAPI, options?: RevocationOptions)` |
| `capability.assertValidDelegation` | `AssertValidDelegationParams` | `assertValidDelegation(from: CapabilityPayload, to: CapabilityPayload, atTime?: number)` |
| `capability.checkCapability` | `CheckCapabilityParams` | `checkCapability(permission: Permission, payload: SignedPayload, inputOptions?: DelegationChainOptions)` |
| `capability.checkDelegationChain` | `CheckDelegationChainParams` | `checkDelegationChain(payload: CapabilityPayload, capabilities: Array<string>, inputOptions?: DelegationChainOptions)` |
| `capability.assertMemberRoot` | `AssertMemberRootParams` | `assertMemberRoot(payload: CapabilityPayload, options: DelegationChainOptions \| undefined, time: number)` |
| `capability.hasPartsMatch` | `HasPartsMatchParams` | `hasPartsMatch(expected: string, actual: string)` |
| `capability.hasPermission` | `HasPermissionParams` | `hasPermission(expected: Permission, granted: Permission)` |
| `capability.isMatch` | `IsMatchParams` | `isMatch(expected: string, actual: string)` |
| `capability.createRevocationChecker` | `CreateRevocationCheckerParams` | `createRevocationChecker(backend: RevocationBackend, options?: RevocationOptions)` |
| `capability.createRevocationRecord` | `CreateRevocationRecordParams` | `createRevocationRecord(signer: SigningIdentity, jti: string)` |
| `capability.assertDeviceCapabilityPolicy` | `AssertDeviceCapabilityPolicyParams` | `assertDeviceCapabilityPolicy(payload: { exp?: number }, options: DeviceCapabilityPolicyOptions = {})` |
| `capability.assertNonExpired` | `AssertNonExpiredParams` | `assertNonExpired(payload: { exp?: number }, atTime?: number)` |
| `capability.assertValidIssuedAt` | `AssertValidIssuedAtParams` | `assertValidIssuedAt(payload: { iat?: number }, atTime?: number)` |
| `capability.assertValidNotBefore` | `AssertValidNotBeforeParams` | `assertValidNotBefore(payload: { nbf?: number }, atTime?: number)` |
| `records.compareRecordDecisionHLC` | `CompareRecordDecisionHLCParams` | `compareRecordDecisionHLC(left: string, right: string)` |
| `records.parseBoundedHLC` | `ParseBoundedHLCParams` | `parseBoundedHLC(hlc: string, nowMS: number, maxDriftMS: number)` |
| `records.recordDecisionFromVerifiedCopies` | `RecordDecisionFromVerifiedCopiesParams` | `recordDecisionFromVerifiedCopies(key: RecordKey, entries: ReadonlyArray<VerifiedRecordCopy>, stampSource: 'hlc' \| 'version')` |
| `records.createRecordVerifier` | `CreateRecordVerifierParams` | `createRecordVerifier(opKind: string, methods?: MethodRegistry, options?: CryptoOptions)` |
| `records.fingerprintRange` | `FingerprintRangeParams` | `fingerprintRange(leaves: ReadonlyArray<RangeLeaf>, options?: CryptoOptions)` |
| `records.rangeContains` | `RangeContainsParams` | `rangeContains(bounds: RangeBounds, key: RecordKey)` |
| `records.rangeLeaf` | `RangeLeafParams` | `rangeLeaf(decision: RecordDecision, policy: MergePolicy, options?: CryptoOptions)` |
| `records.summarizeRange` | `SummarizeRangeParams` | `summarizeRange(leaves: ReadonlyArray<RangeLeaf>, rangeBounds: RangeBounds, options?: CryptoOptions)` |
| `records.nextRequesterSteps` | `NextRequesterStepsParams` | `nextRequesterSteps(local: ReadonlyArray<RangeLeaf>, response: RangeResponse, options?: CryptoOptions)` |
| `records.recordClaimDigest` | `RecordClaimDigestParams` | `recordClaimDigest(claim: RecordClaim, options?: CryptoOptions)` |
| `records.recordPayloadDigest` | `RecordPayloadDigestParams` | `recordPayloadDigest(payload: Uint8Array \| null, options?: CryptoOptions)` |
| `records.recordPayloadMatches` | `RecordPayloadMatchesParams` | `recordPayloadMatches(record: SignedRecord, claim: RecordClaim, options?: CryptoOptions)` |
| `records.recordSignerKey` | `RecordSignerKeyParams` | `recordSignerKey(issuer: string, opJWT: string)` |
| `records.getRecordDecisions` | `GetRecordDecisionsParams` | `getRecordDecisions(store: RecordStoreAdapter, keys: ReadonlyArray<RecordKey>)` |
| `records.filterVisibleRecords` | `FilterVisibleRecordsParams` | `filterVisibleRecords(records: ReadonlyArray<SignedRecord>, types: ReadonlyMap<string, RecordTypeDefinition>, ctx: VisibilityContext)` |
| `records.verifyHolderProof` | `VerifyHolderProofParams` | `verifyHolderProof(proof: SignedRecord, ctx: VisibilityContext)` |
| `records.visibleTo` | `VisibleToParams` | `visibleTo(record: SignedRecord, rules: ReadonlyArray<VisibilityRule>, ctx: VisibilityContext)` |
| `deterministic.derivePrivateKey` | `DerivePrivateKeyParams` | `derivePrivateKey(seed: Uint8Array, path: string)` |
| `deterministic.resolveDerivationPath` | `ResolveDerivationPathParams` | `resolveDerivationPath(keyID: string, basePath: string = DEFAULT_BASE_PATH)` |
| `CryptoProvider.sign` | `CryptoProviderSignParams` | `sign(alg, privateKey, message)` |
| `CryptoProvider.signBatch` | `CryptoProviderSignBatchParams` | `signBatch(alg, items)` |
| `CryptoProvider.blake3` | `CryptoProviderBlake3Params` | `blake3(input, dkLen)` |
| `CryptoProvider.blake3Batch` | `CryptoProviderBlake3BatchParams` | `blake3Batch(inputs, dkLen)` |
| `SigningIdentity.signToken` | `SigningIdentitySignTokenParams` | `signToken(payload, options?)` |
| `MultiKeyIdentity.signToken` | `MultiKeyIdentitySignTokenParams` | `signToken(payload, options?)` |
| `KeyAgreementIdentity.agreeKey` | `KeyAgreementIdentityAgreeKeyParams` | `agreeKey(ephemeralPublicKey)` |
| `MultiKeyIdentity.agreeKey` | `MultiKeyIdentityAgreeKeyParams` | `agreeKey(ephemeralPublicKey, kid?)` |
| `DIDCache.set` | `DIDCacheSetParams` | `set(shortForm, doc)` |
| `HDKeyStore.fromSeed` | `HDKeyStoreFromSeedParams` | `fromSeed(seed, options?)` |
| `HDKeyStore.fromMnemonic` | `HDKeyStoreFromMnemonicParams` | `fromMnemonic(mnemonic, options?)` |

### Methods and callbacks

| API | Named params type | Previous form |
| --- | --- | --- |
| `vault.KeyCache.get` | `KeyCacheGetParams` | `get(keyID, keyVersion)` |
| `vault.KeyCache.has` | `KeyCacheHasParams` | `has(keyID, keyVersion)` |
| `vault.KeyCache.evictVersion` | `KeyCacheEvictVersionParams` | `evictVersion(keyID, keyVersion)` |
| `vault.VaultRecordHooks.validateConsumerMetadata` | `VaultRecordHooksValidateConsumerMetadataParams` | `validateConsumerMetadata(value, request)` |
| `keystore-conformance.KeyStoreConformanceHarness.isSameKey` | `KeyStoreConformanceHarnessIsSameKeyParams` | `isSameKey(a, b)` |
| `controller-conformance.ControllerImplementation.createInception` | `ControllerImplementationCreateInceptionParams` | `createInception(seed, profile)` |
| `controller-conformance.ControllerImplementation.foldLog` | `ControllerImplementationFoldLogParams` | `foldLog(did, log)` |
| `controller-conformance.ControllerImplementation.resolveBranches` | `ControllerImplementationResolveBranchesParams` | `resolveBranches(did, branches)` |
| `controller-conformance.ControllerImplementation.enumerateProfiles` | `ControllerImplementationEnumerateProfilesParams` | `enumerateProfiles(seed, count)` |
| `controller-conformance.ControllerImplementation.recoveryPrivateKey` | `ControllerImplementationRecoveryPrivateKeyParams` | `recoveryPrivateKey(seed, profile)` |
| `controller-conformance.ControllerImplementation.signEvent` | `ControllerImplementationSignEventParams` | `signEvent(event, privateKeys)` |
| `store-controller.ControllerStoreAPI.markObserved` | `ControllerStoreAPIMarkObservedParams` | `markObserved(did, at?)` |
| `controller.LogStore.merge` | `LogStoreMergeParams` | `merge(did, update)` |
| `store-delegation.DelegationStoreAPI.getRevocationByIssuer` | `DelegationStoreAPIGetRevocationByIssuerParams` | `getRevocationByIssuer(jti, issuer)` |
| `store-delegation.DelegationStoreAPI.isRevokedBy` | `DelegationStoreAPIIsRevokedByParams` | `isRevokedBy(jti, issuer)` |
| `store-delegation.DelegationStoreAPI.markRevocationVerified` | `DelegationStoreAPIMarkRevocationVerifiedParams` | `markRevocationVerified(jti, issuer, params)` |
| `store-delegation.DelegationStoreAPI.getPendingRevocationByIssuer` | `DelegationStoreAPIGetPendingRevocationByIssuerParams` | `getPendingRevocationByIssuer(jti, issuer)` |
| `store-delegation.DelegationStoreAPI.deletePendingRevocationsFromOtherIssuers` | `DelegationStoreAPIDeletePendingRevocationsFromOtherIssuersParams` | `deletePendingRevocationsFromOtherIssuers(jti, issuer)` |
| `capability.RevocationBackend.get` | `RevocationBackendGetParams` | `get(jti, issuer)` |
| `capability.VerifyTokenHook` | `VerifyTokenHookParams` | `VerifyTokenHook(token, raw)` |
| `store-vault.VaultRecords.apply` | `VaultRecordsApplyParams` | `apply(records, transportContext?)` |
| `store-vault.VaultCoordinator.lockAll` | `VaultCoordinatorLockAllParams` | `lockAll(ownerDID, call?)` |
| `store-vault.VaultCoordinator.listKeys` | `VaultCoordinatorListKeysParams` | `listKeys(ownerDID, call?)` |
| `records.ApplyRecordChunkParams.verifyCapability` | `ApplyRecordChunkParamsVerifyCapabilityParams` | `verifyCapability(tokens, owner, issuer)` |
| `records.RecordAuthorizeContext.verifyCapability` | `RecordAuthorizeContextVerifyCapabilityParams` | `verifyCapability(tokens, owner, issuer)` |
| `records.RecordTypeDefinition.authorize` | `RecordTypeDefinitionAuthorizeParams` | `authorize(op, ctx)` |
| `records.RecordTypeDefinition.precheck` | `RecordTypeDefinitionPrecheckParams` | `precheck(op, record)` |
| `records.RecordTypeDefinition.visibleTo` | `RecordTypeDefinitionVisibleToParams` | `visibleTo(record, ctx)` |
| `records.RecordTypeDefinition.dependencies` | `RecordTypeDefinitionDependenciesParams` | `dependencies(record, op)` |
| `records.RecordTypeDefinition.onEqual` | `RecordTypeDefinitionOnEqualParams` | `onEqual(incoming, stored)` |
| `records.RecordTypeDefinition.afterApply` | `RecordTypeDefinitionAfterApplyParams` | `afterApply(record, store)` |
| `records.RecordTypeDefinition.afterAuthorize` | `RecordTypeDefinitionAfterAuthorizeParams` | `afterAuthorize(record, store)` |
| `records.RecordTypeDefinition.lockKeys` | `RecordTypeDefinitionLockKeysParams` | `lockKeys(incoming, stored)` |
| `records.VisibilityContext.authorizeProof` | `VisibilityContextAuthorizeProofParams` | `authorizeProof(record, stored)` |
| `records.VisibilityContext.currentKeyVersion` | `VisibilityContextCurrentKeyVersionParams` | `currentKeyVersion(owner, keyID)` |
| `records.VisibilityContext.isGroupMember` | `VisibilityContextIsGroupMemberParams` | `isGroupMember(groupID, did)` |
| `records.CompareRecordOpsParams.onEqual` | `CompareRecordOpsParamsOnEqualParams` | `onEqual(incoming, stored)` |
| `records.RecordStoreAdapter.listByGroup` | `RecordStoreAdapterListByGroupParams` | `listByGroup(type, groupID)` |
| `records.RecordStoreAdapter.pruneCopy` | `RecordStoreAdapterPruneCopyParams` | `pruneCopy(key, signerDID)` |
| `token.DIDMethodResolver.resolve` | `DIDMethodResolverResolveParams` | `resolve(did, header)` |
| `token.DIDMethodResolver.resolveHistoric` | `DIDMethodResolverResolveHistoricParams` | `resolveHistoric(did, header)` |
| `token.DIDMethodResolver.resolveMember` | `DIDMethodResolverResolveMemberParams` | `resolveMember(subject, member)` |
| `token.DIDMethodResolver.resolveMemberHistoric` | `DIDMethodResolverResolveMemberHistoricParams` | `resolveMemberHistoric(subject, member)` |
| `token.Verifier` | `VerifierParams` | `verifier(signature, message, publicKey)` |

| API | Named params type | Previous form |
| --- | --- | --- |
| `createDelegationRevocationChecker(...).verdict` | `DelegationRevocationVerdictParams` | `verdict(token, raw)` |
| `splitRange` | `SplitRangeParams` | `{ leaves, rangeBounds, leafThreshold, cryptoOptions? }` |
