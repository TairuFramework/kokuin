# @kokuin/controller

## Installation

```sh
npm install @kokuin/controller
```

## Crypto provider migration to 0.7.0

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
| `mergeLogs` | `MergeLogsParams` | `did, left, right, crypto?` |
| `verifySignatures` | `VerifySignaturesParams` | `event, sigs, keys, crypto?` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?, crypto?` |
| `deviceRevokeIndices` | `DeviceRevokeIndicesParams` | `did, chain, subject, crypto?` |
| `deviceRevokeIndex` | `DeviceRevokeIndexParams` | `did, chain, subject, crypto?` |

`EpochSignatureSigner` names the existing root-or-member signer union for `verifyEpochSignature`.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `isCanonicalizable` | `IsCanonicalizableParams` | `isCanonicalizable(value: unknown, depth = 1)` |
| `verifyDigest` | `VerifyDigestParams` | `verifyDigest(digest: string, value: unknown)` |
| `withinCanonicalDepth` | `WithinCanonicalDepthParams` | `withinCanonicalDepth(value: unknown, depth = 1)` |
| `agreementPath` | `AgreementPathParams` | `agreementPath(profile: number, gen: number, seq: number)` |
| `authorityPath` | `AuthorityPathParams` | `authorityPath(profile: number, gen: number, seq: number)` |
| `deriveKeyPair` | `DeriveKeyPairParams` | `deriveKeyPair(seed: Uint8Array, path: string, alg: string)` |
| `verifyEpochSignature` | `VerifyEpochSignatureParams` | `verifyEpochSignature(signed: SignedEvent<EpochEvent>, signer: EpochSignatureSigner, options: CryptoOptions = {})` |
| `createInception` | `CreateInceptionParams` | `createInception(seed: Uint8Array, profile: number, options: CryptoOptions = {})` |
| `didFor` | `DidForParams` | `didFor(seed: Uint8Array, profile: number)` |
| `verifyInception` | `VerifyInceptionParams` | `verifyInception(signed: SignedEvent<InceptionEvent>, did: string, options: CryptoOptions = {})` |
| `verifyReset` | `VerifyResetParams` | `verifyReset(signed: SignedEvent<RotateEvent>, inception: InceptionEvent, options: CryptoOptions = {})` |
| `verifyRotate` | `VerifyRotateParams` | `verifyRotate(signed: SignedEvent<RotateEvent>, prior: { digest: string; n: Array<string> }, options: CryptoOptions = {})` |
| `foldLog` | `FoldLogParams` | `foldLog(did: string, input: ControllerLog, options: CryptoOptions = {})` |
| `keyStateAt` | `KeyStateAtParams` | `keyStateAt(result: FoldResult, position: number)` |
| `snapshotOf` | `SnapshotOfParams` | `snapshotOf(state: KeyState, drop: { deny?: Iterable<string>; members?: Iterable<string> } = {})` |
| `encodeKey` | `EncodeKeyParams` | `encodeKey(publicKey: Uint8Array, alg: KeyAlgorithm)` |
| `epochHeads` | `EpochHeadsParams` | `epochHeads(did: string, log: ControllerLog, options: CryptoOptions = {})` |
| `pruneLog` | `PruneLogParams` | `pruneLog(did: string, input: ControllerLog, options: CryptoOptions = {})` |
| `enumerateProfiles` | `EnumerateProfilesParams` | `enumerateProfiles(seed: Uint8Array, count: number)` |
| `resolveBranches` | `ResolveBranchesParams` | `resolveBranches(did: string, chains: Array<Array<SignedEvent>>, options: CryptoOptions = {})` |

Method and callback contracts follow the same convention.

| API | Named params type | Previous form |
| --- | --- | --- |
| `LogStore.merge` | `LogStoreMergeParams` | `merge(did, update)` |

Existing params objects also flatten their options fields:

| Existing params type | Updated params type | Field migration |
| --- | --- | --- |
| `FoldHeldParams` | `FoldHeldParams` | `Nested options fields → top-level fields` |
| `WithEpochParams` | `WithEpochParams` | `Nested options fields → top-level fields` |
| `SettledChainParams` | `SettledChainParams` | `Nested options fields → top-level fields` |
| `MergeLogsParams` | `MergeLogsParams` | `Nested options fields → top-level fields` |
| `VerifySignaturesParams` | `VerifySignaturesParams` | `Nested options fields → top-level fields` |
| `CreateResetParams` | `CreateResetParams` | `Nested options fields → top-level fields` |
| `EvaluateParams` | `EvaluateParams` | `Nested options fields → top-level fields` |
| `DeviceRevokeIndicesParams` | `DeviceRevokeIndicesParams` | `Nested options fields → top-level fields` |
| `DeviceRevokeIndexParams` | `DeviceRevokeIndexParams` | `Nested options fields → top-level fields` |
| `StepEventParams` | `StepEventParams` | `Nested options fields → top-level fields` |
| `CurrentStateParams` | `CurrentStateParams` | `Nested options fields → top-level fields` |
