# Crypto provider adoption for kumiai

Date: 2026-11-04.
Stage: next.
Scope: a self-contained migration handoff. Downstream implementation and publication require separate authorisation.
Source signatures were checked against the committed provider migration. Re-query downstream call sites at the actual migration baseline.

## Integration work

Thread `crypto?: CryptoProvider` through MLS authentication, lifecycle proofs, recovery, ledger verification, hubs and identity/controller construction.
MLS cryptography itself remains outside this provider migration.

Prior discovery found calls in `mls/src/authentication.ts` near lines 206 and 250, plus `lifecycle-proof.ts:353` and `ledger.ts:90`.
Other observed sites were `recovery.ts:335,622` and `recovery-verdict.ts:140`.
Re-query these discovery coordinates at the implementation baseline.

`mls/src/controller-log.ts` previously returned `foldLog` directly near line 36.
Its wrapper and callers now need asynchronous contracts.
`mls/test/fixtures/lifecycle-ledger.ts` previously constructed inception and identities near lines 25, 43 and 66.
Those builders and their callers need awaits.

Range reconciliation, record fixtures and vault callers need the complete migrations below.
Carry `VerifiedRecordOp.contentDigest` in fixture construction and persisted-object reconstruction.
Never fabricate an empty digest or recompute it synchronously.

## Target dependencies

These are manifest-based release targets, not claims that publication has completed.
These ranges include the pending breaking signature intents. Recompute the release preview before upgrading.
Cross-repository dependencies use published `^` ranges, never `workspace:`.
Every published kokuin package moves together under `versioning.fixed`, so this release is 0.7.0 throughout.

| Package | Target range |
| --- | --- |
| `@kokuin/token` | `^0.7.0` |
| `@kokuin/capability` | `^0.7.0` |
| `@kokuin/controller` | `^0.7.0` |
| `@kokuin/records` | `^0.7.0` |
| `@kokuin/vault` | `^0.7.0` |
| `@kokuin/store-vault` | `^0.7.0` |
| `@kokuin/store-controller` | `^0.7.0` |
| `@kokuin/store-delegation` | `^0.7.0` |
| `@kokuin/jwe` | `^0.7.0` |
| `@kokuin/node` | `^0.7.0` |
| `@kokuin/browser` | `^0.7.0` |
| `@kokuin/deterministic` | `^0.7.0` |
| `@kokuin/electron` | `^0.7.0` |
| `@kokuin/expo` | `^0.7.0` |
| `@kokuin/ledger-device` | `^0.7.0` |
| `@kokuin/crypto` | `^0.7.0` |
| `@kokuin/crypto-native` | `^0.7.0`, only for explicit native construction |

Upgrade applicable packages only. Token, capability, browser, node and deterministic share the coordinated release window.
Controller, records and portable store migrations join that window. Electron and Expo retain independent SDK qualification.
Ledger has a minor intent for named error constructors. Its signing protocol is unchanged.
OAuth has a minor intent for its named error constructor. Private conformance packages remain unpublished.
The crypto validation-cache patch intent accompanies the breaking provider minor intent.

## Token, capability and envelope API differences

`CryptoOptions` from `@kokuin/token` is `{ crypto?: CryptoProvider }`.
`createSigningIdentityForDID(params: CreateSigningIdentityForDIDParams)`, `createSigningIdentity(params: CreateSigningIdentityParams)`,
`createFullIdentity(params: CreateFullIdentityParams)` and `randomIdentity(options?)` retain synchronous construction.
`createIdentity(input)` gains `input.crypto?` and retains its Promise result.
`VerifyTokenOptions` and `VerifySignedPayloadInput` gain `crypto?` without changing verification overloads.
`getVerifier(params: GetVerifierParams)` appends provider options.
Each identity captures its signing provider. A verification option cannot replace an identity's signer.

`CreateCapabilityOptions`, `DelegationChainOptions` and `RevocationOptions` gain `crypto?`.
`createCapability`, `checkDelegationChain` and `checkCapability` retain their existing asynchronous contracts.
`createMemoryRevocationBackend` and `createRevocationChecker` capture provider options at construction.
`createDelegationRevocationChecker(params: CreateDelegationRevocationCheckerParams)` forwards them through tracked wrappers.
Revocation verification always retains `historic: true`.
`unwrapEnvelope` accepts `UnwrapOptions.crypto?` for JWS and both nested JWE/JWS modes.
`WrapOptions` remains signer-driven. Encryption and agreement retain their implementations.

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

### Records migration to 0.7.0

`VerifiedRecordOp` now requires `contentDigest: string`. Verification computes it before returning the operation.
Verified operations contain frozen, owned claims and a protected digest. Synchronous decisions consume this carried digest.
Fixtures must obtain it through verification or an awaited digest of the exact fixture claim.
Persisted-operation reconstruction must verify the signed operation again before trusting its content digest.
No database schema migration is required for the carried field.

Params objects carry `methods?` and `crypto?` as top-level fields.

| Export | Arguments after migration | Result |
| --- | --- | --- |
| `recordClaimDigest` | `RecordClaimDigestParams` | `Promise<string>` |
| `recordPayloadDigest` | `RecordPayloadDigestParams` | `Promise<string \| null>` |
| `recordPayloadMatches` | `RecordPayloadMatchesParams` | `Promise<boolean>` |
| `recordDecisionDigest` | `{ record, opKind, methods?, crypto? }` | `Promise<string>` |
| `fingerprintRange` | `FingerprintRangeParams` | `Promise<string>` |
| `summarizeRange` | `SummarizeRangeParams` | `Promise<RangeSummary>` |
| `splitRange` | `{ leaves, rangeBounds, leafThreshold, crypto? }` | `Promise<Array<RangeSummary \| RangeLeafList>>` |
| `rangeLeaf` | `RangeLeafParams` | `Promise<RangeLeaf \| null>` |
| `nextRequesterSteps` | `NextRequesterStepsParams` | `Promise<Array<RequesterStep>>` |
| `advanceRecordPull` | `{ state, local, response, crypto? }` | `Promise<{ state: RecordPullState; steps: Array<RequesterStep> }>` |

`signRecordOp({ identity, claim, opKind, crypto? })` keeps its Promise result. Options select hashing, while the identity owns signing.
`verifyRecordOp({ opJWT, opKind, methods?, crypto? })` and `verifySignedRecord({ record, opKind, methods?, crypto? })` keep `Promise<VerifiedRecordOp | null>`.
`createRecordVerifier(params: CreateRecordVerifierParams)` remains synchronous and captures options for its asynchronous verifier.
`ApplyRecordChunkParams`, `RecordReceiveContext` and `VisibilityContext` gain `crypto?`.
`verifyHolderProof`, `visibleTo` and `filterVisibleRecords` keep their asynchronous contracts and forward that context.
`visibilityRules(rules)` keeps its signature. Its returned hook consumes the extended context.
Internal dependency checks carry `methods?` and provider options in named params objects and remain asynchronous.

`beginRecordPull`, ordering, policies, decisions and content comparisons remain synchronous.
Hashing preserves canonical bytes, string `meta.version` substitution, tombstones and range framing.
Payload checks must be awaited before persistence. A Promise itself is always truthy.
Provider operational failures reject rather than becoming invalid-input refusals.

```ts
const options = { crypto }
const op = await verifySignedRecord({
  record: record,
  opKind: opKind,
  methods: methods,
  ...options,
})
if (op !== null && (await recordPayloadMatches({ record, claim: op.claim, ...options }))) {
  const digest = op.contentDigest
  // Apply authorisation and persistence policy using this verified content.
}
```

## Vault API migration

All functions below accept top-level `crypto?` in named params objects and now require `await`.

| Export | Result |
| --- | --- |
| `digestParts(params: DigestPartsParams)` | `Promise<string>` |
| `vaultKeyDigest(params: VaultKeyDigestParams)` | `Promise<string>` |
| `vaultWrappingDigest(params: VaultWrappingDigestParams)` | `Promise<string>` |
| `vaultEntriesDigest(params: VaultEntriesDigestParams)` | `Promise<string>` |
| `vaultEntryDigest(params: VaultEntryDigestParams)` | `Promise<string>` |
| `descriptorDigest(params: DescriptorDigestParams)` | `Promise<string>` |
| `createVaultKeyID(params: CreateVaultKeyIDParams)` | `Promise<string>` |
| `createVaultKeyReference(params: CreateVaultKeyReferenceParams)` | `Promise<{ keyID: string; keyUnique: string }>` |
| `vaultRecordMeta(params: VaultRecordMetaParams)` | `Promise<VaultRecordMetas[Type] \| null>` |
| `decodeVaultRecord(params: DecodeVaultRecordParams)` | `Promise<DecodedVaultRecord>` |

`checkDescriptorDigest({ descriptors, expectedDescriptorDigest, crypto? })` now returns `Promise<void>`.
`VaultRecordTypeParams`, `WrapParams` and `UnwrapParams` gain `crypto?`.
`vaultRecordTypes` and `vaultProofAuthorizer` capture provider options at construction.
`vaultKeyVersionReader({ store, opKind, methods?, crypto? })` captures the provider and returns its existing asynchronous callback.
`vaultHolderTypes(types)`, `getSuite`, wrapping and unwrapping retain their return contracts.

Public metadata validation still checks owner/key-ID commitments. Internal structural parsing does not replace that validation boundary.
`compareVaultBranches` and `selectWinningBranch` remain synchronous and consume verified `contentDigest` values.
Canonical IDs, digests and encrypted formats remain unchanged. Provider errors propagate through decoding and authorisation.
SHA-256, X25519, HKDF, AES-GCM, BIP39 and randomness retain their existing implementations.

```ts
const { keyID, keyUnique } = await createVaultKeyReference({ owner: ownerDID, unique, crypto })
const meta = await vaultRecordMeta({ type: 'vault.key', claim, crypto })
const decoded = await decodeVaultRecord({ record, recordMeta, crypto })
await checkDescriptorDigest({ descriptors, expectedDescriptorDigest, crypto })
```

## Store integration

`VaultRecordsParams` and `VaultCoordinatorParams` gain `crypto?`. Their factories remain synchronous.
`createVaultRecords` captures options for verification, metadata validation, payload checks and projections.
`createVaultCoordinator` forwards one provider through records, suites, factors and adapters.
Replicated coordinators inherit the outer provider into `records`. Explicit unequal nested providers throw `TypeError` before work.
Omitted outer selection means noble, so a custom nested provider also conflicts.

```ts
import { createVaultCoordinator, createVaultRecords } from '@kokuin/store-vault'
import { createDelegationRevocationChecker } from '@kokuin/store-delegation'

const records = createVaultRecords({ ...recordsParams, crypto })
const coordinator = createVaultCoordinator({
  ...replicatedParams,
  mode: 'replicated',
  crypto,
  records: { ...replicatedParams.records, crypto },
})
const checkRevocation = createDelegationRevocationChecker({ api: delegationStore, crypto, methods })
```

The caller supplies complete existing configurations and one resolved `crypto` reference.
Raw SQL store factories gain no provider option. No SQL schema migration is required for carried operation digests.
Payload and metadata checks finish before persistence. Projection decoding finishes before deleting existing copies.
Joined transactions and the 500-parameter limit remain unchanged.

Controller-store merge callbacks must await authoritative verification:

```ts
await logs.merge(did, async (seen) => {
  const accepted = await authoritativeLog({ did, loaded: presented, seen, context: 'sync', crypto })
  return accepted.log
})
```

The caller imports `authoritativeLog` from `@kokuin/controller` and supplies the existing trusted history store.

### Identity-store options

| Package target | Provider entry points |
| --- | --- |
| node 0.7.0 | `NodeKeyStoreParams.crypto?`, constructor and `NodeKeyStore.open(params)` |
| electron 0.7.0 | `ElectronKeyStoreParams.crypto?`, constructor and `ElectronKeyStore.open(params?)` |
| expo 0.7.0 | Constructor and `ExpoKeyStore.open(options?)` accept `StoreEntryOptions & { crypto?: CryptoProvider }` |
| deterministic 0.7.0 | `HDKeyStoreParams.crypto?`, constructor, `fromSeed({ seed, basePath?, crypto? })`, `fromMnemonic({ mnemonic, basePath?, crypto? })` |

HD factory options retain `basePath?` alongside `crypto?`.
Node, Electron and Expo reject reopening cached stores with a different resolved provider reference.
Omission and explicit `nobleCrypto` are equivalent. Omission after custom-provider selection is a conflict.
Same-reference reopen succeeds. Equivalent-looking replacement provider objects still conflict.
`provideIdentitySync` on Node, Electron and Expo remains synchronous. Identity signing remains asynchronous.
Expo strips `crypto` before passing entry options to SecureStore.

## Provider option examples

The caller supplies real seed, log, loader, history, signed-token, verified capability payload, permission and audience values in these examples.

```ts
import { createControllerIdentity, createControllerResolver, createInception } from '@kokuin/controller'
import { nobleCrypto } from '@kokuin/crypto'
import type { CryptoProvider } from '@kokuin/crypto'
import { checkCapability } from '@kokuin/capability'
import { createSigningIdentity, verifyToken } from '@kokuin/token'

const crypto: CryptoProvider = nobleCrypto
const options = { crypto }
const identity = createSigningIdentity({ privateKey: seed, ...options })
const inception = await createInception({ seed, profile, ...options })
const controllerIdentity = await createControllerIdentity({ seed, profile, log, crypto })
const resolver = createControllerResolver({ loadLog, history, crypto })
const methods = [resolver.frozen()]
const verified = await verifyToken({ token: signed, crypto, methods, audience })
await checkCapability({ permission, payload: capabilityPayload, ...capabilityOptions, crypto, methods })
```

Algorithm overrides use existing `verifiers` options:

```ts
const verified = await verifyToken({ token: signed, crypto, methods, verifiers: { EdDSA: applicationEdDSAVerifier } })
```

The application supplies `applicationEdDSAVerifier`. It owns EdDSA policy, while missing ES256 overrides use the selected provider.
Reuse the same provider reference across software stores, resolver construction and verification options.

### Provider selection and retained paths

Omitted `crypto` resolves to strict `nobleCrypto`. Pass one resolved provider through identities, resolvers and verification constructors.
The six-method `CryptoProvider` contract comes from `@kokuin/crypto`.
`createNativeCrypto()` from `@kokuin/crypto-native` constructs the standalone Nitro provider explicitly.
Portable packages require no Nitro dependency. Node providers are available through `@kokuin/crypto-node` and `@kokuin/crypto-napi`. No browser WASM backend is delivered.

Default integration routes remain noble. No measured manifest is supplied with this handoff.
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
Sibling verification caches need equivalent provider, verifier and resolution-policy isolation.

Controller history trusts stored epoch authentication. Changing providers does not reauthenticate those stored copies.
Only authoritative accepted logs belong in that trusted storage. Untrusted presentations must pass authoritative verification before persistence.
Provider-isolated fold memos prevent cross-provider success reuse without changing this durable storage contract.

Providers must remain behaviourally immutable throughout their lifetime. Constructors capture references, not copies of provider implementations.
Replacing caller option fields cannot change captured policy. Mutating provider internals violates the contract.

## Verification expectations

These checks belong to downstream implementation. This handoff records no new downstream test execution.

1. Add six-method provider counters with owned input copies and controllable delay, refusal and rejection.
2. Assert exact cold-path method counts, ordered batch membership and preserved raw-message bytes.
3. Prime success under provider A, then verify identical inputs under rejecting provider B.
4. Repeat concurrently, through frozen resolution, and after settlement to prove failure eviction and retryability.
5. Test algorithm-specific overrides independently, proving missing overrides still invoke the provider.
6. Reject a unique provider sentinel and assert the identical error escapes every outer operation.
7. Delay provider completion, mutate caller-owned inputs, and assert authenticated outputs retain their original bytes.
8. Retain canonical DID, signature, operation hash, record digest and range fingerprint golden outputs wherever applicable.
9. Exercise correctly framed small-order and mixed-order signatures that the previous ZIP-215 policy accepted.
10. Retain ordinary-signature acceptance, ES256 low-S acceptance, high-S rejection and single raw-message hashing.
11. Check same-provider cache hits, cross-provider refusal, aggregate bounds and no successful caching of rejected work.
12. Recheck browser WebCrypto and Ledger signing counters without claiming physical hardware qualification.

Route verification needs the stored measured manifest from separate work. Unlisted and unmeasured integrated variants remain noble.
Promoted native-route failures must leave noble counters unchanged. Expanded mobile conformance and physical workload retesting remain release qualifications.

## Acceptance checks for membership and storage

- Cover recovery, membership management, revocation, lifecycle proofs and ledger checks with delayed and rejecting providers.
- Cover range sync, requester steps, tombstones, branch winners and convergence against literal golden outputs.
- Assert carried digests match verified immutable claims after suspended input mutation.
- Test payload mismatch and owner/key-ID commitment mismatch before persistence.
- Test rollback after an earlier draft write in standalone and ambient transactions.
- Catch a late provider failure inside an ambient transaction and verify existing copies survive its eventual commit.
- Test nested-provider conflicts before any provider call or storage mutation.
- Keep MLS cryptographic primitives and unrelated encryption paths outside this provider contract.

Route counters and physical workload evidence remain separate qualifications. This handoff claims portable propagation only.

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
| `NapiBinding.signBatch` | `Array<NapiBindingSignParams>` | `seeds, messages` |
| `NapiBinding.blake3` | `NapiBindingBlake3Params` | `input, length` |
| `NapiBinding.blake3Batch` | `NapiBindingBlake3BatchParams` | `inputs, length` |
| `NapiBinding.verify` | `NapiVerifyParams` | `es256, signature, message, publicKey` |
| `NapiBinding.verifyBatch` | `Array<NapiVerifyParams>` | `es256, signatures, messages, publicKeys` |

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
