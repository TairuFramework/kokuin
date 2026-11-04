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

| Package | Target range |
| --- | --- |
| `@kokuin/token` | `^0.7.0` |
| `@kokuin/capability` | `^0.6.0` |
| `@kokuin/controller` | `^0.3.0` |
| `@kokuin/records` | `^0.3.0` |
| `@kokuin/vault` | `^0.2.0` |
| `@kokuin/store-vault` | `^0.3.0` |
| `@kokuin/store-controller` | `^0.5.0` |
| `@kokuin/store-delegation` | `^0.4.0` |
| `@kokuin/jwe` | `^0.2.0` |
| `@kokuin/node` | `^0.5.0` |
| `@kokuin/browser` | `^0.3.0` |
| `@kokuin/deterministic` | `^0.3.0` |
| `@kokuin/electron` | `^0.5.0` |
| `@kokuin/expo` | `^0.5.0` |
| `@kokuin/ledger-device` | `^0.3.0` |
| `@kokuin/crypto` | `^0.2.0` |
| `@kokuin/crypto-native` | `^0.2.0`, only for explicit native construction |

Upgrade applicable packages only. Token, capability, browser, node and deterministic share the coordinated release window.
Controller, records and portable store migrations join that window. Electron and Expo retain independent SDK qualification.
Ledger has a minor intent for named error constructors. Its signing protocol is unchanged.
OAuth has a minor intent targeting 0.2.0 for its named error constructor. Private conformance packages remain unpublished.
The crypto validation-cache patch intent accompanies the breaking provider minor intent.

## Token, capability and envelope API differences

`CryptoOptions` from `@kokuin/token` is `{ crypto?: CryptoProvider }`.
`createSigningIdentityForDID(id, privateKey, options?)`, `createSigningIdentity(privateKey, options?)`,
`createFullIdentity(privateKey, options?)` and `randomIdentity(options?)` retain synchronous construction.
`createIdentity(input)` gains `input.crypto?` and retains its Promise result.
`VerifyTokenOptions` and `VerifySignedPayloadInput` gain `crypto?` without changing verification overloads.
`getVerifier(algorithm, verifiers?, options?)` appends provider options.
Each identity captures its signing provider. A verification option cannot replace an identity's signer.

`CreateCapabilityOptions`, `DelegationChainOptions` and `RevocationOptions` gain `crypto?`.
`createCapability`, `checkDelegationChain` and `checkCapability` retain their existing asynchronous contracts.
`createMemoryRevocationBackend` and `createRevocationChecker` capture provider options at construction.
`createDelegationRevocationChecker(api, options?: RevocationOptions)` forwards them through tracked wrappers.
Revocation verification always retains `historic: true`.
`unwrapEnvelope` accepts `UnwrapOptions.crypto?` for JWS and both nested JWE/JWS modes.
`WrapOptions` remains signer-driven. Encryption and agreement retain their implementations.

### Controller Promise migration

Functions with four or more arguments now accept named params objects. Existing parameter objects gain `crypto?: CryptoProvider`.
`CryptoOptions` comes from `@kokuin/token`. Every result below now requires `await`.

| Export | Arguments after migration | Result |
| --- | --- | --- |
| `createInception` | `seed, profile, options?` | `Promise<SignedEvent<InceptionEvent>>` |
| `verifyInception` | `signed, did, options?` | `Promise<boolean>` |
| `verifySignatures` | `{ event, sigs, keys, options? }` | `Promise<boolean>` |
| `createRotate` | `CreateRotateParams` including `crypto?` | `Promise<SignedEvent<RotateEvent>>` |
| `verifyRotate` | `signed, prior, options?` | `Promise<boolean>` |
| `createReset` | `{ seed, profile, gen, snapshot?, options? }` | `Promise<SignedEvent<RotateEvent>>` |
| `verifyReset` | `signed, inception, options?` | `Promise<boolean>` |
| `createAdd` | `CreateAddParams` including `crypto?` | `Promise<SignedEvent<AddEvent>>` |
| `createRenew` | `CreateRenewParams` including `crypto?` | `Promise<SignedEvent<RenewEvent>>` |
| `createRemove` | `CreateRemoveParams` including `crypto?` | `Promise<SignedEvent<RemoveEvent>>` |
| `createRevoke` | `CreateRevokeParams` including `crypto?` | `Promise<SignedEvent<RevokeEvent>>` |
| `verifyEpochSignature` | `signed, signer, options?` | `Promise<boolean>` |
| `foldLog` | `did, log, options?` | `Promise<FoldResult>` |
| `resolveBranches` | `did, chains, options?` | `Promise<ResolveResult>` |
| `authoritativeLog` | `{ did, loaded, seen, context, crypto? }` | `Promise<AuthoritativeLog>` |
| `epochHeads` | `did, log, options?` | `Promise<Array<string>>` |
| `mergeLogs` | `{ did, left, right, options? }` | `Promise<ControllerLog>` |
| `pruneLog` | `did, log, options?` | `Promise<ControllerLog>` |
| `deviceRevokeIndices` | `{ did, chain, subject, options? }` | `Promise<Array<number>>` |
| `deviceRevokeIndex` | `{ did, chain, subject, options? }` | `Promise<number \| undefined>` |
| `createDeviceRevoke` | `CreateDeviceRevokeParams` including `crypto?` | `Promise<SignedEvent>` |
| `createControllerIdentity` | `{ seed, profile, log, crypto? }` | `Promise<FullIdentity>` |
| `createControllerIdentityWithKey` | `{ privateKey, log, crypto? }` | `Promise<SigningIdentity>` |

`provideControllerIdentity({ entry, profile, logStore, crypto? })` already returns `Promise<FullIdentity>` and now forwards the provider.
`createControllerResolver({ loadLog, history?, crypto? })` remains synchronous. Its resolution methods remain asynchronous.
`createRotate` still requires a complete `snapshot`. Epoch builders retain their existing head, parent and signer fields.
`createReset({ seed, profile, gen, snapshot?, options? })` makes the snapshot optional within its params object.

The following source-module exports also became asynchronous. They are internal propagation points, without public package subpath exports.

| Source module | Function | Result |
| --- | --- | --- |
| `events.ts` | `signEvent(event, privateKeys, options?)` | `Promise<Array<string>>` |
| `epoch.ts` | `foldEpochDetailed(params)` | `Promise<FoldEpochDetail \| FoldEpochRefusal>` |
| `epoch.ts` | `foldEpoch(params)` | `Promise<FoldEpochResult \| FoldEpochRefusal>` |
| `log.ts` | `foldHeld({ did, log, limits?, options? })` | `Promise<HeldFold \| Extract<FoldResult, { ok: false }>>` |
| `log.ts` | `withEpoch({ did, states, events, limits?, trusted?, options? })` | `Promise<HeldFold \| Extract<FoldResult, { ok: false }>>` |
| `history.ts` | `authoritativeLogWithin(params, limits?)` | `Promise<AuthoritativeLog>` |
| `fold-memo.ts` | `memoizedAuthoritativeLog(params, limits?)` | `Promise<AuthoritativeLog>` |
| `state.ts` | `currentState({ did, log, context, options? })` | `Promise<KeyState>` |

`FoldEpochParams` and `AuthoritativeLogParams` include `crypto?`.
Internal `createControllerResolverWithin` remains synchronous and accepts the extended resolver options.
`didFor`, `didFromInception`, canonicalisation, SHA-256 digests, key derivation and `enumerateProfiles` remain synchronous.
`appliedCopies`, `keyStateAt`, `snapshotOf`, state-view selectors and memory-store construction also remain synchronous.

### Records migration to 0.3.0

`VerifiedRecordOp` now requires `contentDigest: string`. Verification computes it before returning the operation.
Verified operations contain frozen, owned claims and a protected digest. Synchronous decisions consume this carried digest.
Fixtures must obtain it through verification or an awaited digest of the exact fixture claim.
Persisted-operation reconstruction must verify the signed operation again before trusting its content digest.
No database schema migration is required for the carried field.

Params objects carry `methods?` and `options?: CryptoOptions` for APIs that previously exceeded three arguments.

| Export | Arguments after migration | Result |
| --- | --- | --- |
| `recordClaimDigest` | `claim, options?` | `Promise<string>` |
| `recordPayloadDigest` | `payload, options?` | `Promise<string \| null>` |
| `recordPayloadMatches` | `record, claim, options?` | `Promise<boolean>` |
| `recordDecisionDigest` | `{ record, opKind, methods?, options? }` | `Promise<string>` |
| `fingerprintRange` | `leaves, options?` | `Promise<string>` |
| `summarizeRange` | `leaves, bounds, options?` | `Promise<RangeSummary>` |
| `splitRange` | `{ leaves, rangeBounds, leafThreshold, cryptoOptions? }` | `Promise<Array<RangeSummary \| RangeLeafList>>` |
| `rangeLeaf` | `decision, policy, options?` | `Promise<RangeLeaf \| null>` |
| `nextRequesterSteps` | `local, response, options?` | `Promise<Array<RequesterStep>>` |
| `advanceRecordPull` | `{ state, local, response, options? }` | `Promise<{ state: RecordPullState; steps: Array<RequesterStep> }>` |

`signRecordOp({ identity, claim, opKind, options? })` keeps its Promise result. Options select hashing, while the identity owns signing.
`verifyRecordOp({ opJWT, opKind, methods?, options? })` and `verifySignedRecord({ record, opKind, methods?, options? })` keep `Promise<VerifiedRecordOp | null>`.
`createRecordVerifier(opKind, methods?, options?)` remains synchronous and captures options for its asynchronous verifier.
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
  options: options,
})
if (op !== null && (await recordPayloadMatches(record, op.claim, options))) {
  const digest = op.contentDigest
  // Apply authorisation and persistence policy using this verified content.
}
```

## Vault API migration

All functions below accept appended `options?: CryptoOptions` and now require `await`.

| Export | Result |
| --- | --- |
| `digestParts(parts, options?)` | `Promise<string>` |
| `vaultKeyDigest(key, options?)` | `Promise<string>` |
| `vaultWrappingDigest(wrapping, options?)` | `Promise<string>` |
| `vaultEntriesDigest(entries, options?)` | `Promise<string>` |
| `vaultEntryDigest(entry, options?)` | `Promise<string>` |
| `descriptorDigest(descriptors, options?)` | `Promise<string>` |
| `createVaultKeyID(owner, unique, options?)` | `Promise<string>` |
| `createVaultKeyReference(owner, unique, options?)` | `Promise<{ keyID: string; keyUnique: string }>` |
| `vaultRecordMeta(type, claim, options?)` | `Promise<VaultRecordMetas[Type] \| null>` |
| `decodeVaultRecord(record, recordMeta, options?)` | `Promise<DecodedVaultRecord>` |

`checkDescriptorDigest({ descriptors, expectedDescriptorDigest, crypto? })` now returns `Promise<void>`.
`VaultRecordTypeParams`, `WrapParams` and `UnwrapParams` gain `crypto?`.
`vaultRecordTypes` and `vaultProofAuthorizer` capture provider options at construction.
`vaultKeyVersionReader(store, { opKind, methods?, crypto? })` captures the provider and returns its existing asynchronous callback.
`vaultHolderTypes(types)`, `getSuite`, wrapping and unwrapping retain their return contracts.

Public metadata validation still checks owner/key-ID commitments. Internal structural parsing does not replace that validation boundary.
`compareVaultBranches` and `selectWinningBranch` remain synchronous and consume verified `contentDigest` values.
Canonical IDs, digests and encrypted formats remain unchanged. Provider errors propagate through decoding and authorisation.
SHA-256, X25519, HKDF, AES-GCM, BIP39 and randomness retain their existing implementations.

```ts
const { keyID, keyUnique } = await createVaultKeyReference(ownerDID, unique, { crypto })
const meta = await vaultRecordMeta('vault.key', claim, { crypto })
const decoded = await decodeVaultRecord(record, recordMeta, { crypto })
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
const checkRevocation = createDelegationRevocationChecker(delegationStore, { crypto, methods })
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
| node 0.5.0 | `NodeKeyStoreParams.crypto?`, constructor and `NodeKeyStore.open(params)` |
| electron 0.5.0 | `ElectronKeyStoreParams.crypto?`, constructor and `ElectronKeyStore.open(params?)` |
| expo 0.5.0 | Constructor and `ExpoKeyStore.open(options?)` accept `StoreEntryOptions & { crypto?: CryptoProvider }` |
| deterministic 0.3.0 | `HDKeyStoreParams.crypto?`, constructor, `fromSeed(seed, options?)`, `fromMnemonic(mnemonic, options?)` |

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
const identity = createSigningIdentity(seed, options)
const inception = await createInception(seed, profile, options)
const controllerIdentity = await createControllerIdentity({ seed, profile, log, crypto })
const resolver = createControllerResolver({ loadLog, history, crypto })
const methods = [resolver.frozen()]
const verified = await verifyToken(signed, { crypto, methods, audience })
await checkCapability(permission, capabilityPayload, { ...capabilityOptions, crypto, methods })
```

Algorithm overrides use existing `verifiers` options:

```ts
const verified = await verifyToken(signed, {
  crypto,
  methods,
  verifiers: { EdDSA: applicationEdDSAVerifier },
})
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
| `createCapability` | `CreateCapabilityParams` | `signer, payload, header?, options?` |
| `new TokenRevokedError` | `TokenRevokedErrorParams` | `jti, options?` |

### @kokuin/controller

| Export | Named params type | Fields |
| --- | --- | --- |
| `deriveKeyMaterial` | `DeriveKeyMaterialParams` | `seed, path, alg, length?` |
| `mergeLogs` | `MergeLogsParams` | `did, left, right, options?` |
| `verifySignatures` | `VerifySignaturesParams` | `event, sigs, keys, options?` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?, options?` |
| `deviceRevokeIndices` | `DeviceRevokeIndicesParams` | `did, chain, subject, options?` |
| `deviceRevokeIndex` | `DeviceRevokeIndexParams` | `did, chain, subject, options?` |

### @kokuin/controller-conformance

| Export | Named params type | Fields |
| --- | --- | --- |
| `ControllerImplementation.createRotate` | `CreateRotateParams` | `seed, profile, did, prior, snapshot` |
| `createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?` |
| `ControllerImplementation.authorityPrivateKey` | `AuthorityPrivateKeyParams` | `seed, profile, gen, seq` |

### @kokuin/crypto-napi

| Export | Named params type | Fields |
| --- | --- | --- |
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
| `signRecordOp` | `SignRecordOpParams` | `identity, claim, opKind, options?` |
| `verifyRecordOp` | `VerifyRecordOpParams` | `opJWT, opKind, methods?, options?` |
| `verifySignedRecord` | `VerifySignedRecordParams` | `record, opKind, methods?, options?` |
| `recordDecisionDigest` | `RecordDecisionDigestParams` | `record, opKind, methods?, options?` |
| `compareRecordOps` | `CompareRecordOpsParams` | `incoming, stored, policy, onEqual?` |
| `new RecordTypeGraphError` | `RecordTypeGraphErrorParams` | `message` |
| `new RecordContentRefusalError` | `RecordContentRefusalErrorParams` | `message` |
| `new RecordRangeError` | `RecordRangeErrorParams` | `message, options?` |
| `splitRange` | `SplitRangeParams` | `leaves, rangeBounds, leafThreshold, cryptoOptions?` |
| `advanceRecordPull` | `AdvanceRecordPullParams` | `state, local, response, options?` |

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
`Identity.id`, `KeyEntry.keyID`, `NapiCrypto.backend` and `NapiCrypto.failure` omit TypeScript `readonly`.
Their runtime property behaviour remains unchanged.

`VaultSecretUnverifiableParams` names the existing `UnverifiableWrapping` constructor object without changing its shape.
