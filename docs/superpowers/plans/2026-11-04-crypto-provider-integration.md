# Crypto Provider Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route existing identity, controller, record and vault operations through immutable injected crypto providers without changing canonical bytes.

**Architecture:** Capture `crypto?: CryptoProvider` at construction and forward the resolved provider through nested operations. Default to strict `nobleCrypto`. Make verification-dependent controller work and provider-backed hashing asynchronous. Carry verified record content digests into synchronous comparisons.

**Tech Stack:** TypeScript, pnpm 12.16.1, Vitest, noble, Nitro, Rust, `@hozon/db`.

**Spec:** `docs/agents/plans/backlog/2026-10-27-crypto-provider-integration.md` (binding, read fully before execution).

**Status:** Research complete. Implementation has not started. No tests, installs, builds, benchmarks, version changes or git writes ran during planning.

**Baseline:** User-specified `feat/crypto-provider-integration`, origin/main `075dc61`. Source coordinates below refer to the inspected checkout.

## Global constraints

- The user waived the formal physical benchmark gate **for starting migration**. Phone benchmarks already show significant speedup.
- The measured route manifest still controls routes. Unmeasured and losing variants stay on noble.
- Expanded conformance remains required before production-readiness claims. The waiver does not qualify new routes.
- Preserve canonical bytes, DIDs, operation hashes, record digests and range fingerprints.
- Preserve custom verifier overrides. Missing algorithm overrides use the selected provider.
- Native registration, ABI and execution failures propagate without dynamic fallback.
- Keep provider behaviour immutable for its lifetime. No mutable global selection.
- Keep strict Ed25519 canonical/subgroup checks and low-S compact ES256 verification over raw messages hashed once.
- Hardware signing, browser WebCrypto signing, public-key derivation and key agreement retain their current paths.
- SHA-256, X25519, HKDF, AES-GCM, BIP39 and random generation remain outside the provider.
- Store changes use `withStoreTransaction`. No statement binds more than 500 parameters.
- Cross-repo dependencies use published `^` ranges. Internal package dependencies use `workspace:`.
- Node N-API and browser WASM backends remain separate future work.
- Downstream implementation and publication require separate authorisation. This document does not authorise either.

Read also `AGENTS.md`, `docs/agents/development.md`, the completed standalone delivery, and `packages/crypto/src/{types,noble,index}.ts`.
The standalone packages remain at 0.1.0. Their async contract already supplies all six single/batch methods needed here.

## Review focus

1. A permissive provider must never prime a verification cache for a rejecting provider. PRs 1–3 own regression tests.
2. A provider rejection must escape malformed-input refusal paths. PRs 1–4 own sentinel-error tests.
3. A caller mutating claims or payloads during suspension must not detach a carried digest from authenticated bytes. PR 3 owns snapshot tests.
4. Hostile epoch events must retain deterministic failed-signature accounting and causal order. PR 2 owns counter-based budget tests.
5. Async payload validation must finish before persistence, including ambient transactions and vault projections. PRs 3–4 own rollback tests.

## Source map and counting method

Appendix A inventories call expressions in each requested package's `src/*.ts`, using TypeScript's parser without compilation.
It excludes imports, comments, declarations, generated files and ordinary unit tests. Private conformance source is included.
Counts represent static call expressions, not runtime invocations. Multiple calls on one line count separately.
Rows include provider primitives, forwarding calls and async propagation points. Counts deliberately include signer delegation whose API remains asynchronous.
Custom capability hook invocations are labelled separately. They must not be mistaken for cryptographic verification.
The primitive subset contains **13 calls**: token 4, controller 2, records 5, vault 2.
Public-key derivation and retained hardware/WebCrypto signing are recorded separately in Appendix B.
Appendix A also covers source-module exports absent from package barrels where those modules need signature changes.

Implementation file responsibilities:

| Files | Responsibility |
| --- | --- |
| `packages/token/src/identity.ts`, `token.ts`, `verifier.ts`, `verified-memo.ts` | Capture signing providers, select verifiers and isolate both verification caches |
| `packages/capability/src/types.ts`, `delegation.ts`, `revocation.ts` | Forward provider through parents, chains and revocation verification |
| `packages/jwe/src/index.ts` | Forward unwrap provider through both JWS verification branches |
| `packages/controller/src/events.ts`, `epoch-events.ts`, `epoch.ts`, `fold.ts` | Async signing and causally ordered verification |
| `packages/controller/src/{log,history,fold-memo,resolver,supersede,state,identity,keystore-identity,device-revoke,profiles}.ts` | Complete async propagation, cache isolation and synchronous profile enumeration |
| `packages/controller-conformance/src/index.ts` | Async implementation contract and awaited test helpers |
| `packages/records/src/{op,record,range,reconcile}.ts` | Async digest and reconciliation operations, captured claims |
| `packages/records/src/{decision,policy,apply,visibility}.ts` | Carried digests, async payload checks and provider propagation |
| `packages/vault/src/{digest,id,records,record-types,branch,suite}.ts` | Provider hashing, async validation and synchronous branch comparisons |
| `packages/store-vault/src/` | Forward provider through coordinator, adapter, projections and record validation |
| `packages/{node,electron,expo,deterministic}/src/store.ts` | Immutable provider capture, identity construction and reopen conflicts |
| `packages/store-delegation/src/revocation-checker.ts` | Preserve provider while tracking revocation dependency failures |
| `packages/store-controller/src/api.ts` | Existing async callback contract remains sufficient |

## API notation and decisions

`CryptoOptions` below means the structural type `{ crypto?: CryptoProvider }`, defaulting to `nobleCrypto`.
Export one such named type from token for identity helpers. Other packages may use equivalent local option types.
Append an options parameter to positional APIs. Extend existing parameter objects instead of inserting positional arguments.
Preserve `methods?: MethodRegistry` positions on record APIs and append `options?: CryptoOptions` after them.
An existing Promise remains a Promise unless explicitly stated. Generic type parameters and overload narrowing remain intact.
Provider identity uses object reference equality after resolving the default. Omission and explicit `nobleCrypto` mean the same provider.
Custom verifier policy is captured per algorithm by function identity. Mutating the caller's overrides object cannot alter captured policy.
The public `isVerifiedToken` predicate continues to indicate prior verification, not acceptance under every provider.
`verifyToken` alone decides whether provenance matches its requested provider, verifier and resolution context.

## Phase split and independently green PRs

No intermediate PR is published. Every PR updates all workspace callers of its changed types before merge.
A PR may include mechanical dependent-package changes required for a green workspace. These belong with the breaking API, not a later PR.
Do not introduce temporary synchronous noble shims. They would violate provider routing and disappear at the next phase.

### PR 1: Token, capability and JWE provider threading

**Exported API diffs:**

| Location | Change |
| --- | --- |
| `token/src/identity.ts:84` | `createSigningIdentityForDID(id, privateKey, options?: CryptoOptions): SigningIdentity` |
| `token/src/identity.ts:142` | `createSigningIdentity(privateKey, options?: CryptoOptions): SigningIdentity` |
| `token/src/identity.ts:185` | `createFullIdentity(privateKey, options?: CryptoOptions): FullIdentity` |
| `token/src/identity.ts:194` | `randomIdentity(options?: CryptoOptions): OwnIdentity` |
| `token/src/identity.ts:493` | `createIdentity(input: CreateIdentityInput & CryptoOptions): Promise<MultiKeyIdentity>` |
| `token/src/token.ts:41,114,132,397–412` | Add `crypto?` to `VerifyTokenOptions` and `VerifySignedPayloadInput`. Preserve all `verifyToken` overloads |
| `token/src/verifier.ts:42` | `getVerifier(algorithm, verifiers?: Verifiers, options?: CryptoOptions): Verifier` |
| `capability/src/types.ts:6,35` | Add `crypto?` to `DelegationChainOptions` and `CreateCapabilityOptions` |
| `capability/src/delegation.ts:50,172,244` | `createCapability`, `checkDelegationChain`, `checkCapability` accept provider through their existing options |
| `capability/src/revocation.ts:91,119,191` | Add `crypto?` to `RevocationOptions`, used by `createMemoryRevocationBackend` and `createRevocationChecker` |
| `jwe/src/index.ts:457` | Add `crypto?` to `UnwrapOptions`, consumed by `unwrapEnvelope` |

No token identity factory becomes asynchronous solely for provider capture.
`signToken`, capability creation and `createRevocationRecord` still sign through the supplied identity.
Do not add a per-token provider override that can replace the identity's captured signer.
`WrapOptions` remains signer-driven. All three wrapping branches already await signing.

- [ ] Add `provider-routing.test.ts` in token, capability and JWE test directories.
- [ ] Assert both EdDSA sign sites use the injected provider with the exact raw signing bytes.
- [ ] Assert ES256 uses compact signature bytes and a raw message, with no caller-side SHA-256.
- [ ] Assert an EdDSA override suppresses provider EdDSA calls while missing ES256 override invokes the provider.
- [ ] Assert parent, chain, revocation-backend and revocation-checker paths all reach the selected provider.
- [ ] Extend `revocation.ts:108`'s `verifyOptions` return `Pick` and object with `crypto`, preserving mandatory `historic: true`.
- [ ] Assert both unwrap branches route verification, including nested JWE/JWS modes.
- [ ] Partition the signature memo by resolved provider and algorithm. Retain all existing size and byte limits.
- [ ] Store policy provenance for verified-token objects. Reverify objects crossing provider, override or relevant resolver/method contexts.
- [ ] Snapshot relevant signature, key, message and policy inputs before yielding to asynchronous verification.
- [ ] Preserve time, audience, historic, mutation and custom-verifier behaviour on cache hits.
- [ ] Add explicit rejection tests proving failed provider operations do not populate either cache.
- [ ] Update provider documentation and changed option exports in package barrels.

**Green boundary:** Existing callers need no syntax changes. Strict verification starts here, so ZIP-215-dependent tests change in this PR.
Store-delegation's existing `RevocationOptions` parameter gains `crypto?` structurally. Test its tracked-options spread here or in PR 4.

### PR 2: Complete controller async migration

**Exported API diffs:** Every function in this table gains provider selection and wraps its previous result in `Promise` unless stated otherwise.

| Location | Export and result after migration |
| --- | --- |
| `controller/src/events.ts:82` | Source-module `signEvent(event, privateKeys, options?): Promise<Array<string>>` |
| `controller/src/events.ts:140` | `verifySignatures(event, sigs, keys, options?): Promise<boolean>` |
| `controller/src/events.ts:180,221` | `createInception(seed, profile, options?): Promise<SignedEvent<InceptionEvent>>`. `verifyInception(signed, did, options?): Promise<boolean>` |
| `controller/src/events.ts:359,453` | `createRotate(params & CryptoOptions): Promise<SignedEvent<RotateEvent>>`. `verifyRotate(signed, prior, options?): Promise<boolean>` |
| `controller/src/events.ts:503,561` | `createReset(seed, profile, gen, snapshot?, options?): Promise<SignedEvent<RotateEvent>>`. `verifyReset(signed, inception, options?): Promise<boolean>` |
| `controller/src/epoch-events.ts:172,186,196,208` | `createAdd`, `createRenew`, `createRemove`, `createRevoke`: extend parameter objects with `crypto?`, return `Promise<SignedEvent<E>>` |
| `controller/src/epoch-events.ts:303` | `verifyEpochSignature(signed, signer, options?: CryptoOptions): Promise<boolean>` |
| `controller/src/fold.ts:491` | `foldLog(did, log, options?): Promise<FoldResult>` |
| `controller/src/supersede.ts:209` | `resolveBranches(did, chains, options?): Promise<ResolveResult>` |
| `controller/src/history.ts:199` | `authoritativeLog(params: AuthoritativeLogParams & CryptoOptions): Promise<AuthoritativeLog>` |
| `controller/src/log.ts:131,225,261` | `epochHeads`, `mergeLogs`, `pruneLog`: append options, return `Promise` of former result |
| `controller/src/device-revoke.ts:25,51,68` | `deviceRevokeIndices`, `deviceRevokeIndex`: append options, return `Promise<Array<number>>` / `Promise<number | undefined>`. `createDeviceRevoke(params & CryptoOptions): Promise<SignedEvent>` |
| `controller/src/identity.ts:168,200` | `createControllerIdentity(params & CryptoOptions): Promise<FullIdentity>`. `createControllerIdentityWithKey(params & CryptoOptions): Promise<SigningIdentity>` |
| `controller/src/keystore-identity.ts:24` | `provideControllerIdentity(params & CryptoOptions): Promise<FullIdentity>` (already async) |
| `controller/src/resolver.ts:12,67` | `ControllerResolverOptions` gains `crypto?`. `createControllerResolver` stays synchronous |
| `controller-conformance/src/index.ts:123` | Seven `ControllerImplementation` members become Promise-returning: inception, rotate, reset, fold, branch resolution, epoch creation and test signing |

Confirm exact existing result aliases when editing. `createControllerIdentityWithKey` retains its existing identity capabilities.
Internal source exports also change: `foldEpochDetailed:371`, `foldEpoch:580`, `foldHeld:69`, `withEpoch:92`, `authoritativeLogWithin:207`,
`memoizedAuthoritativeLog:76`, and `currentState:25` become async and accept/forward the selected provider.
`createControllerResolverWithin:75` keeps its return type and extends its options.
`appliedCopies`, `keyStateAt`, `snapshotOf`, state-view selectors and memory-store construction remain synchronous.
`didFor`, `didFromInception`, canonicalisation, SHA-256 digest helpers, derivation and profile enumeration remain synchronous.

- [ ] Add controller provider counter, operational-failure and fold-memo isolation tests before changing implementations.
- [ ] Implement `signEvent` with ordered `signBatch` and `verifySignatures` with bounded ordered `verifyBatch` calls.
- [ ] Keep parsing and canonicalisation refusal catches outside the awaited provider operation.
- [ ] Await chain events and epoch candidates in their existing causal evaluation order.
- [ ] Keep failed-signature charging unchanged. Never batch speculative verification across hostile event candidates.
- [ ] Preserve `MAX_EVENT_SIGNATURES = 16` and `MAX_FAILED_SIGNATURES = 64` from `controller/src/limits.ts`.
- [ ] Forward provider through all Appendix A controller sites, including current-state and identity construction.
- [ ] Replace `enumerateProfiles` signing with `didFor(seed, index)` at `profiles.ts:57`.
- [ ] Replace reset's throwaway inception signing with unsigned inception derivation where only its body is needed.
- [ ] Partition fold memo by provider identity while retaining `FOLD_MEMO_SIZE = 256`, default-limit rules and success-only entries.
- [ ] Await authoritative folds before accessing `.result` or storing settled-success memo entries.
- [ ] Preserve in-flight sharing, `finally` eviction, frozen-view retry and unchanged-log object identity.
- [ ] Convert controller conformance tests and local helper functions to await their implementation contract.
- [ ] Update all controller tests, workspace integration fixtures and device builders in the same PR.
- [ ] Test synchronous profile enumeration with a provider that throws if any signing or verification method runs.

**Green boundary:** Include `tests/integration/test/store-controller.test.ts` and every other workspace consumer discovered by a symbol query.
`ControllerStoreAPI.merge` already accepts Promise-returning callbacks. No store-controller API change is needed.
Controller-conformance remains framework-agnostic and must not import controller.

### PR 3: Records async hashing and carried content digests, with mandatory vault consumer updates

**Exported API diffs:**

| Location | Change |
| --- | --- |
| `records/src/op.ts:23` | Required `VerifiedRecordOp.contentDigest: string` |
| `records/src/record.ts:61` | `recordClaimDigest(claim, options?): Promise<string>` |
| `records/src/record.ts:169,174` | `recordPayloadDigest(payload, options?): Promise<string | null>`. `recordPayloadMatches(record, claim, options?): Promise<boolean>` |
| `records/src/op.ts:160` | `signRecordOp(identity, claim, opKind, options?): Promise<{ opJWT: string; opHash: string }>` |
| `records/src/op.ts:215,269,302` | `verifyRecordOp`, `verifySignedRecord`, `createRecordVerifier`: append `options?` after `methods?`, retain current results |
| `records/src/decision.ts:56` | `recordDecisionDigest(record, opKind, methods?, options?): Promise<string>` |
| `records/src/range.ts:108,158,176,239` | `fingerprintRange`, `summarizeRange`, `splitRange`, `rangeLeaf`: append options and return `Promise` of former result |
| `records/src/reconcile.ts:89,157` | `nextRequesterSteps`, `advanceRecordPull`: append options and return `Promise` of former result |
| `vault/src/records.ts:330` | `decodeVaultRecord(record, meta): Promise<DecodedVaultRecord>` becomes async here because it calls `recordPayloadDigest` |
| `records/src/apply.ts:178,606` | `ApplyRecordChunkParams` gains `crypto?`. `applyRecordChunk` remains async |
| `records/src/visibility.ts:190,310,331,348` | `verifyHolderProof`, `visibleTo`, `visibilityRules`, `filterVisibleRecords` consume provider through `VisibilityContext` |

`visibilityRules(rules)` keeps its signature and returns a hook accepting the extended context. The other visibility exports already return Promises.
Internal dependency helpers `apply.ts:393,403` append options and remain async.
`RecordReceiveContext`, `VisibilityContext` and internal chunk contexts carry the selected provider.
`beginRecordPull`, range ordering, policies, decisions, visibility comparisons and apply comparisons remain synchronous.

- [ ] Freeze literal pre-migration golden digest and fingerprint fixtures before replacing noble calls.
- [ ] Capture canonical claims synchronously before the first suspension in every claim-hashing and signing entry point.
- [ ] Decode verified claims into owned storage and compute `contentDigest` before returning `VerifiedRecordOp`.
- [ ] Preserve string `meta.version` substitution for digest HLC. Other metadata and claim bytes remain unchanged.
- [ ] Copy `contentDigest` through memo entries, `copyOp`, decisions and all hand-built fixtures.
- [ ] Replace synchronous `recordClaimDigest(op.claim)` comparisons with `op.contentDigest` throughout Appendix A.
- [ ] Partition op memos by provider and relevant verification policy. Preserve the self-certifying issuer rules and 1024-entry bound.
- [ ] Forward provider through op hashing, signature verification, payload checking, ranges and requester reconciliation.
- [ ] Snapshot payload byte views before suspension where callers retain mutable ownership.
- [ ] Await each payload check at its existing authorisation boundary before persistence.
- [ ] Preserve signer queues for prompting and hardware identities. Hashing must not overlap hardware signing requests.
- [ ] Update `range.ts`'s locally constructed `orderOf` input for the new required field without inventing a fake digest.
- [ ] Narrow `orderOf` to the actual claim/opHash fields it reads, or pass the decision's carried digest.
- [ ] Update every vault and store-vault caller of record hashing and every `VerifiedRecordOp` fixture in this PR.
- [ ] Test golden fixtures, mutation across suspension, tombstones, convergence and rollback on provider rejection.

**Green boundary:** Records cannot land alone with broken vault consumers.
This PR includes the mechanical awaits in vault/store-vault, synchronous branch comparisons using carried digests, and necessary helper async propagation.
For `records-rows.ts:159–160`, the altered metadata claim is not the authenticated op. Compute its digest asynchronously for the comparison.
For untouched verified claims at `records-rows.ts:193` and `records-adapter.ts:196`, consume `contentDigest` directly.
The separate identity/store PR below completes vault's own BLAKE3 routing and all outer provider configuration.

### PR 4: Identity stores, vault hashing and store integration

**Exported API diffs:**

| Location | Change |
| --- | --- |
| `node/src/store.ts:17,43,63` | `NodeKeyStoreParams`, constructor and `open` accept `crypto?` |
| `electron/src/store.ts:20,45,76` | `ElectronKeyStoreParams`, constructor and `open` accept `crypto?` |
| `expo/src/store.ts:22,30` | Constructor and `open` accept `StoreEntryOptions & CryptoOptions` without passing provider to SecureStore |
| `deterministic/src/store.ts:16,29,34,38` | `HDKeyStoreParams`, constructor, `fromMnemonic`, `fromSeed` accept `crypto?` |
| `vault/src/digest.ts:14,42,46,56,66,71` | `digestParts`, `vaultKeyDigest`, `vaultWrappingDigest`, `vaultEntriesDigest`, `vaultEntryDigest`, `descriptorDigest`: append options, return `Promise<string>` |
| `vault/src/digest.ts:75` | `checkDescriptorDigest(params & CryptoOptions): Promise<void>` |
| `vault/src/id.ts:9,21` | `createVaultKeyID(owner, unique, options?): Promise<string>`. `createVaultKeyReference(owner, unique, options?): Promise<{ keyID: string; keyUnique: string }>` |
| `vault/src/records.ts:167,330` | `vaultRecordMeta(type, claim, options?): Promise<VaultRecordMetas[Type] | null>`. `decodeVaultRecord(record, meta, options?): Promise<DecodedVaultRecord>` adds provider options after becoming async in PR 3 |
| `vault/src/record-types.ts:67,492,500,509,539` | Add `crypto?` to `VaultRecordTypeParams`, used by `vaultRecordTypes` and `vaultProofAuthorizer`. Extend `vaultKeyVersionReader`'s `Pick` to include `crypto` |
| `vault/src/suite.ts:76,98` | Add `crypto?` to `WrapParams` and `UnwrapParams`. `getSuite`, wrapping and unwrapping retain return types |
| `store-vault/src/records.ts:46,87` | `VaultRecordsParams` inherits `crypto?`. `createVaultRecords` stays synchronous |
| `store-vault/src/coordinator-types.ts:131` | `VaultCoordinatorParams` gains `crypto?`. `createVaultCoordinator` stays synchronous |
| `store-delegation/src/revocation-checker.ts:174` | `createDelegationRevocationChecker(api, options?: RevocationOptions)` gains provider through existing options |

`vaultHolderTypes(types)` keeps its exact signature. It only selects an existing type definition.
No new provider option is needed for raw SQL storage construction, store-controller, browser WebCrypto identity construction, OAuth or Ledger signing.
Node/Electron/Expo `provideIdentitySync` remain synchronous. They only provision keys and capture an asynchronous signer.
`compareVaultBranches` and `selectWinningBranch` retain their signatures and consume carried digests after PR 3.
Source-module helpers in store-vault gain provider via their existing `Bound`/context objects. They need not expose new public factories.

- [ ] Capture resolved provider in Node, Electron, Expo and HD store constructors.
- [ ] Forward the captured provider at all seven identity construction sites in Appendix A.
- [ ] Reject reopen conflicts using resolved provider equality, including omitted-default versus previously selected custom provider.
- [ ] Test default→custom, custom→omitted, custom→different, same→same and default→explicit-noble reopen cases.
- [ ] Route vault's two direct BLAKE3 sites and all digest helper calls through the selected provider.
- [ ] Implement private synchronous metadata parsing for policy version readers and dependency enumeration.
- [ ] Keep `vaultRecordMeta`'s existing owner/key-ID commitment check in its asynchronous public validation path.
- [ ] Run full async metadata validation at every existing structural precheck/authorisation/persistence boundary.
- [ ] Keep `entryOrder`, `keyOrder` and synchronous dependencies on the private structural parser only.
- [ ] Await async `decodedAs`, metadata validation and `decodeVaultRecord` callers, including SQL projections.
- [ ] Snapshot metadata, unique bytes, descriptors and record payloads before suspending for provider work.
- [ ] Forward one provider through coordinator records, record contexts, suite wrapping, factor digest checks and store adapters.
- [ ] Resolve coordinator and nested record options once. Reject explicitly conflicting nested providers before any work.
- [ ] Preserve provider options through store-delegation's tracked dependency wrappers.
- [ ] Retain sentinel provider errors through vault decoding, record verification and capability refusal catches.
- [ ] Test mismatch-before-persistence and provider-rejection rollback under standalone and ambient transactions.
- [ ] Verify browser and Ledger counters show zero provider signing calls and unchanged retained signing behaviour.

**Green boundary:** Complete vault codec option forwarding and update digest/key-reference fixtures with awaits in this PR.
Keep database transaction joining and 500-parameter limits unchanged. No schema migration is needed for ephemeral carried digests.
Shared keystore-conformance has no identity signing contract today. Add provider cases to backend identity tests rather than widening key-entry conformance unnecessarily.

### PR 5: Release preparation, documentation and downstream handoff

- [ ] Document every API delta above in package migration notes and provider adoption documentation.
- [ ] Record strict verification as a coordinated 0.x minor cutover, including controller and records.
- [ ] Publish no historical rescan or version gate. Reverification applies strict policy immediately.
- [ ] Explain custom verifier precedence and that custom overrides own their verification policy.
- [ ] Verify the selected route manifest against final module behaviour using route counters.
- [ ] Run shared mobile conformance and injected-provider integration checks on the final module during implementation.
- [ ] Retest retained physical workloads before retaining production routes. Remove routes failing the agreed performance criterion.
- [ ] Prepare separate self-contained enkaku and kumiai handoffs using the exact released versions below.
- [ ] Record pnpm minor intents and preview the release graph after registry publication status is known.

**Green boundary:** Documentation, release intents and dependency version changes only. No new API changes in this PR.
Publication and downstream edits remain separate actions.

## Verification strategy for future execution

These are planned checks, not checks performed in this research turn.
For each implementation PR, first run focused failing regressions, then implementation, then focused passing regressions.
Use `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter <package> exec vitest run test/<specific-file>.test.ts`.
Run affected-package `test:types` and the workspace type checks after updating callers.
Before merging each PR, run the repository's required unit/type/integration checks and inspect their actual results.
Hardware/mobile checks run in the appropriate later environment. Do not infer their success from portable tests.

### Provider counters and routing

Use a delegating test provider with six counters, captured immutable input copies and controllable resolution/rejection.
Keep an independent expected-results oracle. Compare byte results with pre-migration constants, not another migrated helper.
Cold-cache assertions require the exact provider method and item count, including batch membership and order.
Warm-cache assertions require only the documented same-policy successes to skip provider work.
An injected provider returning false must change verification outcomes. A provider rejecting a unique sentinel error must reject the outer operation identically.
Those outcome tests catch direct noble calls that positive counters on unrelated calls could miss.
Test mixed providers concurrently, then retry after rejection. No false or rejected result enters a success memo.
Test EdDSA-only overrides and ES256-only overrides separately. The missing algorithm must still use the chosen provider.
Exercise did:key, peer:4 long/short forms, did:kokuin, historic resolution, capability parents/chains and both revocation paths.
Exercise all envelope modes, retained WebCrypto signing and hardware signing.
For static native routing, count both noble and native branches. Unmeasured variants must increment only noble counters.
A promoted native branch that rejects must leave noble counters unchanged.

### Rejecting-after-permissive fold memo

1. Build one deterministic valid log and cloned byte-equivalent logs. Clear the existing fold memo.
2. Resolve using provider A, whose verification returns true. Confirm its provider counters increment and the fold memo warms.
3. Resolve the same DID/log/seen tuple using provider B, whose verification returns false.
4. Assert refusal and positive B verification counts. A's cached success must not authorise B.
5. Start concurrent B resolutions on one resolver. Assert existing in-flight sharing and identical refusal outcomes.
6. Retry B after settlement. Assert another provider invocation, proving failure eviction.
7. Repeat with B rejecting a sentinel operational error. Assert rejection, no history write and retryability.
8. Repeat through `frozen()`, with/without history and through two distinct resolver instances sharing the module memo.
9. Assert unchanged successful writes still return the original `seen` object and do not update observation time.
10. Repeat analogous cross-policy cases for token object provenance, signature memo and record op memo.

Trusted stored epoch copies remain an explicit LogStore trust boundary.
A provider switch cannot make a prior provider's fold memo authoritative, but the existing store contract already trusts persisted epoch authentication.
Do not silently change that durable trust model in this migration. See question Q4.

### Golden bytes and concurrency

Commit literal canonical bytes and outputs captured from the old algorithms in dedicated record/vault fixture files.
Cover record op length framing, canonical nested metadata, Unicode, string `meta.version` substitution and non-string version behaviour.
Cover null tombstones, empty payloads, key IDs, descriptor digests, wrapping digests and sorted entry digests.
Cover range signer deduplication/order, permutation invariance, empty ranges, split thresholds and parent/child summaries.
Record fingerprints retain eight 32-bit lanes and a 36-byte input: 32 lane-sum bytes plus a four-byte count.
Keep big-endian framing and the 16-byte fingerprint output. Claim, op, payload and signer digests remain 32 bytes.
Run the same goldens through noble and the qualified routed provider.
Mutate caller-owned claims, nested metadata, descriptors, payload views and unique buffers immediately after invocation.
Delay provider settlement and assert carried claims/digests still describe the original authenticated snapshot.
Retain decision tie-breaks, branch winners, reconciliation state, convergence and transaction outcomes.

### Strict-verification cutover

Reuse pure-data vectors from `packages/crypto-conformance/vectors/corpus.json`.
Select fixtures explicitly known to pass the old ZIP-215 policy, including the mixed-order A vector accepted by weakened noble.
Assert those fail through default token verification, capability/revocation paths, controller events/folds and record-op verification.
For controller vectors, derive the DID from the crafted event so DID mismatch does not mask the signature-policy assertion.
For tokens and records, construct correctly framed signed messages for the chosen vectors instead of pasting incompatible corpus signatures.
Where the vector equation depends on the message challenge, regenerate or use message-independent small-order fixtures with the same construction.
Assert ordinary deterministic signatures remain valid and canonical outputs remain unchanged.
Keep ES256 low-S acceptance, high-S rejection and raw-message single hashing tests.
Test that a deliberately permissive custom verifier still controls its selected token algorithm only.
Release notes state: crafted signatures previously accepted only under ZIP-215 become invalid when reverified.
No historical rescan, compatibility switch or version gate is introduced.

## Release matrix

The following are manifest-based target versions, not claims about registry publication.
The source for each current version is `packages/<name>/package.json:3`.

| Package | From | To | Release treatment |
| --- | --- | --- | --- |
| token | 0.6.4 | 0.7.0 | Coordinated minor |
| capability | 0.5.2 | 0.6.0 | Coordinated minor |
| controller | 0.2.5 | 0.3.0 | Coordinated breaking minor |
| records | 0.2.0 | 0.3.0 | Coordinated breaking minor |
| vault | 0.1.0 | 0.2.0 | Async API minor |
| store-vault | 0.2.5 | 0.3.0 | Provider and digest-contract minor |
| store-controller | 0.4.1 | 0.5.0 | Recommended alignment minor for new controller contract |
| store-delegation | 0.3.0 | 0.4.0 | Provider options and verification-policy minor |
| jwe | 0.1.1 | 0.2.0 | Provider options and verification-policy minor |
| node | 0.4.2 | 0.5.0 | Coordinated identity-store minor |
| browser | 0.2.4 | 0.3.0 | Coordinated minor, retained WebCrypto signing |
| deterministic | 0.2.4 | 0.3.0 | Coordinated identity-store minor |
| electron | 0.4.4 | 0.5.0 | Independently versioned SDK package, migration minor |
| expo | 0.4.2 | 0.5.0 | Independently versioned SDK package, migration minor |
| ledger-device | 0.2.5 | 0.2.6 | Dependency cascade only, hardware contract unchanged |
| oauth | 0.1.1 | 0.1.1 | No direct dependency or API change expected |
| crypto | 0.1.0 | 0.1.0 | Standalone contract unchanged |
| crypto-native | 0.1.0 | 0.1.0 | Standalone contract unchanged unless routing changes its package |
| controller-conformance | 0.0.0 | 0.0.0 | Private, never publish |
| keystore-conformance | 0.0.0 | 0.0.0 | Private, never publish |

Token, capability, browser, node and deterministic move together by releaser judgement, without `versioning.fixed`.
Controller, records and the portable/store migration packages join that release window.
Electron and Expo keep independent version numbers and SDK qualification. Ledger keeps its hardware protocol unchanged.
Confirm store-controller's optional minor versus automatic patch with the releaser. Recommendation: use the explicit minor above.
If routing changes crypto-native's public construction API, target 0.2.0 separately rather than disguising it as 0.1.0.

During release execution, use `pnpm change`, `pnpm change status`, `pnpm version -r --dry-run`, then `pnpm version -r`.
Keep all private package names in `versioning.ignore` exactly as listed today.
A never-published package may retain its manifest version despite an intent. Check registry state before committing the version plan.
Verify generated manifests, changelogs, internal ranges and `.changeset/ledger.yaml` against this matrix.
Use `pnpm run release` only when publication is separately authorised.

## Downstream handoffs

The following local sibling observations are discovery evidence, not an exhaustive downstream audit.
Re-query each sibling at its actual migration baseline before editing it.

### enkaku handoff

Upgrade to token `^0.7.0`, capability `^0.6.0`, controller `^0.3.0` and applicable identity packages from the matrix.
Expose `crypto?: CryptoProvider` through client/server and authentication constructors that verify tokens or capabilities.
Pass the same resolved provider to controller resolvers and identity stores. Preserve explicit verifier precedence.
Observed server verification calls: `packages/server/src/server.ts:663,830,944`.
The capability options assembled near `server.ts:673` also need provider forwarding.
Existing token/capability calls already await. Any controller builders/folds/identity construction introduced by the sibling require the new awaits.
Export migration notes with the complete PR 2 controller Promise list, not only `foldLog`.
Test server ingress, streams, authenticated replies, frozen resolution, revocation and replay caches under provider A/B.
All sibling verification caches require equivalent policy isolation.
Document strict ZIP-215 cutover and provider failure propagation. No Node N-API backend is delivered by this migration.

### kumiai handoff

Upgrade controller and records to `^0.3.0`, vault to `^0.2.0`, store-vault to `^0.3.0`, and other matrix dependencies as used.
Thread provider through MLS authentication, lifecycle proof, recovery, ledger verification, hubs and identity/controller construction.
Observed verification calls: `mls/src/authentication.ts:206,250`, `lifecycle-proof.ts:353`, `ledger.ts:90`,
`recovery.ts:335,622` and `recovery-verdict.ts:140`.
`mls/src/controller-log.ts:36` directly returns `foldLog`. Its wrapper and callers must become asynchronous.
Fixtures such as `mls/test/fixtures/lifecycle-ledger.ts:25,43,66` need awaited inception/identity construction.
Await every PR 2 controller operation and every PR 3 digest/range/reconciliation operation wherever used.
Carry required `VerifiedRecordOp.contentDigest` in fixtures and persisted-object reconstruction. Never fabricate or recompute it synchronously.
Await vault key IDs, references, metadata validation, decoding and descriptor checks from PR 4.
Thread provider through `createVaultRecords`, `createVaultCoordinator`, revocation checking and wrapping/unwrapping.
Keep native selection explicit, leave MLS cryptography and unrelated primitives outside this provider migration.
Test recovery, management membership/revocation, lifecycle proofs, range sync, vault branches and rollback under delayed/rejecting providers.
Distribute self-contained versions, API diffs, option examples, route evidence and strict-verification expectations to each downstream owner.

## Open design questions

These questions identify real omissions in the binding design. Recommendations guide implementation but are not recorded user decisions.

| ID | Ambiguity and options | Recommendation |
| --- | --- | --- |
| Q1 | No promoted route manifest was found in this checkout. Supply qualified external evidence, create a static manifest from supplied measurements, or leave all routes noble | Obtain the existing measured manifest before selecting native routes. Continue portable threading meanwhile. Never infer promotion from the exploratory probe |
| Q2 | Routing can live in a consumer composition adapter or inside `createNativeCrypto`. Standalone native currently routes all methods to Rust | Preserve standalone API. Compose one immutable routed provider using the manifest. Default unlisted variants to noble, with no catch-and-fallback |
| Q3 | Positional APIs could take a bare provider, appended options, or a breaking replacement parameter object | Use appended `CryptoOptions` and extend existing objects. Preserve methods positions. This document uses that convention |
| Q4 | Provider-isolated fold memos coexist with trusted stored epoch events. Reauthenticate storage on provider change, record durable provenance, or preserve the existing trusted-store contract | Preserve trusted storage semantics in this migration. Test cold verification and document the boundary. A durable provenance/rescan change needs a separate design |
| Q5 | `vaultRecordMeta` hashes key IDs despite synchronous policy usage. Keep a sync bypass, make all policy async, or split parsing from validation | Make public validation async. Use a private structural parser for synchronous ordering and dependencies. Preserve full checks before authorisation/persistence |
| Q6 | Existing broad catches cannot distinguish malformed peer data from provider operational failures. Add a public error taxonomy, use internal tagging, or isolate catches | Isolate parsing catches. Where outer verification APIs must refuse malformed input, use a private tagged wrapper preserving the original error. Do not swallow provider rejection |
| Q7 | Cache limits could apply globally or independently per provider. Fresh provider objects could multiply retention | Keep existing aggregate count/byte limits, with weak provider identity partitions or weak identity tokens in a globally bounded LRU |
| Q8 | Batch size and fairness are unspecified. Verify whole logs, fixed bounded chunks within events, or serial signatures | Use ordered batches within one event, bounded by existing signature limits. Evaluate event candidates sequentially. Retain noble yields where needed for fairness |
| Q9 | Store-controller has no new direct crypto call. Release a patch cascade or align its exported controller types with a minor | Prefer 0.5.0 for the coordinated contract handoff. Keep SDK/hardware packages independent |
| Q11 | Coordinator and nested record options can name different providers. Outer wins, inner wins, or conflicting selections reject | Use the outer provider as the inherited default. Reject explicit unequal nested providers before creating records or writing storage |
| Q10 | The benchmark waiver covers starting migration. Final retesting and expanded conformance could be waived too or remain release qualifications | Preserve final workload retesting and expanded conformance. Do not block research or portable migration on the waived start gate |

## Planning verification

The inventory came from read-only source inspection and TypeScript call-expression queries.
All requested package manifests and provider source files were inspected.
The design, completed delivery, root instructions and development notes were read.
No external web research was needed for repository-local implementation facts.
No source, test, configuration, release, registry or sibling files were changed during planning.
Only this plan file was written. Future verification commands above have not run.

## Appendix A: Call-site inventory

Each package section below names every matching source call and its original file:line.
`[primitive]` means a direct noble sign, verify or BLAKE3 call that must be replaced.
`[carry]` means a digest call on an authenticated claim that should usually become a carried digest read.
`[hook]` means an application policy hook, retained and forwarded independently of provider verification.
`[thread/await]` means provider forwarding, async propagation or a constructor capturing provider policy.
The exact changed public exports are listed in their owning PR above.

### token: 15 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/token/src/identity.ts:129` | `ed25519.sign` | primitive |
| `packages/token/src/identity.ts:186` | `createSigningIdentity` | thread/await |
| `packages/token/src/identity.ts:196` | `createFullIdentity` | thread/await |
| `packages/token/src/identity.ts:358` | `ed25519.sign` | primitive |
| `packages/token/src/identity.ts:449` | `signWith` | thread/await |
| `packages/token/src/token.ts:152` | `getVerifier` | thread/await |
| `packages/token/src/token.ts:154` | `verify` | thread/await |
| `packages/token/src/token.ts:226` | `signer.signToken` | thread/await |
| `packages/token/src/token.ts:310` | `verifySignedPayload` | thread/await |
| `packages/token/src/token.ts:362` | `verifySignedPayload` | thread/await |
| `packages/token/src/verified-memo.ts:95` | `verify` | thread/await |
| `packages/token/src/verifier.ts:31` | `memoizeVerifier` | thread/await |
| `packages/token/src/verifier.ts:33` | `p256.verify` | primitive |
| `packages/token/src/verifier.ts:35` | `memoizeVerifier` | thread/await |
| `packages/token/src/verifier.ts:37` | `ed25519.verify` | primitive |

### capability: 11 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/capability/src/delegation.ts:66` | `signer.signToken` | thread/await |
| `packages/capability/src/delegation.ts:86` | `signer.signToken` | thread/await |
| `packages/capability/src/delegation.ts:97` | `verifyToken` | thread/await |
| `packages/capability/src/delegation.ts:133` | `signer.signToken` | thread/await |
| `packages/capability/src/delegation.ts:217` | `verifyToken` | thread/await |
| `packages/capability/src/delegation.ts:228` | `options.verifyToken` | hook |
| `packages/capability/src/delegation.ts:329` | `verifyToken` | thread/await |
| `packages/capability/src/delegation.ts:340` | `options.verifyToken` | hook |
| `packages/capability/src/revocation.ts:127` | `verifyToken` | thread/await |
| `packages/capability/src/revocation.ts:210` | `verifyToken` | thread/await |
| `packages/capability/src/revocation.ts:268` | `signer.signToken` | thread/await |

### controller: 51 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/controller/src/device-revoke.ts:7` | `foldLog` | thread/await |
| `packages/controller/src/device-revoke.ts:30` | `foldDeviceChain` | thread/await |
| `packages/controller/src/device-revoke.ts:56` | `deviceRevokeIndices` | thread/await |
| `packages/controller/src/device-revoke.ts:75` | `foldDeviceChain` | thread/await |
| `packages/controller/src/device-revoke.ts:82` | `createRotate` | thread/await |
| `packages/controller/src/epoch-events.ts:161` | `signEvent` | thread/await |
| `packages/controller/src/epoch-events.ts:312` | `verifySignatures` | thread/await |
| `packages/controller/src/epoch-events.ts:318` | `verifySignatures` | thread/await |
| `packages/controller/src/epoch.ts:261` | `verifyEpochSignature` | thread/await |
| `packages/controller/src/epoch.ts:271` | `verifyEpochSignature` | thread/await |
| `packages/controller/src/epoch.ts:581` | `foldEpochDetailed` | thread/await |
| `packages/controller/src/events.ts:87` | `ed25519.sign` | primitive |
| `packages/controller/src/events.ts:165` | `ed25519.verify` | primitive |
| `packages/controller/src/events.ts:183` | `signEvent` | thread/await |
| `packages/controller/src/events.ts:248` | `verifySignatures` | thread/await |
| `packages/controller/src/events.ts:418` | `signEvent` | thread/await |
| `packages/controller/src/events.ts:475` | `verifySignatures` | thread/await |
| `packages/controller/src/events.ts:513` | `createInception` | thread/await |
| `packages/controller/src/events.ts:547` | `signEvent` | thread/await |
| `packages/controller/src/events.ts:601` | `verifySignatures` | thread/await |
| `packages/controller/src/fold-memo.ts:82` | `authoritativeLogWithin` | thread/await |
| `packages/controller/src/fold-memo.ts:92` | `authoritativeLogWithin` | thread/await |
| `packages/controller/src/fold.ts:200` | `verifyReset` | thread/await |
| `packages/controller/src/fold.ts:210` | `verifyRotate` | thread/await |
| `packages/controller/src/fold.ts:409` | `verifyInception` | thread/await |
| `packages/controller/src/fold.ts:503` | `foldEpoch` | thread/await |
| `packages/controller/src/history.ts:108` | `foldLog` | thread/await |
| `packages/controller/src/history.ts:200` | `authoritativeLogWithin` | thread/await |
| `packages/controller/src/history.ts:220` | `foldLog` | thread/await |
| `packages/controller/src/history.ts:236` | `resolveBranches` | thread/await |
| `packages/controller/src/history.ts:242` | `foldLog` | thread/await |
| `packages/controller/src/history.ts:251` | `withEpoch` | thread/await |
| `packages/controller/src/identity.ts:59` | `identity.signToken` | thread/await |
| `packages/controller/src/identity.ts:99` | `createSigningIdentityForDID` | thread/await |
| `packages/controller/src/identity.ts:174` | `currentState` | thread/await |
| `packages/controller/src/identity.ts:209` | `currentState` | thread/await |
| `packages/controller/src/keystore-identity.ts:33` | `createInception` | thread/await |
| `packages/controller/src/keystore-identity.ts:39` | `createControllerIdentity` | thread/await |
| `packages/controller/src/log.ts:80` | `foldLog` | thread/await |
| `packages/controller/src/log.ts:84` | `withEpoch` | thread/await |
| `packages/controller/src/log.ts:99` | `foldEpochDetailed` | thread/await |
| `packages/controller/src/log.ts:132` | `foldHeld` | thread/await |
| `packages/controller/src/log.ts:194` | `foldLog` | thread/await |
| `packages/controller/src/log.ts:195` | `foldLog` | thread/await |
| `packages/controller/src/log.ts:202` | `resolveBranches` | thread/await |
| `packages/controller/src/log.ts:262` | `foldHeld` | thread/await |
| `packages/controller/src/profiles.ts:57` | `createInception` | thread/await |
| `packages/controller/src/resolver.ts:102` | `memoizedAuthoritativeLog` | thread/await |
| `packages/controller/src/resolver.ts:117` | `memoizedAuthoritativeLog` | thread/await |
| `packages/controller/src/state.ts:29` | `foldLog` | thread/await |
| `packages/controller/src/supersede.ts:212` | `foldLog` | thread/await |

### controller-conformance: 111 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/controller-conformance/src/index.ts:241` | `impl.createRotate` | thread/await |
| `packages/controller-conformance/src/index.ts:256` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:256` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:260` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:261` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:266` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:267` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:272` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:273` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:284` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:290` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:299` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:302` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:307` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:312` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:329` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:331` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:332` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:337` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:340` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:343` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:347` | `impl.signEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:350` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:360` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:364` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:380` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:385` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:405` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:412` | `impl.signEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:414` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:418` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:423` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:430` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:432` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:447` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:453` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:463` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:468` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:472` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:477` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:482` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:485` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:493` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:503` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:507` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:508` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:520` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:520` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:521` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:521` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:525` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:528` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:529` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:546` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:549` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:558` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:567` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:577` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:582` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:588` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:596` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:599` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:600` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:608` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:617` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:632` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:634` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:638` | `impl.createEpochEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:646` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:654` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:660` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:674` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:678` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:690` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:692` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:708` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:710` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:711` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:712` | `impl.createReset` | thread/await |
| `packages/controller-conformance/src/index.ts:717` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:731` | `impl.resolveBranches` | thread/await |
| `packages/controller-conformance/src/index.ts:753` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:759` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:764` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:770` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:784` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:799` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:803` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:809` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:814` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:835` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:848` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:883` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:885` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:895` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:898` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:908` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:914` | `impl.signEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:916` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:925` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:945` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:964` | `impl.createEpochEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:975` | `impl.createEpochEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:988` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:1031` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:1076` | `impl.createInception` | thread/await |
| `packages/controller-conformance/src/index.ts:1086` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:1103` | `impl.createEpochEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:1109` | `impl.foldLog` | thread/await |
| `packages/controller-conformance/src/index.ts:1191` | `impl.signEvent` | thread/await |
| `packages/controller-conformance/src/index.ts:1308` | `impl.signEvent` | thread/await |

### records: 41 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/records/src/apply.ts:386` | `recordClaimDigest` | carry |
| `packages/records/src/apply.ts:412` | `verifySignedRecord` | thread/await |
| `packages/records/src/apply.ts:493` | `recordPayloadMatches` | thread/await |
| `packages/records/src/apply.ts:502` | `recordClaimDigest` | carry |
| `packages/records/src/apply.ts:506` | `recordPayloadMatches` | thread/await |
| `packages/records/src/apply.ts:547` | `recordClaimDigest` | carry |
| `packages/records/src/apply.ts:547` | `recordClaimDigest` | carry |
| `packages/records/src/apply.ts:552` | `recordPayloadMatches` | thread/await |
| `packages/records/src/apply.ts:609` | `createRecordVerifier` | thread/await |
| `packages/records/src/apply.ts:781` | `createRecordVerifier` | thread/await |
| `packages/records/src/decision.ts:31` | `recordClaimDigest` | carry |
| `packages/records/src/decision.ts:48` | `recordClaimDigest` | carry |
| `packages/records/src/decision.ts:61` | `verifySignedRecord` | thread/await |
| `packages/records/src/decision.ts:63` | `recordClaimDigest` | carry |
| `packages/records/src/op.ts:75` | `blake3` | primitive |
| `packages/records/src/op.ts:80` | `digestParts` | thread/await |
| `packages/records/src/op.ts:169` | `identity.signToken` | thread/await |
| `packages/records/src/op.ts:187` | `recordOpHash` | thread/await |
| `packages/records/src/op.ts:223` | `recordOpHash` | thread/await |
| `packages/records/src/op.ts:235` | `verifyToken` | thread/await |
| `packages/records/src/op.ts:274` | `verifyRecordOp` | thread/await |
| `packages/records/src/op.ts:310` | `verifyRecordOp` | thread/await |
| `packages/records/src/policy.ts:56` | `recordClaimDigest` | carry |
| `packages/records/src/policy.ts:56` | `recordClaimDigest` | carry |
| `packages/records/src/range.ts:122` | `blake3` | primitive |
| `packages/records/src/range.ts:163` | `fingerprintRange` | thread/await |
| `packages/records/src/range.ts:200` | `fingerprintRange` | thread/await |
| `packages/records/src/range.ts:286` | `blake3` | primitive |
| `packages/records/src/reconcile.ts:74` | `fingerprintRange` | thread/await |
| `packages/records/src/reconcile.ts:171` | `nextRequesterSteps` | thread/await |
| `packages/records/src/record.ts:63` | `blake3` | primitive |
| `packages/records/src/record.ts:170` | `blake3` | primitive |
| `packages/records/src/record.ts:175` | `recordPayloadDigest` | thread/await |
| `packages/records/src/visibility.ts:108` | `recordClaimDigest` | carry |
| `packages/records/src/visibility.ts:108` | `recordClaimDigest` | carry |
| `packages/records/src/visibility.ts:115` | `recordClaimDigest` | carry |
| `packages/records/src/visibility.ts:115` | `recordClaimDigest` | carry |
| `packages/records/src/visibility.ts:125` | `verifySignedRecord` | thread/await |
| `packages/records/src/visibility.ts:126` | `recordPayloadMatches` | thread/await |
| `packages/records/src/visibility.ts:152` | `verifySignedRecord` | thread/await |
| `packages/records/src/visibility.ts:318` | `verifySignedRecord` | thread/await |

### vault: 41 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/vault/src/branch.ts:6` | `recordClaimDigest` | carry |
| `packages/vault/src/branch.ts:7` | `recordClaimDigest` | carry |
| `packages/vault/src/digest.ts:17` | `blake3` | primitive |
| `packages/vault/src/digest.ts:43` | `digestParts` | thread/await |
| `packages/vault/src/digest.ts:47` | `digestParts` | thread/await |
| `packages/vault/src/digest.ts:61` | `digestParts` | thread/await |
| `packages/vault/src/digest.ts:67` | `vaultEntriesDigest` | thread/await |
| `packages/vault/src/digest.ts:72` | `digestParts` | thread/await |
| `packages/vault/src/digest.ts:79` | `descriptorDigest` | thread/await |
| `packages/vault/src/id.ts:11` | `blake3` | primitive |
| `packages/vault/src/id.ts:25` | `createVaultKeyID` | thread/await |
| `packages/vault/src/record-types.ts:115` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:127` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:135` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:140` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:157` | `recordPayloadMatches` | thread/await |
| `packages/vault/src/record-types.ts:160` | `decodeVaultRecord` | thread/await |
| `packages/vault/src/record-types.ts:174` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:190` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:210` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:255` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:260` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:303` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:309` | `verifyRecordOp` | thread/await |
| `packages/vault/src/record-types.ts:310` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:331` | `recordPayloadDigest` | thread/await |
| `packages/vault/src/record-types.ts:376` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:380` | `recordPayloadMatches` | thread/await |
| `packages/vault/src/record-types.ts:420` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:422` | `recordPayloadMatches` | thread/await |
| `packages/vault/src/record-types.ts:446` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:478` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:517` | `verifySignedRecord` | thread/await |
| `packages/vault/src/record-types.ts:518` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/record-types.ts:549` | `verifySignedRecord` | thread/await |
| `packages/vault/src/records.ts:187` | `createVaultKeyID` | thread/await |
| `packages/vault/src/records.ts:343` | `vaultRecordMeta` | thread/await |
| `packages/vault/src/records.ts:350` | `recordPayloadDigest` | thread/await |
| `packages/vault/src/records.ts:355` | `recordPayloadDigest` | thread/await |
| `packages/vault/src/suite.ts:324` | `descriptorDigest` | thread/await |
| `packages/vault/src/suite.ts:332` | `checkDescriptorDigest` | thread/await |

### store-vault: 35 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/store-vault/src/coordinator-context.ts:265` | `recordPayloadDigest` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:276` | `signRecordOp` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:283` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:323` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:334` | `checkDescriptorDigest` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:486` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/coordinator-context.ts:524` | `recordClaimDigest` | carry |
| `packages/store-vault/src/coordinator-context.ts:524` | `recordClaimDigest` | carry |
| `packages/store-vault/src/coordinator-context.ts:565` | `recordPayloadDigest` | thread/await |
| `packages/store-vault/src/coordinator-records.ts:114` | `recordPayloadDigest` | thread/await |
| `packages/store-vault/src/coordinator-records.ts:214` | `signRecordOp` | thread/await |
| `packages/store-vault/src/coordinator-rotate.ts:99` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/coordinator.ts:42` | `createVaultKeyReference` | thread/await |
| `packages/store-vault/src/coordinator.ts:487` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/records-adapter.ts:185` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records-adapter.ts:187` | `recordPayloadMatches` | thread/await |
| `packages/store-vault/src/records-adapter.ts:192` | `vaultRecordMeta` | thread/await |
| `packages/store-vault/src/records-adapter.ts:196` | `recordClaimDigest` | carry |
| `packages/store-vault/src/records-adapter.ts:272` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records-ports.ts:26` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records-ports.ts:30` | `recordPayloadMatches` | thread/await |
| `packages/store-vault/src/records-ports.ts:31` | `vaultRecordMeta` | thread/await |
| `packages/store-vault/src/records-projection.ts:47` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/records-rows.ts:151` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records-rows.ts:156` | `recordPayloadMatches` | thread/await |
| `packages/store-vault/src/records-rows.ts:159` | `recordClaimDigest` | carry |
| `packages/store-vault/src/records-rows.ts:160` | `recordClaimDigest` | carry |
| `packages/store-vault/src/records-rows.ts:164` | `decodeVaultRecord` | thread/await |
| `packages/store-vault/src/records-rows.ts:193` | `recordClaimDigest` | carry |
| `packages/store-vault/src/records.ts:211` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records.ts:246` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records.ts:309` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records.ts:357` | `verifyRecordOp` | thread/await |
| `packages/store-vault/src/records.ts:397` | `verifySignedRecord` | thread/await |
| `packages/store-vault/src/records.ts:406` | `decodeVaultRecord` | thread/await |

### store-controller: 0 sites

No cryptographic calls. `api.ts:48` exports `createControllerStore`; `api.ts` already awaits its merge callback. Update integration tests with the async controller PR.

### store-delegation: 0 sites

No direct signature/hash calls. `revocation-checker.ts:47,174` exposes the backend/checker factories. The checker forwards `RevocationOptions` through the spread at line 158, which must retain `crypto`.

### jwe: 5 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/jwe/src/index.ts:478` | `options.signer.signToken` | thread/await |
| `packages/jwe/src/index.ts:484` | `options.signer.signToken` | thread/await |
| `packages/jwe/src/index.ts:493` | `options.signer.signToken` | thread/await |
| `packages/jwe/src/index.ts:512` | `verifyToken` | thread/await |
| `packages/jwe/src/index.ts:517` | `verifyToken` | thread/await |

### node: 2 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/node/src/store.ts:108` | `createFullIdentity` | thread/await |
| `packages/node/src/store.ts:134` | `createFullIdentity` | thread/await |

### browser: 0 sites

No provider-driven source calls. Existing WebCrypto signing is retained. Its token dependency joins the coordinated minor release.

### electron: 2 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/electron/src/store.ts:120` | `createFullIdentity` | thread/await |
| `packages/electron/src/store.ts:141` | `createFullIdentity` | thread/await |

### expo: 2 sites

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/expo/src/store.ts:55` | `createFullIdentity` | thread/await |
| `packages/expo/src/store.ts:76` | `createFullIdentity` | thread/await |

### deterministic: 1 site

| File:line (relative to package src) | Call | Treatment |
| --- | --- | --- |
| `packages/deterministic/src/store.ts:58` | `createFullIdentity` | thread/await |

### keystore-conformance: 0 sites

No signing, verification or BLAKE3 calls. `index.ts:7` tests key-store/key-entry contracts, not identity signatures. Existing exported conformance functions keep their signatures.

### oauth: 0 sites

No signing, verification or BLAKE3 calls. OAuth PKCE SHA-256 is outside scope. TokenResponse explicitly leaves ID tokens opaque.

### ledger-device: 0 sites

No provider-driven calls. APDU signing remains hardware-owned. Provider options on Ledger construction would be misleading.

**Inventory total:** 317 source call expressions. Primitive count remains 13. Conformance includes four epoch-event construction calls. The 100 helper invocations below are additional propagation sites.

### Conformance helper propagation

These additional local helper calls need awaits after the seven implementation members become async.
They are separate from the inventory total because they wrap calls already counted above.

| File | Helper | Call count | Lines |
| --- | --- | --- | --- |
| `packages/controller-conformance/src/index.ts` | `rotate` | 21 | 246, 301, 311, 362, 383, 384, 407, 429, 431, 449, 466, 505, 548, 602, 603, 649, 676, 677, 897, 940, 1085 |
| `packages/controller-conformance/src/index.ts` | `denying` | 19 | 363, 452, 468, 472, 480, 482, 486, 491, 493, 506, 560, 561, 562, 579, 580, 581, 616, 693, 694 |
| `packages/controller-conformance/src/index.ts` | `resign` | 2 | 414, 418 |
| `packages/controller-conformance/src/index.ts` | `summary` | 32 | 1015, 1022, 1027, 1027, 1036, 1036, 1041, 1042, 1044, 1045, 1057, 1058, 1059, 1063, 1064, 1065, 1066, 1140, 1142, 1214, 1218, 1223, 1241, 1242, 1242, 1250, 1261, 1263, 1271, 1302, 1311, 1315 |
| `packages/controller-conformance/src/index.ts` | `event` | 23 | 1151, 1152, 1160, 1169, 1175, 1183, 1203, 1213, 1218, 1223, 1240, 1246, 1257, 1267, 1276, 1277, 1288, 1289, 1290, 1300, 1301, 1322, 1326 |
| `packages/controller-conformance/src/index.ts` | `sameInEveryOrder` | 3 | 1275, 1287, 1326 |

### Package counts

The per-package headings are authoritative counts. Zero-call packages were inspected rather than omitted.

## Appendix B: Retained paths and zero-change API decisions

| Package | Original site | Decision |
| --- | --- | --- |
| browser | `packages/browser/src/identity.ts:58,129` | Two WebCrypto signing calls remain asynchronous and WebCrypto-owned |
| browser | `packages/browser/src/identity.ts:97–104` | Retain low-S normalisation of WebCrypto ES256 signatures |
| browser | `packages/browser/src/utils.ts:78–80` | Retain random seed, public-key derivation and agreement-secret derivation |
| ledger-device | `packages/ledger-device/src/provider.ts:132` | APDU signature acquisition remains hardware-owned |
| token | `packages/token/src/identity.ts:88,143,152,271–272` | Retain public-key derivation and randomness |
| token | `packages/token/src/identity.ts:154,175,393,455` | Retain key agreement and secret conversion |
| controller | `packages/controller/src/derivation.ts:86`, `identity.ts:207` | Retain Ed25519 public-key derivation |
| controller | `packages/controller/src/canonical.ts:109` | SHA-256 digests remain synchronous |
| jwe | `packages/jwe/src/index.ts:202` | Retain Ed25519-to-Montgomery public-key conversion |
| oauth | `packages/oauth/src/pkce.ts` | PKCE SHA-256 remains outside provider scope |
| deterministic | `packages/deterministic/src/derivation.ts` | Retain SLIP-0010 and mnemonic derivation |
| keystore-conformance | `packages/keystore-conformance/src/index.ts` | Existing exported conformance functions keep their signatures |
| store-controller | `packages/store-controller/src/api.ts:48` | `createControllerStore` keeps its signature and async callback contract |
| store-delegation | `packages/store-delegation/src/revocation-checker.ts:47` | `createDelegationRevocationBackend` keeps its signature |

Browser, OAuth, ledger-device and keystore-conformance introduce no new async exports or provider options.
Store-delegation's checker inherits options from capability. Store-controller only exposes the updated imported controller types.

## Appendix C: Internal propagation and implementation checks

The source-module exports below also require attention, even though package consumers usually reach them through public factories.

| Source | Change |
| --- | --- |
| `packages/token/src/verified-memo.ts:82` | `memoizeVerifier` must scope memo access to verifier/provider policy. Prefer closure-owned policy scope over changing public token exports |
| `packages/token/src/verifier.ts:31,35` | Construct provider-bound default verifier closures and memoise by provider identity |
| `packages/controller/src/epoch.ts:75` | Extend `FoldEpochParams` with provider selection |
| `packages/controller/src/epoch.ts:371,580` | Return Promise-wrapped detail/result unions |
| `packages/controller/src/log.ts:69,92` | `foldHeld` and `withEpoch` append provider options and return Promises |
| `packages/controller/src/history.ts:207` | `authoritativeLogWithin` gains provider through params and returns a Promise |
| `packages/controller/src/fold-memo.ts:76` | `memoizedAuthoritativeLog` returns a Promise and partitions by resolved provider |
| `packages/controller/src/state.ts:25` | `currentState` appends provider options and returns `Promise<KeyState>` |
| `packages/records/src/apply.ts:393,403` | Dependency helpers append provider options and forward them to verification |
| `packages/store-vault/src/records-rows.ts:50` | `Bound` carries resolved provider. `checked` and `decision` retain async results |
| `packages/store-vault/src/records-projection.ts:7` | `projection` retains `Promise<void>` and reads provider from `Bound` |
| `packages/store-vault/src/records-ports.ts:13` | `vaultRecordPortsFor` keeps its signature and reads provider from the adapter's `Bound` |
| `packages/store-vault/src/coordinator-context.ts:183` | `createCoordinatorContext` captures provider from extended coordinator params |

Existing helpers that close over caller-owned option objects must copy provider and verifier policy at construction.
This includes record verifiers, vault proof definitions and store/coordinator contexts, not only key stores.
Add `@kokuin/crypto` workspace dependencies to packages importing provider types or noble defaults.
Update the lockfile through the normal implementation workflow when dependency declarations change. No installation occurred during research.
Do not add Nitro dependencies to portable packages. Only the explicit native composition layer may import crypto-native.

Static route composition must be resolved with Q1/Q2 before native integration claims.
PRs 1–3 can prove provider propagation using injected test providers without inventing native route eligibility.
PR 4 must test the supplied manifest's exact algorithm, message-size and batch variants before claiming native consumer routing.
Do not derive route choices from runtime timing or backend availability.
Where manifest data is unavailable, native route selection remains an explicitly incomplete deliverable, while portable migration can stay green.

Self-review found two sequencing requirements: vault decoding becomes async in PR 3, and full vault metadata validation follows in PR 4.
Both changes are reflected in the API tables. No legacy synchronous hashing compatibility layer is planned.

## Recorded decisions (2026-11-04, user)

- Q1: no measured route manifest exists yet. Not a blocker. All routes stay on noble; native routing waits on a stored, measured manifest, tracked as a follow-on item at completion.
- Q2-Q9, Q11: the recommendations above are the rulings.
- Q10: the start gate is waived; final workload retesting and expanded conformance remain release qualifications.
- Execution: one PR at a time on this branch line, Codex implementer per PR, controller review, then the next PR stacked on it.
