# Rust Crypto Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** add an explicit mobile crypto provider while preserving identical strict verification and digest results across backends.

**Architecture:** `@kokuin/crypto` owns the provider contract and default noble implementation. A binding-independent Rust core supplies measured native operations through Nitro. Existing packages receive providers explicitly, with async verification and precomputed record content digests.

**Tech Stack:** TypeScript, noble, Vitest, Rust, dalek, p256, blake3, cbindgen, Nitro Modules, Expo, Maestro, pnpm built-in versioning.

**Spec:** [Rust crypto backend](../specs/2026-10-24-rust-crypto-backend-design.md)

## Global Constraints

- "Benchmarks first, and they gate."
- "No automatic backend detection."
- "A Rust toolchain requirement for JS consumers" is an anti-goal.
- "Batch verification is a loop of strict single verifies inside the backend."
- "Record merge logic stays sync."
- "Downstream (enkaku, kumiai) call-site migrations are **follow-up work**."
- Preserve existing canonical bytes, DIDs, op hashes, record digests and range fingerprints.
- Keep SHA-256, X25519, HKDF, AES-GCM, BIP39 and random key generation outside the provider.
- Keep hardware signing and browser WebCrypto signing on their existing paths.
- Preserve `verifiers` overrides. Missing algorithm overrides use the selected provider.
- Use `workspace:^` internally and published `^` ranges for cross-repo dependencies.
- List every private workspace package exactly in `versioning.ignore`.
- Use existing `@kigu/dev` configuration and `withStoreTransaction` where store transactions require changes.

## Review Focus

- A cached permissive provider verdict must never satisfy a stricter provider. Task 4 tests cache isolation.
- Mutation during async work must not change authenticated input. Tasks 1, 2 and 5 test snapshots and digest consistency.
- Mixed valid and malformed batch entries must retain order and per-item verification results. Tasks 1 and 2 test this.
- Provider failures must never trigger runtime fallback. Tasks 2 and 4 test rejection and retry behaviour.
- Persisted records must retain their digest and conflict outcomes after cutover. Task 5 tests golden values and convergence.

## Execution prerequisites

The [benchmark spike](2026-10-25-rust-crypto-benchmark-spike.md) must report `proceed` on real iOS and Android devices.
The design must be approved before product implementation. Its current status remains awaiting approval.
This plan supplies proposed builder decisions, not evidence that those decisions have already been approved.

- [ ] Copy the spike's report path, source revision, dependency versions, deployment floors and routing manifest into this section.
- [ ] Replace experimental batch transport details with the measured choice from the report.
- [ ] Confirm every intended native route has evidence on both mobile platforms.

An unmeasured or losing route stays on noble by a documented static routing decision.
Do not catch native errors and invoke noble. Missing registration or an incompatible native ABI fails construction.
If no route passes, stop at the spike. Do not perform this plan's public API migration.

## Final interfaces and proposed builder decisions

Use `crypto?: CryptoProvider` consistently. It defaults to `nobleCrypto` at the outer boundary and propagates unchanged.
No mutable global provider exists. Providers have immutable behaviour for their lifetime.

```ts
export type CryptoAlgorithm = 'EdDSA' | 'ES256'
export type SignItem = { privateKey: Uint8Array; message: Uint8Array }
export type VerifyItem = {
  alg: CryptoAlgorithm
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}
export type CryptoProvider = {
  sign(alg: 'EdDSA', privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  signBatch(alg: 'EdDSA', items: Array<SignItem>): Promise<Array<Uint8Array>>
  verify(alg: CryptoAlgorithm, signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>
  verifyBatch(items: Array<VerifyItem>): Promise<Array<boolean>>
  blake3(input: Uint8Array, dkLen: number): Promise<Uint8Array>
  blake3Batch(inputs: Array<Uint8Array>, dkLen: number): Promise<Array<Uint8Array>>
}
export type CryptoOptions = { crypto?: CryptoProvider }
```

Contract details:

- Ed25519 private keys are 32-byte seeds. Signatures are 64 bytes and public keys are 32 bytes.
- Ed25519 requires canonical A/R encodings, canonical S, and non-small-order torsion-free A/R points.
- ES256 accepts compressed 33-byte or uncompressed 65-byte SEC1 public keys and compact 64-byte signatures.
- ES256 consumes raw messages. Each backend applies SHA-256 exactly once and rejects high-S without normalisation.
- A malformed signature or key resolves `false`. Unsupported algorithms reject with `TypeError`.
- Signing rejects invalid seeds with `TypeError`. A malformed signing item rejects the entire batch.
- Hash lengths are integers from 1 through 65536. Invalid lengths reject with `RangeError` before dispatch.
- The hash-length ceiling is a proposed resource bound. Current callers need 16 or 32 bytes.
- Empty batches resolve `[]`. Batch results preserve input order, including mixed verification results.
- Every method snapshots input views before its first suspension. Results own independent byte storage.
- Detached and shared-memory-backed buffers reject with `TypeError`. Ordinary subarray views are supported.
- Infrastructure failures reject. They never become a noble fallback.

Keep `getPublicKey` outside the provider. Constructors that only derive keys may remain synchronous.
Use `createNativeCrypto(): CryptoProvider` for explicit construction and ABI validation.
Expose the chosen routes as a separate immutable `nativeCryptoRoutes` export for diagnosis and documentation.

## File map

| Files | Responsibility |
| --- | --- |
| `packages/crypto/src/{types,validation,ed25519,noble,index}.ts` | Public contract, validation and strict noble |
| `packages/crypto-conformance/src/{types,index}.ts` | Framework-agnostic cases and adapter |
| `packages/crypto-conformance/vectors/{crypto.json,provenance.json}` | One backend-independent corpus and source licences |
| `scripts/generate-crypto-vectors.mjs`, `packages/crypto-conformance/src/vectors.ts` | Checked JSON-to-TypeScript corpus generation |
| `packages/crypto/test/{conformance,contract}.test.ts` | Noble contract and vector execution |
| `crates/kokuin-crypto/tests/{vectors,properties}.rs` | Same corpus and Rust properties |
| `packages/crypto-native/src/{Crypto.nitro,provider,routes,index}.ts` | Generated bridge contract and native provider adapter |
| `packages/crypto-native/cpp/{HybridCrypto.hpp,HybridCrypto.cpp}` | Snapshot, worker and output ownership |
| `scripts/{build-crypto-native,check-crypto-artifacts}.mjs` | Reproducible binaries and package checks |
| `.github/workflows/{crypto-rust,crypto-native}.yml` | Rust checks and mobile binary builds |
| `tests/e2e-expo/crypto/{conformance,integration}.ts` | Mobile contract and package integration |
| `tests/e2e-expo/components/CryptoConformance.tsx` | Machine-readable E2E result |
| `tests/e2e-expo/.maestro/crypto-conformance.yaml` | Mobile acceptance checks |
| `docs/reference/{crypto-provider,crypto-migration}.md` | Permanent API and migration reference |

Create package manifests and shared-toolchain configuration for the two new TS packages.
Promote the spike's `crypto-native` package and retain its generated binding and linking configuration.
Modify existing consumer files only within the owning task below. Do not edit generated `lib/` files.

### Task 1: finalise the contract and shared strict conformance

**Files:** create the `crypto` and `crypto-conformance` files above, plus `packages/crypto-conformance/test/index.test.ts`.
Modify `pnpm-workspace.yaml`, `pnpm-lock.yaml` and the spike's Rust core implementation.
Create the Rust vector/property tests listed above.

**Interfaces:** produce all types above, `nobleCrypto: CryptoProvider`, and `cryptoConformance(provider: CryptoProvider): Array<CryptoConformanceCase>`.
`CryptoConformanceCase` is `{ name: string; run(): Promise<void> }`. Its runner throws on assertion failure without importing Vitest.
The private suite depends on `@kokuin/crypto`. Production crypto never depends on the private suite.
Load the same `crypto.json` in Rust through `include_str!` and in the JS suite through generated `src/vectors.ts`.
The generator validates corpus shapes and emits a typed constant. Its `--check` mode rejects stale generated data.

- [ ] Add failing contract tests for empty batches, subarrays, snapshots, output independence and every specified error type.
- [ ] Add `mixed verification batch preserves order`: assert `[true, false, false, true]` across both algorithms and malformed lengths.
- [ ] Add identity-point and mixed-order A/R cases that would pass weaker verification policies.
- [ ] Add corpus records with `id`, `operation`, hex inputs, explicit expected output and a provenance identifier.
- [ ] Import RFC 8032, Wycheproof Ed25519/P-256 and official blake3 vectors with pinned source revisions and licences.
- [ ] Record explicit policy-based rejection reasons where project expectations differ from upstream expected outcomes.
- [ ] Cover non-canonical A/R/S, S at/above L, invalid r/s, off-curve keys, high-S, DER rejection and double hashing.
- [ ] Cover blake3 lengths 1, 16, 32, 64 and 65536, plus zero, fractional, negative and excessive lengths.
- [ ] Run `pnpm --filter @kokuin/crypto test`. Expect missing implementation failures.
- [ ] Implement the provider and noble operations with explicit strict checks and shared argument validation.
- [ ] Implement `scripts/generate-crypto-vectors.mjs` and run it before building the conformance package.
- [ ] Expand Rust checks to the same contract and corpus. Keep panic containment at the ABI boundary.
- [ ] Add deterministic property cases comparing each batch result with its strict single-operation result.
- [ ] Add self-tests proving the conformance runner rejects a deliberately incorrect provider.
- [ ] Run `pnpm --filter @kokuin/crypto... build` and `pnpm --filter @kokuin/crypto-conformance... build`.
- [ ] Run both packages' `test` scripts and `cargo test --workspace --locked`. Expect zero corpus disagreements.
- [ ] Commit as `feat: add shared strict crypto provider and conformance`.

### Task 2: promote the native provider and make binaries distributable

**Files:** modify the spike's FFI, C++ owners, mobile linking configuration and `packages/crypto-native/package.json`.
Create the native provider, routes, artifact-check script and CI workflows from the file map.
Modify `.github/workflows/e2e-ios.yml`, `.github/workflows/e2e-android.yml` and relevant Expo dependencies.
Create `packages/crypto-native/test/{provider,package}.test.ts`.

**Interfaces:** consume Task 1's provider and corpus. Produce `createNativeCrypto(): CryptoProvider` and `nativeCryptoRoutes`.
Add a versioned C ABI handshake. Bind the TS adapter, generated C header and Rust binaries to the same ABI version.
The static routes come from the spike report. They do not change in response to exceptions or device detection.

- [ ] Add failing tests for missing registration, ABI mismatch and worker failure. Assert no noble fallback calls.
- [ ] Add native contract tests for subarray snapshots, detached buffers, empty batches and mixed verification results.
- [ ] Extend ownership tests to every seed-bearing allocation, invalid-batch exits and rejected dispatches.
- [ ] Run `pnpm --filter @kokuin/crypto-native test`. Expect missing adapter and artifact failures.
- [ ] Implement shared validation, the ABI handshake and static per-variant routes.
- [ ] Implement one native call per native batch. Do not turn a batch into JS-side single calls.
- [ ] Reuse the spike's zeroising input owners and native-owned output deleters.
- [ ] Ship an iOS XCFramework and Android libraries for every target established by the spike.
- [ ] Package generated glue, headers, licences, Podspec, Gradle/CMake files and all binaries through an explicit `files` list.
- [ ] Make Nitro a compatible peer dependency. Keep it outside `@kokuin/crypto`'s dependency graph.
- [ ] Add `test:native` to build and execute C++ ownership tests using CMake/CTest with supported sanitizers.
- [ ] Add `test:package` to inspect packed files, ABI versions and required slices through `check-crypto-artifacts.mjs`.
- [ ] Run `pnpm --filter @kokuin/crypto-native test:native` and `pnpm --filter @kokuin/crypto-native test:package`.
- [ ] Add PR CI for locked Rust tests, formatting, clippy and generated-header drift.
- [ ] Check vector-module drift with `node scripts/generate-crypto-vectors.mjs --check` in PR CI.
- [ ] Add native cross-build CI and feed its artifacts into both mobile E2E jobs before client compilation.
- [ ] Remove the promoted public package from `versioning.ignore`. Keep `@kokuin/crypto-conformance` listed exactly.
- [ ] Run all three crypto packages' tests and `cargo test --workspace --locked`. Expect identical results.
- [ ] Commit as `feat: ship explicit Nitro crypto provider with prebuilt binaries`.

### Task 3: inject providers through tokens and runtime identities

**Files:** modify `packages/token/src/{identity,token,verifier,index}.ts` and their existing tests.
Modify `packages/capability/src/{types,delegation,revocation}.ts`, `packages/jwe/src/index.ts` and forwarding tests.
Modify `packages/{node,electron,expo,deterministic}/src/store.ts` and their identity/conformance tests.
Modify affected package manifests and lockfile.

**Interfaces:** add `crypto?: CryptoProvider` to `VerifyTokenOptions`, `VerifySignedPayloadInput`, `CreateIdentityInput` and nested verification options.
Add trailing `options?: CryptoOptions` to `createSigningIdentity`, `createSigningIdentityForDID`, `createFullIdentity` and `randomIdentity`.
Produce `createVerifiers(crypto: CryptoProvider = nobleCrypto): Verifiers`.
Change `getVerifier` to `(algorithm: SignatureAlgorithm, verifiers?: Verifiers, crypto?: CryptoProvider): Verifier`.
Preserve the existing `Verifier` return union and caller override precedence.

Add `crypto?: CryptoProvider` to Node, Electron and HD store parameters and HD static factory options.
Add trailing `cryptoOptions?: CryptoOptions` to the Expo store constructor and `open` method.
Keep SecureStore entry options separate. Synchronous identity provisioning returns an identity whose signing method remains async.
Cached store reopening with a different provider throws, including attempts to change the default provider implicitly.

- [ ] Add spy-provider tests for did:key, did:peer:4, supplied-DID and every multikey Ed25519 signing path.
- [ ] Add partial override tests: overridden EdDSA bypasses the provider, while unoverridden ES256 reaches it.
- [ ] Add nested capability, revocation and both JWE unwrap branches asserting the same provider object reaches token verification.
- [ ] Add runtime store tests proving returned identities use the configured provider.
- [ ] Add cached-store conflict tests and regression checks for synchronous identity provisioning.
- [ ] Run the affected packages' tests. Expect provider-routing assertions to fail before implementation.
- [ ] Implement constructor capture and async signing without changing synchronous key derivation or key-agreement paths.
- [ ] Replace fixed default verifiers with provider-built verifiers and export the supported factory.
- [ ] Forward `crypto` through every nested verification call, including option-building helper functions.
- [ ] Update affected manifests to depend directly on `@kokuin/crypto` where they import it.
- [ ] Build affected packages in dependency order through `pnpm run build`.
- [ ] Run `pnpm --filter @kokuin/token --filter @kokuin/capability --filter @kokuin/jwe test`.
- [ ] Run Node, Electron, Expo and deterministic unit/conformance tests. Expect preserved store semantics and provider capture.
- [ ] Commit as `feat: thread crypto providers through tokens and identities`.

### Task 4: migrate controller authentication and isolate verification caches

**Files:** modify `packages/controller/src/{events,epoch-events,device-revoke,epoch,fold,log,supersede,history,state,resolver,fold-memo,identity,keystore-identity,profiles,index}.ts`.
Create `packages/controller/src/crypto.ts` for shared controller crypto options.
Modify `packages/controller-conformance/src/index.ts`, controller test fixtures and existing controller tests.
Create `packages/controller/test/crypto-provider.test.ts`. Update relevant integration callers under `tests/integration/`.

**Interfaces:** export `ControllerCryptoOptions = CryptoOptions` from `crypto.ts`.
Add optional `crypto` fields to existing parameter objects. Add trailing `options?: ControllerCryptoOptions` to positional crypto-dependent functions.
Convert existing result `T` to `Promise<T>` whenever a function signs or verifies, directly or transitively.

Required async exports include `signEvent`, `verifySignatures`, `createInception`, `createRotate`, `createReset`, `verifyInception`, `verifyRotate`, `verifyReset`.
Also convert `createAdd`, `createRenew`, `createRemove`, `createRevoke`, `createDeviceRevoke`, `verifyEpochSignature`, `foldEpoch` and `foldLog`.
Also convert `foldHeld`, `withEpoch`, `epochHeads`, `mergeLogs`, `pruneLog`, `resolveBranches`, `authoritativeLog` and `currentState`.
Convert controller identity constructors that fold logs. Propagate internally through `*Within` and detailed helpers.
`memoizedAuthoritativeLog` returns `Promise<AuthoritativeLog>`. Existing `LogStore.merge` already accepts an async callback.

Keep `didFor`, `didFromInception`, canonicalisation, SHA-256 digests, key derivation and `enumerateProfiles` synchronous.
Change profile enumeration to derive DIDs through `didFor`, avoiding an unnecessary signature.
Controller-conformance crypto-dependent callbacks now return Promises and their cases await them.

- [ ] Add a rejecting-provider test after a permissive provider primes the same log's memo. Assert rejection still occurs.
- [ ] Add deferred-provider tests for concurrent resolution, a newly loaded revoke, frozen views and failed-fold retry.
- [ ] Add malformed signature, small-order and mixed-order cases through actual controller verification exports.
- [ ] Preserve existing failed-signature budget tests. Assert no work starts beyond the current deterministic budget.
- [ ] Assert ordinary multi-signature events use one `signBatch` or `verifyBatch` call with positional ordering intact.
- [ ] Add a golden profile test asserting `enumerateProfiles` remains synchronous and produces unchanged DIDs and handles.
- [ ] Run `pnpm --filter @kokuin/controller test`. Expect routing assertions to fail before migration.
- [ ] Convert signing and verification primitives, then their callers, preserving causal evaluation order.
- [ ] Use bounded batches within an event. Keep causal events and hostile-copy evaluation sequential where budgets depend on earlier results.
- [ ] Await folds inside history merge callbacks. Preserve rollback, retry purity and unchanged-object write suppression.
- [ ] Partition successful fold memos using `WeakMap<CryptoProvider, Map<string, MemoEntry>>`, bounded at 256 entries per provider.
- [ ] Preserve in-flight resolver cleanup and frozen-view behaviour. Do not cache provider failures as successful folds.
- [ ] Retain false/refusal results for malformed peer input. Propagate operational provider errors without caching or fallback.
- [ ] Audit catch blocks to distinguish decoded-input errors from rejected provider execution.
- [ ] Migrate controller conformance and all test fixtures to await signatures, builders and folds.
- [ ] Run `pnpm run build` and `pnpm --filter @kokuin/controller test`.
- [ ] Run store-controller tests and `pnpm run test:integration` with its documented database services available.
- [ ] Expect identical fork, denial, truncation and transactional outcomes under noble and a delayed provider wrapper.
- [ ] Commit as `feat: make controller authentication asynchronous and provider scoped`.

### Task 5: carry verified record digests and migrate hashing boundaries

**Files:** modify `packages/records/src/{record,op,policy,decision,visibility,apply,range,reconcile,index}.ts`.
Modify existing tests under `packages/records/test/`, including `decision-fixture.ts`.
Create `packages/records/test/crypto-provider.test.ts` and update the records manifest.

**Interfaces:** extend `VerifiedRecordOp` with `contentDigest: string`.
Change `recordClaimDigest(claim, options?: CryptoOptions): Promise<string>`.
Change `recordPayloadDigest(payload, options?: CryptoOptions): Promise<string | null>` and `recordPayloadMatches(...): Promise<boolean>`.
Add trailing `options?: CryptoOptions` after existing `methods?: MethodRegistry` arguments on verification/decision helpers.
Add trailing crypto options to `signRecordOp`, without replacing its identity's signing provider.
Add `crypto?: CryptoProvider` to `ApplyRecordChunkParams` and `VisibilityContext`.

Hashing exports `fingerprintRange`, `summarizeRange`, `splitRange` and `rangeLeaf` return Promises of their existing results.
`nextRequesterSteps` and `advanceRecordPull` also return Promises because they compare fingerprints.
Use trailing `options?: CryptoOptions`, preserving existing positional arguments and result shapes.
Keep `compareRecordOps` and `recordDecisionFromVerifiedCopies` synchronous. They consume `op.contentDigest`.

- [ ] Capture golden outputs from current record tests before migration, including the 16-byte range fingerprint fixture.
- [ ] Add verified-op assertions equating `contentDigest` with the existing claim digest, including `meta.version` and tombstones.
- [ ] Add a provider spy asserting sync policy/decision helpers perform no hashing after verification.
- [ ] Add mutation tests that alter caller records during deferred hashing. Assert returned claim and digests describe the same original bytes.
- [ ] Add range tests for duplicate positions, signer-set changes, wraparound sums and malformed digests after async conversion.
- [ ] Run `pnpm --filter @kokuin/records test`. Expect missing carried-digest and provider assertions to fail.
- [ ] Route claim, payload, op-token and range hashing through the provider. Preserve exact framing and output lengths.
- [ ] Compute the verified claim digest once after canonical claim validation and signature verification.
- [ ] Capture verified claims independently of caller-owned mutable record objects before suspension.
- [ ] Replace repeated claim hashing in policy, decision, visibility and apply comparisons with `op.contentDigest`.
- [ ] Keep payload checking at its current authorisation/apply boundary. Await it without accepting mismatched bytes.
- [ ] Narrow `range.ts` ordering helpers to the fields they consume, avoiding fabricated `VerifiedRecordOp` values.
- [ ] Use `blake3Batch` when creating independent range child summaries. Preserve output ordering and error behaviour.
- [ ] Migrate requester state progression and every fixture constructing verified operations or payload digests.
- [ ] Retain delayed-provider failure propagation. Do not persist partially verified operations or trust caller-supplied carried digests.
- [ ] Run `pnpm run build` and `pnpm --filter @kokuin/records test`.
- [ ] Expect unchanged golden bytes, permutation convergence, visibility, dependency and transaction outcomes.
- [ ] Commit as `feat: carry record digests across synchronous merge decisions`.

### Task 6: verify mobile integration and prepare the breaking release

**Files:** create the mobile conformance/integration modules, component and Maestro flow from the file map.
Modify `tests/e2e-expo/{App.tsx,package.json}` and existing E2E callers affected by async APIs.
Create the permanent provider/migration references and downstream handoff documents under `docs/agents/plans/next/`.
Update changed package READMEs and pnpm change intents through the releasing workflow.

**Interfaces:** the mobile runner reports case names, total, passed and failed without logging keys or input payloads.
Maestro asserts a stable completion marker and zero failures on both platforms.
Integration exercises native signing, token verification, controller log resolution and record hashing through explicit injection.

- [ ] Add mobile integration assertions that detect accidental default-noble routing using provider-call counters.
- [ ] Add an explicit construction-failure fixture and mixed-batch case to the mobile suite.
- [ ] Run every shared vector through noble and native providers on an iOS simulator and Android emulator.
- [ ] Run `pnpm --filter e2e-expo test` against both built clients. Expect zero conformance or integration failures.
- [ ] Pack public packages with `pnpm pack` from each package directory after building.
- [ ] Install packed packages into clean Node/web and Expo fixtures outside the monorepo.
- [ ] Verify Node/web default imports never load Nitro, Rust binaries or native installation scripts.
- [ ] Build both Expo platforms from packed packages with Cargo unavailable to the consumer build.
- [ ] Repeat the spike's complete device matrix on the final module. Expect retained routes to satisfy the original gate.
- [ ] Save final measurements beside the release report. Remove routes that no longer pass before release preparation.
- [ ] Document provider injection, strict-rule changes, custom verifier bypasses, target floors and static noble routes.
- [ ] Document every new async export and the required `await recordPayloadMatches(...)` migration explicitly.
- [ ] Prepare self-contained enkaku and kumiai handoffs listing changed APIs, versions and verification expectations.
- [ ] Create downstream `next/` items when those repositories' instructions and write permissions permit.
- [ ] Otherwise retain the handoffs in kokuin and mark downstream filing as an outstanding release requirement.
- [ ] Use `kigu:releasing` to prepare the coordinated 0.x minor release and exact package intents.
- [ ] Include controller and records in the breaking release. Move token, capability, browser, node and deterministic together.
- [ ] Keep Expo, Electron, ledger-device and crypto-native independently versioned, bumping affected packages as required.
- [ ] Run `pnpm change status`, `pnpm run build`, `pnpm test` and `cargo test --workspace --locked`.
- [ ] Run non-mutating Biome checks through `pnpm exec biome check ./packages ./tests`.
- [ ] Confirm existing Node, web, Electron and mobile CI checks pass. Record environmental failures precisely.
- [ ] Commit validated release preparation as `docs: prepare strict async crypto migration`.

Publishing and downstream implementation are separate actions. This planning request does not authorise publishing packages.
Use `kigu:complete` when implementation finishes to preserve summaries and remove ephemeral plan/spec files before merging.

## Coverage and self-review

| Spec requirement | Owning task |
| --- | --- |
| Benchmark gate before the breaking API migration | Separate spike, execution prerequisites |
| Strict Ed25519/P-256 parity and shared adversarial corpus | 1 |
| Async single and batch provider, default noble | 1, 3 |
| Nitro workers, input ownership, seed erasure | 2 |
| Prebuilt binaries and no Rust consumer requirement | 2, 6 |
| Explicit selection and custom verifier escape hatch | 2, 3 |
| Controller signing, folding and resolver propagation | 4 |
| Synchronous merge decisions with carried digests | 5 |
| Async payload/range hashing and reconciliation | 5 |
| Mobile conformance and final real-device benchmarks | 6 |
| Coordinated breaking release and downstream handoffs | 6 |
| N-API/WASM readiness without implementation | Binding-independent Rust core retained |

All five Review Focus conditions have explicit test owners above.
Measured routing, tool versions and deployment floors remain deliberate gate outputs, not unspecified implementation work.
