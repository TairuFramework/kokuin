# Rust crypto backend spec review

**Date:** 2026-10-25
**Spec:** [Rust crypto backend](2026-10-24-rust-crypto-backend-design.md)
**Verdict:** suitable for a benchmark spike. Production rollout remains conditional on device measurements and design approval.

The architecture fits the repository. The spec identifies the consensus risk and preserves noble as the default.
The following gaps need explicit implementation decisions. The companion plans supply proposed decisions without changing the spec's approval status.

## Findings

### High: async controller migration includes the complete fold pipeline

`events.ts` is only the entry point. `epoch.ts` supplies synchronous authentication callbacks and deterministic failed-signature accounting.
`fold.ts`, `log.ts`, `supersede.ts`, `history.ts`, `state.ts`, controller identities and resolvers all consume synchronous results.
`profiles.ts` even signs an inception merely to derive its DID.

Convert verification-dependent operations throughout this pipeline. Keep deterministic derivation synchronous by using `didFor` in profile enumeration.
Update `controller-conformance` and its consumers together. Preserve ordering, resource limits, frozen resolver views and atomic history updates.
Do not preverify every hostile event concurrently. That would perform work beyond the existing failed-signature budget.

### High: verification caches must include provider identity

`packages/controller/src/fold-memo.ts` holds a process-wide cache keyed by DID, loaded log and seen log.
An injected provider becomes another input. Without isolation, a permissive provider's cached success can bypass a strict provider.

Partition the bounded memo by provider object identity using a `WeakMap`.
Cache settled successes only. Preserve per-resolver in-flight sharing and failure eviction.
Test two disagreeing providers against identical logs without clearing the memo between calls.

### High: key erasure must cover the C++ input owner

Rust `zeroize` cannot erase an independently owned C++ input copy.
Packing a signing batch into an ordinary buffer could retain every seed after the Rust temporary disappears.

Use a zeroising owner for every native allocation containing seeds, including error and dispatch-failure paths.
Copy JS inputs before returning the Promise. Preserve each typed array's `byteOffset` and `byteLength`.
Never erase caller-owned JS memory. Keep output owners alive until JS releases them.

Nitro documents these ownership boundaries in its [ArrayBuffer documentation](https://nitro.margelo.com/docs/types/array-buffers).
Its [Promise documentation](https://nitro.margelo.com/docs/types/promises) describes C++ worker-pool dispatch.

### High: the benchmark gate needs comparable semantics and a stop rule

Decision 11 does not specify workload sizes, noise handling, or partial-operation success.
Comparing strict Rust against current ZIP-215 noble also confounds implementation speed with verification-rule changes.

Measure current noble and proposed strict noble separately. Use strict noble for the gate.
Include subgroup checks, input copies, dispatch, result conversion and Promise settlement in native timings.
Record wall latency and JS-thread occupation separately. Require real iOS and Android results before API migration.

The spike plan proposes conservative pass criteria and an explicit routing manifest.
An unmeasured operation stays on noble. A missing device leaves the gate pending.
If no operation passes, stop without changing existing public APIs.

### Medium: malformed inputs and algorithm encodings need one contract

The interface is deliberately provisional, but the shared suite needs final rules before provider implementations diverge.
Specify Ed25519 seeds, raw messages, P-256 SEC1 keys, compact signatures, output lengths and batch failures.
P-256 must hash the raw message exactly once. Reject high-S inputs rather than normalising them.

Explicit subgroup checks remain necessary. Canonical decoding must also reject identity points, which are themselves torsion-free.
Rust must compare decompressed-and-recompressed encodings against both original A and R bytes.
Do not assume library flags implement the whole contract.

These checks use the documented [dalek verification API](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html)
and [torsion checks](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/edwards/struct.EdwardsPoint.html).
The installed noble source confirms its cofactored equation in `node_modules/@noble/curves/src/abstract/edwards.ts`.

Upstream vectors require provenance and explicit expected outcomes under this project's stricter policy.
Do not copy Wycheproof's expected outcomes blindly or derive expected values from either implementation under test.

### Medium: provider injection must reach real signing entry points

`ExpoKeyStore.provideIdentity()` currently constructs a default identity internally.
Adding providers only to token constructors would leave normal Expo callers signing through noble.
Node, Electron and deterministic stores have the same construction pattern.

Thread `crypto?: CryptoProvider` through identity constructors, stores, nested capability checks and JWE unwrapping.
Reject conflicting providers when reopening cached stores. Preserve hardware and WebCrypto signing paths.

### Medium: carried record digests require a complete caller migration

`VerifiedRecordOp` currently has no content digest. Policy, decision, visibility and apply functions recompute it independently.
`rangeLeaf`, `splitRange`, `nextRequesterSteps` and `advanceRecordPull` also hash indirectly.

Compute `contentDigest` during verification using the existing `meta.version` substitution.
Carry it through every verified-op fixture and decision. Keep comparison helpers synchronous.
Make range operations that actually hash asynchronous. Preserve every existing digest byte and reconciliation outcome.

### Medium: native publication needs a reproducible consumer test

The repository currently targets Expo 58 and React Native 0.88. Historical SDK 57 comparisons cannot establish present compatibility.
Nitro versions, native minimum versions and ABI support require a successful build against these current targets.

Test installation from packed packages outside the monorepo with Cargo absent from the consumer environment.
Require prebuilt iOS device/simulator slices and Android arm64-v8a/x86_64 libraries.
Prove explicit native construction fails when registration or ABI compatibility is missing.

## Proposed planning boundary

1. Execute [the benchmark spike](../plans/2026-10-25-rust-crypto-benchmark-spike.md) after design approval.
2. Record measurements, selected versions, supported targets and the operation routing decision.
3. Reconcile those results into [the conditional rollout plan](../plans/2026-10-25-rust-crypto-backend.md).
4. Execute rollout only when the gate passes.

Downstream source migration remains follow-up work. Prepare self-contained handoff documents in kokuin.
Creating files in sibling repositories requires their repository instructions and filesystem authorisation during execution.
No product code, builds, device measurements or dependency installations form part of this review.
