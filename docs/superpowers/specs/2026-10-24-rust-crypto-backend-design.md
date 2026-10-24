# Rust crypto backend (mobile first) — design

**Date:** 2026-10-24
**Status:** design, awaiting approval (builder check done)

## Intent

Signing, verification and blake3 hashing in kokuin run as noble JS on the calling thread. On
mobile that is Hermes, which has no JIT, so noble's BigInt-heavy curve math is slow and blocks the
JS thread (UI jank, slow key-log and record verification). The goal is to move these operations
into a Rust core that runs **off the JS thread**, packaged first as a React Native module, behind a
provider interface the existing TS packages consume, with noble remaining the default backend.

The same Rust core is meant to back Node (N-API) and the browser (WASM in a Web Worker) later,
through the same provider interface. Those are not built now.

## Goals

- Ed25519 sign, Ed25519 verify, P-256 (ES256) verify, and blake3 hashing available through an
  async, batch-capable provider interface.
- A Rust implementation of that interface for iOS and Android, running work off the JS thread.
- A noble implementation of the same interface, used by default everywhere.
- Both backends give identical answers on a shared test-vector suite, including adversarial edge
  cases.
- Verification rules tightened to the most secure option (strict Ed25519, low-S P-256), identically
  in both backends.

## Non-goals

- N-API (Node) and WASM (browser) backends. The design must not preclude them; they are follow-up
  work on the same Rust core.
- sha256, x25519, hkdf, AES-GCM, bip39 and random key generation. They stay on noble (sha256 calls
  are small and frequent; moving them would cost more in thread hops than they take).
- ES256 signing (only the browser keystore signs ES256, through WebCrypto).
- kumiai/MLS crypto. It may adopt the core later; not in scope.
- Ledger device signing (signs on the device; unaffected).
- Automatic backend detection.

## Anti-goals (would be failure even if it works)

- **Backend divergence.** Any input where noble and Rust disagree on a verification result. For
  controller key logs that is a fork between peers.
- **Silent fallback.** An app that asked for the native backend quietly getting noble because the
  module failed to load. Explicit selection fails loudly.
- **A Rust toolchain requirement for JS consumers.** The native package ships prebuilt binaries;
  apps that never opt in are unaffected.
- **Wider private-key exposure than today.** Private keys already live in JS memory; the native
  side must not retain, log or cache them beyond the call.

## Decisions made with Paul

1. **Scope:** sign, verify, blake3 (sha256 stays noble).
2. **Off the JS thread, async everywhere.** APIs that are sync today and touch these operations
   become async. This is a breaking change shipped as a new 0.x version.
3. **Batch variants** of every operation from the start, because a thread hop costs about as much as
   one native Ed25519 verify; batching amortizes it.
4. **Explicit opt-in.** The app constructs and passes the native provider; noble is the default. No
   auto-detection (for now).
5. **Most secure verification rules,** even at the cost of a breaking change:
   - Ed25519: strict / SUF-CMA, replacing noble's ZIP-215 default. Reject non-canonical R and A
     encodings, S ≥ L, and small-order public keys (and small-order R).
   - P-256: keep `lowS: true`, compact 64-byte signatures over the SHA-256 prehash; reject r or
     s = 0, out-of-range values and off-curve keys.
6. **Mobile first** (iOS and Android). Node and browser later.
7. **Nitro Modules** for React Native, with a C++ Hybrid Object calling a Rust C ABI.
8. **Everything lives in the kokuin repo.**
9. **Straight cutover to the strict rules** in the 0.x bump. No version gate, no re-scan of
   persisted logs or records; a crafted ZIP-215-only signature already stored becomes invalid on
   re-verification, which is accepted.
10. **Record merge logic stays sync.** Digests are computed once at verification time and carried on
    `VerifiedRecordOp` and the merge decision; `policy.ts`, `decision.ts`, `visibility.ts` and
    `apply.ts` consume the carried digest instead of hashing. Only verification, payload hashing
    and range fingerprinting go through the provider.
11. **Benchmarks first, and they gate.** Before the async API break and the wiring, a benchmark
    spike (Rust core + minimal Nitro call, real iOS and Android devices, vs noble on Hermes) decides
    which operations move. An operation that is not faster than noble once the thread hop is
    counted (per single call and per batch size) stays on noble; if none move, the work stops
    there.

## Approaches considered

**React Native binding**

| Option | Trade-off | Outcome |
| --- | --- | --- |
| uniffi-bindgen-react-native | One Rust interface definition generates iOS/Android bindings and a WASM path; async built in. Copies bytes both ways; younger tool. | Rejected: Paul prefers an established module system. |
| **Nitro Modules (C++ Hybrid Object → Rust C ABI)** | One C++ glue layer shared by both platforms; `Promise<T>::async` thread pool; zero-copy native-owned output buffers; used by VisionCamera and MMKV. Needs cbindgen + hand-written C++; no WASM route (the Rust core still has one). | **Chosen.** |
| Turbo Modules (hand-written JSI C++) | Same shape as Nitro with more manual JSI work; codegen has no ArrayBuffer type. | Rejected: Nitro is the same design with less glue. |
| Expo Modules 1.0 | Fits Expo apps; but glue twice (Swift and Kotlin/JNI → C → Rust) and bytes copied both ways. | Rejected. |
| Expo Modules 2.0 (`@JS` macros) | Much faster sync calls; async ~5.5 µs/call vs TurboModule ~11 µs. iOS-only and experimental in SDK 57, Android not shipped, still Swift/Kotlin glue, ties to SDK 57+. | Deferred: revisit at its SDK 58 beta. Keeping the Rust core binding-agnostic makes a later Expo binding glue-only. |

**Zero-copy.** No option offers zero-copy for an async call reading a JS-allocated buffer: the JS
GC may move or free it, or JS may mutate it, while the worker reads. Inputs are copied once on the
JS thread (one memcpy per batch, negligible next to the crypto); Nitro returns native-owned output
buffers without copying.

**Code location**

| Option | Trade-off | Outcome |
| --- | --- | --- |
| **Inside kokuin** | Vectors, conformance and both backends side by side; rule changes ship in one release. Rust/NDK/Xcode enter kokuin's CI (precedent: `apps/ledger`). | **Chosen.** |
| Sibling repo | Keeps toolchains out of kokuin CI; kumiai could depend directly. Interface and vectors span two repos; every rule change is two releases. | Rejected. |

## Design

### Layout

- `crates/kokuin-crypto` — pure Rust core: ed25519 sign/verify, p256 verify, blake3, batch forms.
  No binding-specific code, so N-API (napi-rs), WASM (wasm-bindgen) and a future Expo binding can
  wrap it unchanged.
- `crates/kokuin-crypto-ffi` — C ABI over the core, header generated by cbindgen.
- `packages/crypto` → **`@kokuin/crypto`** (public): the `CryptoProvider` type and the noble
  implementation (`nobleCrypto`), which is the default everywhere.
- `packages/crypto-native` → **`@kokuin/crypto-native`** (public): the Nitro module (C++ Hybrid
  Object linking the prebuilt Rust static libraries for iOS and Android) exporting a
  `CryptoProvider`. Floats independently, like `expo`, since it is SDK-bound.
- `packages/crypto-conformance` → **`@kokuin/crypto-conformance`** (private, listed in
  `versioning.ignore`): the shared vector file and a framework-agnostic suite any provider must
  pass, in the style of `keystore-conformance` / `controller-conformance`. The Rust crate's own
  tests consume the same vector file.

### Provider interface (shape, not final signatures)

```ts
type CryptoProvider = {
  sign(alg: 'EdDSA', privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  signBatch(alg: 'EdDSA', items: Array<{ privateKey: Uint8Array; message: Uint8Array }>): Promise<Array<Uint8Array>>
  verify(alg: 'EdDSA' | 'ES256', signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>
  verifyBatch(items: Array<{ alg: 'EdDSA' | 'ES256'; signature: Uint8Array; message: Uint8Array; publicKey: Uint8Array }>): Promise<Array<boolean>>
  blake3(input: Uint8Array, dkLen: number): Promise<Uint8Array>
  blake3Batch(inputs: Array<Uint8Array>, dkLen: number): Promise<Array<Uint8Array>>
}
```

Operations are keyed by algorithm so ML-DSA (backlog: `2026-06-30-post-quantum-algorithms.md`)
can be added as another `alg` without reshaping the interface. Batch verification is a loop of
strict single verifies inside the backend, **not** algebraic batch verification: algebraic batching
is only consistent with ZIP-215 rules, and the batch exists to amortize the thread hop.

### Wiring into existing packages

Today's direct noble call sites for the in-scope operations:

- `token`: `identity.ts` (`ed25519.sign` in `signToken` paths), `verifier.ts` (`defaultVerifiers`).
- `controller`: `events.ts` (`signEvent`, `verifySignatures`).
- `records`: `record.ts` (`recordClaimDigest`, `recordPayloadDigest`), `op.ts`, `range.ts`
  (`fingerprintRange` and callers such as `summarizeRange`, `rangeLeaf`). Per decision 10, the
  sync merge engine (`policy.ts`, `decision.ts`, `visibility.ts`, `apply.ts`) reads carried
  digests rather than calling the provider.

Each takes the provider explicitly (option or constructor parameter, defaulting to `nobleCrypto`)
and awaits it.

The existing `verifiers?: Verifiers` override (token, capability, jwe) stays as an explicit escape
hatch; `defaultVerifiers` is replaced by verifiers built from the provider, so with no override the
provider decides (builder-check call). A custom verifier remains the caller's responsibility and
bypasses the strict rules, as it bypasses noble today; document this.

`signToken`, `agreeKey` and `Verifier` are already async-compatible; `signEvent`,
`verifySignatures` and the records digest/fingerprint functions become async, and the change
propagates to their callers in kokuin, then to enkaku and kumiai.

### Native module

- Each JS-allocated input is copied once into an owned buffer on the JS thread before dispatch
  (Nitro `ArrayBuffer.copy`); outputs are native-owned buffers returned without copying.
- Work runs on Nitro's `Promise<T>::async` thread pool.
- Private key bytes are zeroized in Rust (`zeroize`) after use; nothing is cached across calls.
- Prebuilt binaries ship in the npm package: an XCFramework for iOS (device + simulator), `.so` /
  static libraries for Android ABIs.

### Verification rules (both backends)

- **Ed25519 subgroup rule (builder-check call):** reject any A or R not in the prime-order
  subgroup (small-order *and* mixed-order), in addition to canonical-encoding and S < L checks.
  With no torsion component, the cofactored and cofactorless equations agree, which removes the
  divergence between noble (always cofactored, even with `zip215: false`) and `ed25519-dalek`
  `verify_strict` (cofactorless, rejects only small-order A and R). Cost: one extra scalar
  multiplication per point check; public-key checks can be cached per key.
- noble: `ed25519.verify(..., { zip215: false })` plus the explicit subgroup checks on A and R.
- Rust: `ed25519-dalek` `verify_strict` plus the explicit subgroup checks; `p256` crate with an
  explicit low-S check if the crate does not enforce it.
- The vector suite is the authority: where a library's flag and the rule list above disagree, add
  an explicit check until both backends pass every vector.

### Testing

- Shared vectors cover: RFC 8032 vectors; non-canonical R/A/S; S ≥ L; small-order and mixed-order
  keys and R; Wycheproof Ed25519 and ECDSA P-256 (SHA-256) suites; high-S; r/s = 0; off-curve keys;
  blake3 official vectors for several `dkLen` values.
- `nobleCrypto` runs the suite in vitest; the Rust crate runs it in `cargo test`; the native module
  runs it on an iOS simulator and an Android emulator through `tests/e2e-expo`.
- Benchmarks on real devices (iOS and Android): noble on Hermes vs native, single and batch sizes,
  measuring JS-thread time and wall time. Run first as the gating spike (decision 11), then again
  on the finished module; results recorded with the release.

### Release

- One 0.x minor bump covering: async `controller` / `records` APIs, the strict verification rules,
  and the provider parameter. `token`, `capability`, `browser`, `node`, `deterministic` move together
  per AGENTS.md.
- New public packages `@kokuin/crypto` and `@kokuin/crypto-native`; private
  `@kokuin/crypto-conformance` in `versioning.ignore`.
- Downstream (enkaku, kumiai) call-site migrations are **follow-up work**, not part of this plan
  (builder-check call): the plan ends at the kokuin release, and files a `next/` item in each
  downstream repo listing the now-async functions.

## Left to the builder

- Exact TS signatures, option names and where the provider is threaded (per call vs per
  constructed identity/store), within "explicit, default noble, no global".
- Batch wire format across JSI (flat buffer + offsets vs arrays of ArrayBuffers), chosen by
  benchmark.
- Android ABI list and iOS minimum version; CI shape for Rust and cross builds (e.g. cargo tests on
  every PR, mobile cross-builds on a separate workflow).
- Rust crate versions and feature flags.
- Whether `getPublicKey` (scalar multiplication on identity creation) also moves to the provider.
  It is not on the hot path today; include it only if benchmarks show it matters.
