# Integrate crypto providers into existing APIs

## Prerequisites

The [standalone delivery](../completed/2026-10-27-crypto-consumer-packages.complete.md) is complete.
This migration requires a passing [physical benchmark gate](../next/2026-10-27-crypto-benchmark-gate.md).
The [expanded conformance work](../next/2026-10-27-crypto-package-release.md) remains required before production-readiness claims.
The measured route manifest determines which variants execute natively.

## Architecture and invariants

`CryptoProvider` and strict `nobleCrypto` already exist in `@kokuin/crypto`.
`createNativeCrypto()` already supplies explicit standalone Nitro construction.
Thread `crypto?: CryptoProvider` from outer constructors through nested calls, defaulting to noble without mutable global selection.
Keep provider behaviour immutable for its lifetime.
Preserve custom verifier overrides. Missing algorithm overrides use the selected provider.
Native registration, ABI and execution failures propagate without dynamic fallback.

Preserve canonical bytes, DIDs, operation hashes, record digests and range fingerprints.
Retain strict Ed25519 subgroup checks and low-S compact ES256 verification over raw messages hashed once.
Hardware signing, browser WebCrypto signing, public-key derivation, key agreement and unrelated primitives retain their current paths.
SHA-256, X25519, HKDF, AES-GCM, BIP39 and random generation remain outside the provider.
Node N-API and browser WASM backends remain separate future work on the binding-independent Rust core.
The [Node N-API evaluation](#node-n-api-backend-evaluation) records the measured case for the Node backend.

## Token and identity propagation

- Forward providers through every token signing/verification path, capability, revocation and JWE unwrap branch.
- Capture the selected provider in Node, Electron, Expo and deterministic store identity construction.
- Reject conflicting providers when reopening cached stores, including implicit attempts to replace the default.
- Keep synchronous key-only identity provisioning where it performs no verification-dependent work.
- Preserve custom verifier precedence and document that overrides control their own verification policy.
- Partition token and other verification caches by every relevant provider/verifier identity.

## Controller migration

Convert all signing and verification-dependent functions to Promises, including the complete fold, history and resolver pipeline.
The migration includes events, epoch authentication, folds, branch resolution, authoritative logs, current state and controller identity construction.
Update controller conformance, stores and integration callers together.

Keep deterministic DID derivation, canonicalisation, SHA-256 framing and profile enumeration synchronous.
Profile enumeration derives DIDs through `didFor` rather than signing an inception.
Keep causal evaluation order and the deterministic failed-signature budget.
Use bounded batches within events without speculatively verifying hostile events beyond the existing budget.

Partition successful fold memos through provider identity, retaining the existing bounds and settled-success rules.
Preserve resolver in-flight sharing, failure eviction, frozen views and unchanged-write suppression.
Malformed peer input retains its established refusal behaviour. Operational provider failures propagate without successful caching.
Test a rejecting provider after a permissive provider primes the same log, including concurrent resolution and retry cases.

## Record hashing and synchronous decisions

Compute `contentDigest` during verified-operation construction using the existing canonical claim and `meta.version` treatment.
Capture caller-owned claims before suspension so carried digests describe the same bytes as verified claims.
Carry the digest through `VerifiedRecordOp`, decisions and every fixture.
Policy, decision, visibility and apply comparisons remain synchronous and consume the carried digest.

Make claim/payload hashing, payload matching and range fingerprinting asynchronous where they invoke a provider.
Migrate `recordPayloadMatches` callers to await its result.
Propagate asynchronous range work through leaf construction, splitting, summaries and requester reconciliation.
Keep payload checking at the existing authorisation boundary and reject mismatched bytes before persistence.
Preserve framing, output lengths, ordering, tombstone behaviour, convergence and transaction outcomes through golden fixtures.

Re-audit current call sites, including vault/store-vault, rather than relying on old file-level assumptions.
Store changes use `withStoreTransaction` and preserve the repository's parameter limits.

## Release and downstream handoff

Run shared mobile conformance and injected-provider integration checks with call counters detecting accidental noble routing.
Retest retained physical workloads on the final module and remove routes that fail the agreed gate.
Document every new asynchronous export and provider option.

The coordinated 0.x minor release makes a straight cutover to stricter verification.
Crafted signatures accepted only by the previous ZIP-215 policy become invalid when reverified.
No historical rescan or version gate is planned.

Include controller and records in the breaking release.
Move token, capability, browser, node and deterministic together through releaser judgement.
Keep SDK/hardware-bound packages independently versioned and use pnpm's built-in release workflow.
Prepare self-contained enkaku and kumiai handoffs listing new awaits, provider options, versions and verification expectations.
Downstream implementation and publication remain separately authorised actions.

## Node N-API backend evaluation

Evaluated 2026-11-04 with a throwaway napi-rs 3 addon linking `kokuin-crypto` directly.
It is follow-on work after this migration: Node and Electron need the provider threading above before a backend can plug in.

### Measurements

Single runs on a shared 4-vCPU x86_64 Xeon container, Node 22.23.4, OpenSSL 3.5.9.
Ratios should transfer roughly; absolute numbers will not. arm64 was not measured.
Values are µs per operation.

| Operation | Current noble | Strict noble | N-API sync | N-API async | `node:crypto` |
|---|---|---|---|---|---|
| Ed25519 sign, 32 B | 442 | 462 | 26.6 | — | 28 |
| Ed25519 verify, 32 B | 1,024 | 2,592 | 101 | 142 | 85 |
| ES256 verify, 32 B | 1,680 | 1,669 | 145 | 200 | 65 |
| BLAKE3, 32 B | — | 5.9 | 1.06 | — | — |
| BLAKE3, 4 KB | — | 61.9 | 1.78 | — | — |
| BLAKE3, 64 KB | — | 986 | 9.4 | — | — |

"Current noble" is the lax path `token` and `controller` use today; "strict noble" is `nobleCrypto`.
A synchronous N-API call costs about 1 µs over pure Rust (strict Ed25519 verify: 98.5 µs in Rust, 100.6 µs through N-API).
An async call adds 40–55 µs for the libuv threadpool hop. Batches of 32 amortise it to about 109 µs per Ed25519 verify.
The async contract therefore favours the batch methods.

Strict noble Ed25519 verification is 2.5× slower than the current lax path because of its subgroup checks.
Moving Node to the strict contract on noble alone would regress verification throughput.
Natively, the strict checks are 10× cheaper than today's lax path.

### `node:crypto` is not conformant

Against the shared corpus, `node:crypto` accepts three vectors the contract rejects:
a mixed-order Ed25519 public key (k = 0 mod 4), an identity public key with S = 0, and a high-S ES256 signature.
It provides no BLAKE3.
A JavaScript high-S check is cheap and yields a conformant ES256 verifier at 65 µs, faster than the RustCrypto `p256` path.
The Ed25519 subgroup checks need curve arithmetic per signature and would restore noble's cost.

### Cost

- Code: about 80 lines of Rust bindings plus a TypeScript `CryptoProvider` of roughly 100 lines, reusing the core crate and shared corpus.
- napi-rs `AsyncTask` replaces the C++ worker and owned-buffer code the Nitro bridge needs. The `kokuin-crypto-ffi` C ABI is not involved.
- Build: prebuilt binaries for linux x64/arm64 (gnu and musl), macOS x64/arm64 and Windows x64/arm64, about 0.9 MB each unstripped.
- Release: per-platform packages under `optionalDependencies`, a cross-compiling CI matrix with macOS and Windows runners, and binary provenance.
- Maintenance: every dalek or `p256` security update requires rebuilding and republishing all binaries.
- N-API is ABI-stable, so one binary per platform covers every Node and Electron version. Electron still unpacks `.node` files from asar.
- Bun and Deno load napi addons but were not tested.

### Open decisions

- Package shape: a separate `@kokuin/crypto-node` floating independently, like `@kokuin/crypto-native`.
- Unsupported platforms: falling back to strict noble at provider construction differs from the mobile no-fallback rule and needs an explicit decision.
- Gate: reuse the benchmark gate on CI hosts, including arm64, before committing to the build matrix.
- Whether the conformant `node:crypto` ES256 verifier is worth adopting independently, since it needs no native packaging.
