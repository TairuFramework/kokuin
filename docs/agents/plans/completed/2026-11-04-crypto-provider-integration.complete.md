# Crypto provider integration into existing APIs

Status: complete. Native route promotion and physical qualification remain open in the [benchmark gate](../next/2026-10-27-crypto-benchmark-gate.md).

## Goal

Route the existing identity, token, controller, record and vault operations through an immutable injected `CryptoProvider`, without changing canonical bytes.
The standalone providers came from the [standalone delivery](2026-10-27-crypto-consumer-packages.complete.md).

## Key design decisions

- One option, `crypto?: CryptoProvider`, defaults to strict `nobleCrypto`. Public APIs with two or more parameters take one params object, with option fields folded in flat rather than nested. `agreeKey` also takes an object on every identity, so multi-key identities stay substitutable.
- Provider identity is reference equality after resolving the default. Omission and explicit `nobleCrypto` are the same provider.
- Provider behaviour is immutable for its lifetime. There is no mutable global selection and no dynamic fallback. Native failures propagate.
- Custom verifier overrides keep precedence and own their verification policy. Missing algorithm overrides use the selected provider.
- Strict verification is a straight cutover in a coordinated 0.x minor release. Signatures accepted only by the previous ZIP-215 policy fail when reverified. There is no historical rescan or version gate.
- Strict Ed25519 keeps canonical encodings, small-order rejection, torsion-free public keys and signature points, and cofactorless verification. ES256 keeps low-S compact signatures over raw messages hashed once. The torsion check is unconditional, matching the Rust core.
- Noble caches public-key validation only: 256 entries keyed by an owned copy of the encoded key. The signature point is checked on every call.
- Every verification cache (token, fold, record op) is partitioned by provider and verification policy. A permissive provider can never prime a cache for a rejecting one. Operational provider failures are never cached as success.
- Controller signing, verification, folds, history, resolution and identity construction are asynchronous. Causal evaluation order and the deterministic failed-signature budget are preserved. Signatures verify in batches of four within an event, stopping after the first failing batch.
- `VerifiedRecordOp.contentDigest` is computed once during verified-operation construction. Policy, decision, visibility, apply and vault branch comparisons stay synchronous and consume the carried digest. Verified operations are deep-frozen.
- Caller-owned inputs (claims, payloads, metadata, unique bytes, descriptors, factor inputs) are snapshotted into owned storage before the first suspension. `Buffer.slice` shares storage, so copies use `new Uint8Array(view)`.
- Async payload and metadata validation finishes before persistence or destructive deletes, under standalone and ambient transactions.
- Vault metadata uses a private synchronous structural parser for ordering and dependency enumeration. Public `vaultRecordMeta` performs the asynchronous owner/key-ID commitment check at every authorisation and persistence boundary.
- Identity stores capture one resolved provider and reject reopening with a different one. The vault coordinator resolves one provider for itself and its nested records and rejects an explicitly conflicting nested provider before any work.
- Vault hashing stays on single `blake3` calls. Native single calls already beat noble, so no batching was introduced.
- Hardware signing, browser WebCrypto signing, key derivation, key agreement, SHA-256, X25519, HKDF, AES-GCM, BIP39 and random generation keep their current paths.

## What was built

- token, capability and jwe: provider threading through signing, verification, revocation and both JWE unwrap branches.
- controller and controller-conformance: the complete async migration and an awaited conformance contract.
- records: async claim, payload, range and reconciliation hashing with carried content digests.
- vault, store-vault and store-delegation: provider-routed digests, key IDs, metadata validation, decoding, wrapping, coordinator and revocation wrappers.
- node, electron, expo and deterministic: provider capture and reopen-conflict rejection.
- Migration notes in each package README, a provider adoption section in the crypto provider reference, and minor release intents per the release matrix. `@kokuin/crypto` is unpublished, so it first releases at 0.1.0 with the validation cache.
- Downstream handoffs: [enkaku](../next/2026-11-04-enkaku-crypto-provider-handoff.md) and [kumiai](../next/2026-11-04-kumiai-crypto-provider-handoff.md).

Verification: workspace build and type checks, the full unit suite and Biome pass. CPU-heavy controller suites need normal scheduling priority to stay inside their timeouts.
