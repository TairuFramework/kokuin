# Post-quantum algorithms (ML-DSA, ML-KEM)

**Status:** backlog
**Relocated from enkaku** in the 0.18 stack split (2026-06-30). Prose converted to kokuin terms
on 2026-08-03 (triage) — it had described the pre-split `@enkaku/*` packages for a month after
the move. The predecessor link points at the **enkaku** repo's `completed/` folder, not this one.

**Predecessor (enkaku repo):** `completed/2026-05-26-did-peer-4-pq-friendly.complete.md` —
`did:peer:4` PQ-friendly identifiers.

## Goal

Plug `paulmillr/noble-post-quantum` (ML-DSA signatures, ML-KEM key encapsulation, optionally
SLH-DSA) into the `@kokuin/token` algorithm registry, so identities can hold PQ keys end to end.

## Relationship to profile DIDs

`milestones/2026-08-07-profile-did-key-events.md` depends on this work, and constrains it in two
directions.

It needs phase 1 and 2 to be reachable *without changing any identifier*: under `did:peer:4` the
identifier is a hash of the key document, so adding an ML-DSA key mints a new DID and breaks every
ownership row downstream. Under the key-event design the key set lives in a log, so the same
migration is one rotation event and the DID is untouched. That is the strongest argument for doing
the two together rather than PQ first.

In the other direction, the size numbers below are a first-order constraint on that design, not a
footnote: every kumiai control-ledger entry is a signed token, replayed at every welcome and covered
by the authenticated head. ~7 KB tokens argue for rare rotation events, a checkpoint story, and
keeping device onboarding on the capability path where it produces no ledger entry at all.

Also note RFC 9964 (May 2026) now specifies the JOSE and COSE serialisations for ML-DSA, so phase 1
has registered `alg` values to target rather than private ones:
<https://www.rfc-editor.org/info/rfc9964/>. PQ/T hybrid composite signatures are still a draft:
<https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/>.

## Phasing (recommended)

Each phase is its own design and plan.

1. **Verifier-only.** Add an ML-DSA `Verifier` to the existing `Verifiers` map. Lets any
   consumer verify tokens signed by external PQ identities, with no keystore changes.
2. **Node and Electron signing.** Generate and store ML-DSA private keys via `@kokuin/node` and
   `@kokuin/electron` — neither has a size constraint. Wire the `KeyAlg` enum and multicodec
   entries.
3. **JWE hybrid KEM.** New envelope variant `alg: 'X25519+ML-KEM-768'` (or similar), combining
   the existing X25519 ECDH with ML-KEM encapsulation. Add it as opt-in; do not replace the
   X25519-only path.
4. **Browser and Expo keystore refactor.** Both hardcode classical algorithms and have size
   constraints incompatible with PQ key material — browser `SubtleCrypto` has no ML-DSA, and
   Expo's `expo-secure-store` hits an iOS Keychain cap around 4 KB that ML-DSA-87 exceeds. Move
   to raw bytes in IndexedDB, or split storage.

## Sequencing

Phase 3 rewrites `packages/token/src/jwe.ts`, the same file as
`backlog/2026-01-30-jwe-multi-recipient.md`. Both add a non-direct key-agreement mode with
per-recipient wrapped CEKs, so whichever lands first should define that shape and the other
should adopt it rather than introduce a second one.

Phase 4 overlaps `backlog/2026-07-16-browser-x25519-webkit-idb.md`, which already moved browser
agreement keys to raw bytes as a WebKit workaround. If that workaround is still in place when
phase 4 starts, the raw-bytes path it needs partly exists — check before rebuilding it.

## Notes

- The `did:peer:4` foundation already supports long-form documents containing multiple keys, so
  one identity can hold classical + ML-DSA + X25519 + ML-KEM. The algorithm work only adds
  verifier and codec entries plus key generation paths.
- `MultiKeyIdentity.sign({ kid })` already lets clients choose the signing key — useful during
  a hybrid transition.
- Defer MLS PQ ciphersuites until IETF `draft-ietf-mls-combiner` lands and `ts-mls` supports
  them. That is kumiai's call, not kokuin's.
- Defer Ledger PQ until firmware support exists.

## References

- noble-post-quantum: <https://github.com/paulmillr/noble-post-quantum>
- ML-DSA-65: ~1.9 KB public key, ~3.3 KB signature — tokens go from ~200 bytes to ~7 KB.
- ML-KEM-768: ~1.2 KB public key, ~1.1 KB ciphertext.
