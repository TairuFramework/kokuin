# Public key agreement to a recipient DID

**Status:** complete
**Date:** 2026-08-07
**Origin:** `completed/2026-08-07-public-recipient-key-agreement.complete.md`, filed from kubun's
credential store work.
**Branch:** `feat/derive-shared-secret` (7 commits: implementation + tests, exports, changeset and
plan lifecycle, a bump-level correction, a post-review fix wave, and one doc correction)

## Goal

Give a consumer holding a recipient DID a supported way to perform X25519 key agreement, without
building a JWE and without exposing the branch rule that decides which public key to agree with.

## The problem

Resolving a recipient DID to the X25519 public key you encrypt to has two branches, and picking
the wrong one produces a key that encrypts cleanly and silently never decrypts:

- A **did:peer:4** identity carries an independent agreement key in its document, and the sender
  MUST use the published key.
- A **did:key** EdDSA identity publishes none, and the sender derives one from the signing key via
  the birational map.

That rule lived in a module-private `resolveX25519Key` in `jwe.ts`, reachable only through
`createTokenEncrypter`. A consumer wanting a plain ECDH secret therefore had to either reimplement
it — a second implementation of a silently-failing rule, in another repo on another release
cadence — or ship a random secret inside a JWE it did not otherwise need. Kubun's credential store
took the second route: it needs a 32-byte secret only a named recipient can recover, which it then
combines with other factor secrets via HKDF, and paid roughly 200 bytes plus a second AEAD pass per
`did` factor per wrapping to transport a secret the recipient could have derived.

## What was built

`deriveSharedSecret(recipient: string): SharedSecretResult` in `@kokuin/token`, returning
`{ sharedSecret, ephemeralPublicKey }`.

**Key design decision — full encapsulation, not an exported resolver.** The originating request
offered two shapes: export the resolver, or take an ephemeral private key and keep the branch
choice inside. The shipped API is stricter than either — it generates the ephemeral pair
internally and returns only the public half, so the caller never holds the resolved recipient key
*and* never manages ephemeral key material. `resolveX25519Key` stayed module-private and gained a
second in-package caller rather than an export. The function itself is two lines; there is nothing
in it to get wrong.

**Key design decision — raw ECDH output, no KDF inside.** The result is byte-identical to what the
recipient's pre-existing `DecryptingIdentity#agreeKey(ephemeralPublicKey)` returns. That mirror is
why no new recipient-side API was needed at all. Applying a KDF internally would have produced a
value `agreeKey` cannot reproduce, forcing a second new export to mirror it — and consumers run
their own KDF with their own domain separation regardless. The cost is that the raw-output caveat
has to be documented at every touchpoint, which it is.

**Supporting refactor.** The ephemeral-pair-plus-ECDH step was extracted out of
`encryptWithX25519` into a module-private `agreeWithKey`, so `jwe.ts` holds exactly one X25519 ECDH
implementation, shared by the JWE path and the new export.

**Safety documentation.** Two caveats a consumer will otherwise hit are recorded in the JSDoc and
at length in `docs/reference/auth.md`: the agreement is anonymous ephemeral-static ECDH, so
possession of the secret is not evidence about the sender (use `jws-in-jwe` if you need that); and
the caller must bind the ephemeral public key and recipient DID into their own KDF context, which
the JWE path does not do for them either.

## Verification

Ten tests in `packages/token`, including a branch-inversion guard that recomputes the ECDH from the
recipient side against both candidate scalars — the two round-trip tests would both still pass if
sender and recipient were wrong in the same direction, so that guard is the one test that catches
an inverted rule. Also pinned: both of the package's two independent `agreeKey` implementations,
multi-KEM peer:4 ordering symmetry, and the three inherited error refusals. Package suite green at
261 tests.

A whole-branch review verified the sender/recipient symmetry holds for every identity shape
`createIdentity` can produce, including mixed-algorithm KEM keys, and confirmed that
`@noble/curves` rejects a low-order result from a hostile peer:4 document.

## Notes for whoever touches this next

- **Release.** The changeset is `patch` — the change is purely additive. `@kokuin/token` still
  releases as a minor because the unreleased `peer4-audienceless-iss` changeset is minor and
  breaking; changesets takes the highest pending bump per package.
- **The JWE path binds no party identity into its KDF.** Surfaced while documenting the raw API:
  the content key is derived with a fixed `algorithmID` and empty `partyUInfo`/`partyVInfo`, and
  `apu`/`apv` are never set on the protected header, so `decryptToken`'s reads of them are always
  empty. The ephemeral public key is still bound per-message via the protected header acting as
  AES-GCM AAD. Not a vulnerability, and unchanged by this work — see
  `backlog/2026-08-07-jwe-concatkdf-party-binding.md`.
- **Kubun's swap** from its JWE-wrapped random secret to this API is a kubun change, tracked there.
