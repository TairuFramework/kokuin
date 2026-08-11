# Downstream adoption of `did:kokuin:`

**Priority:** high — nothing downstream has been built against the shipped interfaces, and two of
the changes are breaking in ways a type check alone will not surface.
**Origin:** the `did:kokuin:` controller work, 2026-08-11. See
`completed/2026-08-11-controller-key-events.complete.md` for the design and its rationale.

## What changed that downstream must absorb

- **`@kokuin/token` is a major.** `packages/token/src/rotation.ts` and `createRotationAssertion`
  were deleted outright — rotation chains are what the key event log replaces. The JWE split moved
  the cipher-bearing code into `@kokuin/jwe`.
- **`DIDMethodResolver` gained two optional members**, `resolveAgreementKey` and `resolveDenySet`.
  Optional was deliberate — making either required breaks the published type and every hand-rolled
  stub — but a method that *can* revoke and omits `resolveDenySet` fails open. Any resolver
  implemented or wrapped downstream must implement it, and a wrapper that forwards `resolve` while
  quietly dropping `resolveDenySet` is the specific shape that fails silently.
- **`verifyCapability` takes a fourth argument**, the resolver for the subject at the log position
  being verified. It is required, and a call without it is refused at runtime rather than trusted —
  so an older fold calling an newer capability package fails closed rather than reverting to the
  bypass. That refusal is the safety net; it is not a substitute for building the two together.
- **Fail-closed changes read as regressions.** Several rounds of hardening turned former silent
  passes into hard failures. Denials that appear after upgrading are usually correct.

## Who is exposed

Measured 2026-08-11 from each repo's manifests and the symbols its sources import. **Three** repos
depend on kokuin, not two: `kubun` (18 manifests — `token`, `capability`, `browser`, `expo`),
`kumiai` (8 — `token`, `expo`), and `enkaku` (7 — `token`, `capability`, `electron`). None depends
on `@kokuin/controller`, so all exposure is through `@kokuin/token` and `@kokuin/capability`.

`kubun` is the heaviest consumer of what moved: `verifyToken`, `checkCapability`, `VerifyTokenHook`,
`createRevocationRecord`, `createFullIdentity` / `isFullIdentity`.

Two corrections to what the design notes carried:

- **No `deriveSharedSecret` / `isDecryptingIdentity` migration is owed.** Neither symbol appears
  anywhere in `kubun`. Kubun asked for `deriveSharedSecret` and never adopted it — see
  `completed/2026-08-07-derive-shared-secret.complete.md`.
- **The JWE split reaches nothing today.** No repo imports `encryptToken`, `decryptToken` or
  `createTokenEncrypter` in source.

## Work

1. Build `kubun`, `kumiai` and `enkaku` against the shipped packages. None was read during
   development. This gates everything else here.
2. Resolve `kumiai`'s dependency on an `@internal` export: `packages/mls/src/authentication.ts:5,76`
   imports `getSignatureInfo` from `@kokuin/token`, which kokuin marks `@internal` and deliberately
   kept marked when the neighbouring `CODECS` and `getAlgorithmAndPublicKey` were made public.
   Either kumiai stops using it or kokuin publishes it — an internal export with an out-of-repo
   consumer is neither, and it will be broken by a change nobody thinks is breaking.
3. Fix `kubun`'s own fail-open at `packages/store-delegation/src/revocation-checker.ts:49-58`. It
   predates this work and is the same failure mode the controller spent three rounds closing: a
   revocation check that cannot answer should deny, not pass.
4. Run the suites that never ran in the development environment: `tests/e2e-*`, `tests/ledger`, and
   the on-device firmware against the host-side `@kokuin/ledger-device`.

## Deferred with named owners

`kumiai` owns whether implicit device delegation is total or capped by a ceiling in the binding, the
device→profile binding entry, the roster projection at `roleReducer.verifyAuthority` and at the
universal admin invariant in `envelope-fold.ts`, and the genesis anchor carrying both the creator's
profile DID and their device DID — tracked in
`kumiai/docs/agents/plans/backlog/2026-08-07-did-registry-ledger-entries.md`.

`kubun` owns which group anchors the cut-off position for documents reachable from several groups,
and cache invalidation under superseding recovery — tracked in
`kubun/docs/agents/plans/backlog/2026-08-07-profile-did-ownership.md`.
