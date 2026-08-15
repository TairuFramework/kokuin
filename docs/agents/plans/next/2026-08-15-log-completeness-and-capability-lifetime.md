# A loaded log has no completeness proof, and a capability need not expire

**Priority:** high — both are fail-open, both were found by the 2026-08-15 full-branch review of
`key-events-design`, and neither is closable without a decision that belongs outside that branch.
**Origin:** see `completed/2026-08-11-controller-key-events.complete.md`, "The review round after
complete".

## 1. Truncation is a silent revocation bypass

`packages/controller/src/resolver.ts:94-102,136-147`. `loadLog` answers with whatever the caller
has, and nothing establishes that it is the *whole* log. A peer who serves a prefix — stopping just
before the `rev` that denies their device — produces a log that folds cleanly, verifies every
signature, chains every digest, and yields a deny set missing exactly the entry that matters. The
verifier cannot tell a truncated log from a short one.

The named limitation carried in the design record covers **forks** — "cross-group duplicity is
detectable, not preventable". This is **suppression**, which that sentence does not reach: there is
no second branch to compare, only an honest-looking prefix.

What would close it, in increasing cost:

- A **high-water mark** per DID in the consumer's own storage: refuse a log whose head sits at a
  `(gen, seq)` earlier than one already seen. Cheap, purely local, and defeats replay of a stale
  prefix to a party that has seen the newer log. Does nothing for a first encounter.
- A **witness or anchor**: the profile periodically publishes its head digest somewhere a verifier
  can reach independently. This is the standard answer and it is a subsystem, not a patch.
- Accept and **document precisely** — with the high-water mark as the recommended consumer-side
  mitigation, since kubun and kumiai both cache resolved state and are the parties who would
  implement it.

Do not leave it stated as the fork limitation. A reader who has that sentence in mind will conclude
suppression is covered, and it is not.

## 2. A capability with no `exp` never expires

`packages/capability/test/zzatk-chain.test.ts` I4 holds this: a capability carrying no `exp`
verifies arbitrarily far in the future. `exp` is optional by design, and the completed record for
the controller work states that expiry is mandated "at the mint and verify policy layer" —
`assertDeviceCapabilityPolicy` with `DEFAULT_MAX_DEVICE_LIFETIME_SECONDS`. That layer is **opt-in**,
and `createControllerCapabilityVerifier` does not apply it.

So an eternal management capability can authorise log revokes forever, and the only remedy is the
deny set. That is a working remedy — it is why key and DID denial exist — but it is a remedy the
owner has to reach for, against a grant that never lapses on its own.

The decision this needs: whether the controller-revoke path should mandate a bounded lifetime rather
than merely offer one. Tightening it is not free — a management capability already issued without
`exp` would stop authorising, and a log that depends on one would stop folding — so it is a
migration, not a flag. Related: `backlog/2026-08-04-capability-iat-is-optional.md`, the same shape
one claim over.

## 3. The receiving half of "encrypt to a profile" is not packaged

`packages/controller/test/encrypt-to-profile.test.ts:22-28` shows the intended shape, and every
consumer would hand-roll it: deriving the agreement key at the right `keyGen`/`keySeq` and building
the `agreeKey` callback. `@kokuin/controller` packages the sending half (`createTokenEncrypterAsync`
over a `did:kokuin:` resolver) and not the receiving half.

Lowest severity of the three and the only one that is purely ergonomic — but the subtlety it leaves
to consumers is exactly the one the `keySeq`-is-a-derivation-index change existed to get right, and
getting it wrong yields a key that silently fails to decrypt rather than an error.
