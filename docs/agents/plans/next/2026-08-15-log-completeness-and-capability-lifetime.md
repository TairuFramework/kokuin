# A loaded log still has no completeness proof on first contact

**Priority:** medium — reduced from high on 2026-08-15, when the design pass before the docs closed
the parts that were closable on the branch. What remains is the witness subsystem, which was always
outside it.
**Origin:** see `completed/2026-08-11-controller-key-events.complete.md`, "The review round after
complete" and "The design pass before the docs".

**What was closed on the branch, so this item is not read as wider than it is:**

- **Item 2 is done.** A capability authorising a `did:kokuin:` revoke must now carry `exp`
  (`REVOKE_UNBOUNDED_LIFETIME`), with `maxLifetimeSeconds` available for a ceiling. Taken then rather
  than filed because nothing downstream had adopted the method yet: the migration cost was zero and
  would not have stayed zero. The general "a capability with no `exp` never expires" outside the
  controller-revoke path stands, and is `backlog/2026-08-04-capability-iat-is-optional.md`'s
  neighbour.
- **Item 1 is half closed.** `LogStore` on `createControllerResolver` refuses a loaded log that does
  not supersede the last one accepted for that DID, which defeats replaying a stale prefix to a party
  that has seen the newer log. Item 3 below is unchanged.

## 1. Truncation on a first encounter is still a silent revocation bypass

`packages/controller/src/resolver.ts:94-102,136-147`. `loadLog` answers with whatever the caller
has, and nothing establishes that it is the *whole* log. A peer who serves a prefix — stopping just
before the `rev` that denies their device — produces a log that folds cleanly, verifies every
signature, chains every digest, and yields a deny set missing exactly the entry that matters. The
verifier cannot tell a truncated log from a short one.

The named limitation carried in the design record covers **forks** — "cross-group duplicity is
detectable, not preventable". This is **suppression**, which that sentence does not reach: there is
no second branch to compare, only an honest-looking prefix.

**What shipped**, and what it does not reach: `ControllerResolverOptions.history` takes a `LogStore`,
and a loaded log that does not supersede the last one accepted for that DID is refused
(`LOG_NOT_AUTHORITATIVE`), as is a genuine fork against it (`LOG_FORKED`). The comparison is
`resolveBranchesAsync`, deliberately *not* a high-water mark over `(gen, seq)` — supersession
legitimately lowers the sequence, so a mark would have rejected the owner's recovering rotate at the
moment it rescues the profile, which is a bricking bug rather than a defence. A stored log that no
longer folds is treated as no memory rather than as a refusal, so a fold rule that tightens in a
later release does not brick every cached profile; the cost is one round of the guarantee.

**None of that helps on a first encounter**, which is what is left. Closing it needs a **witness or
anchor**: the profile periodically publishes its head digest somewhere a verifier can reach
independently. That is the standard answer, it is a subsystem rather than a patch, and it is the
whole of this item now.

Do not leave it stated as the fork limitation. A reader who has that sentence in mind will conclude
suppression is covered, and it is not.

## 2. (closed 2026-08-15 — see the note at the top)

## 3. The receiving half of "encrypt to a profile" is not packaged

`packages/controller/test/encrypt-to-profile.test.ts:22-28` shows the intended shape, and every
consumer would hand-roll it: deriving the agreement key at the right `keyGen`/`keySeq` and building
the `agreeKey` callback. `@kokuin/controller` packages the sending half (`createTokenEncrypterAsync`
over a `did:kokuin:` resolver) and not the receiving half.

Lowest severity of the three and the only one that is purely ergonomic — but the subtlety it leaves
to consumers is exactly the one the `keySeq`-is-a-derivation-index change existed to get right, and
getting it wrong yields a key that silently fails to decrypt rather than an error.
