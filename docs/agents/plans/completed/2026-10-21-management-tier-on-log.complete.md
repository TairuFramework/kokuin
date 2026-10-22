# Management tier on the controller log — completed

**Status:** complete
**Date:** 2026-10-21
**Branch:** `management-tier-on-log` (design `9ad452d` .. `0aea6fc`). Build, `test:types` 34/34,
test 66/66 (controller 714, capability 212, store-controller 19), biome clean.
**Release:** breaking. Intents cover `@kokuin/controller`, `@kokuin/capability`, `@kokuin/token`,
`@kokuin/store-controller` (now `@hozon/db` `^0.3.0`) and `@kokuin/store-delegation`.

## Goal

The root signer (Ledger or cold mnemonic) comes out only for setup, for adding a management device,
for settlement and for recovery. Day to day, a few **management devices** mint grants for edge
agents, revoke them, and renew each other. This replaces the capability-authorised revoke. That
revoke was checked against the clock, so once its capability expired every log containing it stopped
folding (`REVOKE_NOT_AUTHORISED`). The DID became unresolvable to newcomers, and a truncated prefix
won anti-truncation.

## Key design decisions

- **Management authority lives in the log, and member actions merge rather than compete.** No member
  action can fork the log. Only root events form a single chain, and only root settles.
- **Two layers.** The root chain (`icp`, `rot`, reset) stays linear, with today's precedence: a
  higher generation wins, a pre-committed `rot` beats a current-key event, anything else is
  duplicity resolved by a reset. Branch selection compares from the top generation's reset. Every
  `rot` is a settlement carrying a full snapshot (`m` members with add reference and lease end, `d`
  deny set). A reset may carry a snapshot. A blind reset has exactly one encoding (`d: []`, no `m`),
  so it stays byte-identical per `(seed, profile, gen)`.
- **Epochs are DAGs.** Between root-chain events, `add`/`ren`/`rmv`/`rev` events name their epoch
  `e` and parents `p` (at most 16, same epoch only; a missing parent means pending, not an empty
  past). Authorisation is causal: an event is judged against its ancestors' state only, never
  arrival order or wall time. Effects are semilattice unions: denials, removals and adds union, the
  lease is the maximum renewal, and removal dominates renewal. The order is Kahn topological with
  ties broken by digest.
- **Who may do what.** Only root adds a member, and root signs every add. Root or any *other* member
  renews or removes. "Other" is judged by pinned-key equality, so an alias cannot self-renew. Root
  or any single member revokes an edge holder. A member revoke may not target any member in its
  causal past, removed or denied ones included (the spec overrode the task brief here). Root and
  member keys are disjoint: a member pin may never be any root key, the recovery commitment included.
- **Members are Ed25519 `did:key` or long-form `did:peer:4`.** The DID must carry the pinned key.
  The incarnation is the add digest, so a delayed remove never hits a re-add.
- **Denial dominates membership.** A member targeted by a denial in its causal past is not
  effective. Events concurrent with the denial are not voided. One predicate, "this denial targets
  this membership", serves both the revoke guard and dominance: the normalised DID or `#` plus the
  pinned key.
- **The fold never reads a clock or a lease.** The lease bounds grants only; only a removal ends log
  authority.
- **Limits.** Request limits reject input and never change memory: `MAX_LOG_EVENTS` 8192,
  `MAX_EVENT_BYTES` 8192, `MAX_EVENT_SIGNATURES` 16, `MAX_EVENT_PARENTS` 16, and
  `MAX_FAILED_SIGNATURES` 64. Past 64 failed signatures the whole presentation is refused with
  `TOO_MANY_FAILED_SIGNATURES`, which depends on the total, not the order. Epoch saturation is
  separate: more than `MAX_EPOCH_EVENTS` (4096) authenticated events fail the epoch closed and are
  remembered until a settlement. The root chain still folds, so root can always settle.
- **Memory.** `authoritativeLog` stores the settled chain plus the current epoch's applied events,
  one verified copy each. Old epochs are dropped at settlement. Unauthenticated input never reaches
  the store, and `LogStore.merge` is atomic. Stored current-epoch events are **not re-verified**,
  only re-authorised, so **a `LogStore` is trusted for signatures**: write to it only what
  `authoritativeLog` returned for that DID, never peer bytes or a `mergeLogs` union. This keeps
  re-resolving a held 4000-event epoch at 0.57 s instead of 4.5 s. An unchanged log is not
  rewritten. A corrupt or non-folding row counts as no memory.
- **Member grants (capability).** `sub` is the controller DID and `iss` a member DID. The `mbr {add,
  g}` claim names the incarnation and generation. The grant is valid when the incarnation is
  effective, it is signed by exactly the pinned key (`signingKeysOf`), `exp` ≤ lease, and
  `exp − iat` ≤ 43200 s (configurable). These bounds are also checked at mint. One frozen view per DID
  (`resolveMember`, `frozen()`) answers membership, lease and every delegation-link denial for one
  verification, and saturation fails closed.
- **Removed:** the capability-authorised revoke (`verifyCapability`, the `capability` step,
  `createControllerCapabilityVerifier`, `createRevokeWithKey`'s `cap`), `supersedes()`, and
  `createStateResolver`.

## What was built

- `@kokuin/controller`:
  - `epoch-events.ts` (builders), `epoch.ts` (fold), `members.ts`, `log.ts`;
  - `epochHeads`, capped at 16, plus `pruneLog` and `mergeLogs`, both with held-input limits;
  - `history.ts` (`authoritativeLog`), `limits.ts`;
  - the resolver's `resolveMember` and frozen view;
  - snapshot-aware reset and rotation.
- `@kokuin/token`: `signingKeysOf`.
- `@kokuin/capability`: the member-grant chain root in the check and delegation walk, plus minting.
- `@kokuin/store-controller`: atomic merge, skip-unchanged write, corrupt row as no memory.
- `@kokuin/controller-conformance`: the spec's conformance cases, including the rule mutations.
- Docs: `docs/reference/controller.md` (custody tiers, events, fold, branch selection, memory),
  `docs/reference/security.md` (accepted risks, verification cost), `docs/reference/capability.md`
  (member grants).

## Accepted risks (unchanged from the design)

- **Stolen member.** It can remove every honest member, deny edge holders and flood the epoch until
  root settles: one root ceremony per theft.
- **Removed members vs offline verifiers.** A removed member can keep minting grants that verifiers
  which never saw the removal accept, until its lease end.
- **Withheld events on first contact.** See `next/2026-08-15-log-completeness-and-capability-lifetime.md`.
- **Incomplete settlement.** A snapshot drops what root never saw.

## Follow-ons

`backlog/2026-10-21-management-tier-follow-ons.md`. Enkaku adopting the frozen view is tracked in
enkaku's backlog. Adoption by kubun and kumiai is out of scope and needs its own plans.
