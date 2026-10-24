# Snapshot tombstone growth

**Status:** backlog
**Origin:** removed-member tombstones in root snapshots (`@kokuin/controller` 0.3, field `u`). Unbounded
growth within a generation was accepted for the first release.

## Context

A root snapshot now carries every removed incarnation of the generation as a tombstone, so a record a
member signed keeps verifying through `resolveMemberHistoric` after the member is removed and the epoch
is settled. Each tombstone repeats a full member entry in every later carrying snapshot. `MAX_EVENT_BYTES`
bounds epoch events only; root-chain events have no controller limit, so a long-lived generation with
member churn grows each settle event without bound. Root may prune with `snapshotOf(head, { drop: {
members } })`, which discards the historic evidence for future receivers (earlier chain states keep what
they already checkpointed).

## Work

- **Size warning.** Root tooling warns when a settle snapshot's tombstones pass a threshold (count or
  bytes), naming the oldest incarnations and the cost of pruning them.
- **Pruning policy.** Define when a tombstone may go: e.g. once no record signed by that incarnation can
  still need verification (all its grants revoked or expired, or the consumer confirms), or at the next
  reset. Decide whether the policy lives in the controller (a `snapshotOf` option) or in each consumer.
- **Evidence elsewhere.** Consider whether a pruned incarnation's evidence can ride with the records it
  signed (the `add` event) instead of the log.

Reopen when: a consumer reports settle events over a transport or storage limit, or before the first
generation with regular member churn ships.
