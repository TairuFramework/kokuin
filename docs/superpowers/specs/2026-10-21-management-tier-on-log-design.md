# Management tier on the controller log

**Status:** design, awaiting approval. Supersedes
`docs/agents/plans/next/2026-10-21-revoke-capability-expiry-in-folded-logs.md` (delete it when this
lands).

## Intent

The root signer (Ledger or cold mnemonic) should come out only for first setup, for adding a
management device, for settling disputes between management devices, and for recovery. Day to day,
a few trusted **management devices** (e.g. a desktop app that manages AI agents, plus the user's
phone) mint grants for **edge** agents and devices and revoke them.

Today the management tier is a capability: a `rev` carrying `cap` is verified against the clock.
Once that capability expires, every log containing a revoke it authorised stops folding
(`REVOKE_NOT_AUTHORISED`): the DID becomes unresolvable for any newcomer, and a truncated prefix wins
anti-truncation. With an offline root, the earlier "anchor by a later authority event" fix almost
never fires, because authority events are rare by design. A management capability also cannot be
renewed without root, since a delegated child cannot outlive its parent.

The fix: **management authority lives in the log.** The fold judges a management-signed event by
the management set published at that position, never by a clock. Time is checked only where it is
already normal: on grants, which expire anyway.

## Goals

- The fold stays deterministic and clock-free for every log. A log that folds once folds forever.
- Management devices hold a lease and renew each other without root.
- Any single management device can revoke an edge holder alone.
- Edge grants are minted by management devices, not by the root key.
- Most verifiers work offline: a grant plus the log it travels with is enough to verify it.
- Root signs only: every add, dispute settlement, recovery.

## Non-goals

- A trusted clock, witnesses, or timestamped events.
- Grants on the log. Grants stay off-log signed tokens; the log holds only the management set and
  denials.
- Revoking an individual capability `jti` on the log (stays off-log via `revocation.ts`).
- ES256 / P-256 member keys. Members are Ed25519 only; a second event signature algorithm is a
  separate project.
- kubun / kumiai adoption. They get their own plans; this design defines what kokuin offers them.
- Threshold (m-of-n) root keys; the fold stays n-of-n on `k`.

## Anti-goals

- Any rule under which a log that folded can stop folding with no new event.
- Any way for a single management device to add a management key (a thief would add a sock-puppet
  and the two would renew each other forever).
- Any way for a management device to rotate, reset, touch `k`/`ka`/`n`, or renew itself.
- Routine use (two members appending while one is offline) requiring root.

## Decided rules

Decided with the user, in this form.

| Action | Who may sign | Root needed |
| --- | --- | --- |
| Add a management member (with a lease end) | root only | yes, every time |
| Renew a member's lease | root, or any member **other than** the one renewed | no |
| Remove a member | root, or any member other than the one removed | no |
| Revoke an edge holder (`rev`, target a DID or retired key) | root, or any single member | no |
| Mint an edge grant | any member (as issuer) | no |
| Settle a fork the rules below cannot | root | yes |

- **Members** are an Ed25519 `did:key`, or a long-form `did:peer:4` that carries the pinned Ed25519
  key (the same rule the `cnf` pin uses today). The add event carries the DID and the key; the fold
  refuses an add whose DID does not carry that key, or any other DID form.
- **The fold never reads the lease.** A member-signed event is valid iff its signer was a member at
  that position. The lease end is carried in the state.
- **Grants are bounded at mint.** A member-issued grant verifies only if its `exp` is no later than
  the issuer's lease end in the log the verifier holds, plus the normal `exp` check. Lapse therefore
  ends the grants by itself, and a member cannot stretch them: it cannot renew itself. Renewal does
  not revive old grants; members re-mint.
- **Short grants, long leases.** Lease (months) is how long a user can stay away before root is
  needed. Edge grant lifetime is how late an offline verifier can learn of a revoke or removal:
  default **12 hours**, configurable, enforced by the verifier as a maximum `exp - iat`. Members
  re-mint automatically. An agent that is not renewed simply lapses, with no log entry; a revoke is
  only for killing one early.
- **Removal kills the member's grants** as soon as a verifier holds the removing log; honest grants
  included, agents get new ones from another member.
- **Two members, one removed:** the survivor works until its own lease end, then needs root, either
  root renewing it or root adding a new member who renews it.
- **Accepted leak:** a thief holding a member can remove the honest peer first (single-member
  removal is decided) and then mint 12-hour grants until its own lease end, and deny edge holders.
  It cannot add, renew itself, or touch the root keys. Root restores the honest member; a cold `rot`
  with a pruned `d` undoes the denials. The bound on the leak is the lease length.
- **Capability-authorised revoke is removed** (breaking change, accepted as safer). No production
  producer exists; it is the source of the clock dependency.
- **Example flow:** desktop install creates the mnemonic; root (still in hand) publishes the
  inception and adds the desktop. Adding the phone later is one root signature. From then on,
  desktop and phone renew each other and manage edge agents without root.

## Design

### Root signature

"Root" means a signature by the current authority keys `k` (n-of-n, `verifySignatures`), on an
event that does not rotate them, so adds do not burn pre-rotation. **Constraint for consumers:** no
management device holds the seed or a current `k` private key, or root-only rules mean nothing.
(kubun's shopping-lists app holds the seed on device today; that is its migration.)

### State

`KeyState` gains the management set: each member's DID, pinned key, and lease end (unix seconds).
`icp` starts it empty; a reset discards it (new generation, root re-adds); a `rot` carries it
unchanged unless it carries a replacement snapshot (below). Invariant, like `k`: no member key is
in `k`, `ka`, or the deny set of the same state.

### Events

New event type(s), `crit: true`, so a verifier that predates this fails closed rather than skipping a
removal. Each is checked against the state before it:

- **add** — root-signed. Member not already present, key not in `k`/`ka`, not denied, DID form as
  above, lease end required.
- **renew** — root, or a member other than the renewed one. Sets a new lease end.
- **remove** — root, or a member other than the removed one.
- **member revoke** — a `rev` signed by one member. May not target a current member (its DID or key):
  members are removed through remove, so the fold can see the member rule. Existing `rev` rules (no
  denying a published `k`/`ka` key) still apply.
- **`rot`** gains an optional management-set snapshot that replaces the set, like `d` replaces the
  deny set, so root can settle a dispute in one event.

All count as understood in the skip budget. All are pure signature checks, so the **sync**
`foldLog` verifies them. With capability-authorised revokes gone, the sync and async folds accept
the same logs.

### Forks and branch selection

Two members appending at once (one offline) forks the log; so can a hostile member forking from a
position where it was still a member. Rules, applied at the divergence point within a generation,
after the existing "a `rot` signed by the pre-committed keys supersedes" rule:

1. A root-signed event beats a member-signed rival.
2. A branch that, after the divergence, **removes the member who signed the rival branch's first
   event** wins, unless the rival also removes this branch's first signer: that is a dispute,
   surfaced as duplicity for root.
3. Otherwise (no conflict), the branch whose divergence event has the lower digest wins. The losing
   branch's events are superseded; kokuin returns them so their authors re-issue them on the winner.
   Until re-issued, a revoke on the losing branch is not in effect.

Rule 2 is what contains a hostile ex-member: any fork it makes loses to the honest branch that
removes it. Consumers should also avoid forks in the first place: ingest the latest head before
appending, and re-issue their own events if they find themselves on a losing branch.

### Edge grants and offline verification

A capability with `sub` = controller DID and `iss` = a member DID is a chain root when the member is
in the management set at the head the verifier holds, and its `exp` ≤ that member's lease end.
`checkCapability` and the delegation walk gain that arm next to `iss === sub`. Same power as a
root-issued grant; it cannot confer management power, since management comes only from a root add.
The edge holder may delegate further under the existing chain rules.

A grant travels with the controller log up to at least the event that set the issuer's current
lease. A verifier folds it offline (sync, clock-free); if it holds a newer log, the existing
`history` comparison prefers that one and refuses an older presented log. What an offline verifier
cannot know is a removal or revoke after the log it was shown; a presenter can also show an older
log on purpose. Both are bounded by the grant lifetime (12 h default).

### Advisory lapse

kokuin exposes, from a folded state and a caller-supplied time, which members' leases have passed,
so consumers can warn or remove. It never makes a fold or resolution fail.

## Left to the builder

- Event type names and field spellings; one type with an op field vs several.
- How the signer is named in a member event (by DID/key in the event vs matched by signature).
- Default lease length (suggest 90 days) and where it is configured.
- Resolver method names; whether removal also writes a deny entry for the member key.
- The shape of the "superseded events to re-issue" result.
- Removal of the capability-authorised revoke surface: `FoldOptions.verifyCapability`, the
  `capability` step outcome, `createControllerCapabilityVerifier`, `createRevokeWithKey`'s `cap`,
  the `unverified` / `needs-capability-verification` plumbing in `supersede.ts` and `history.ts`.
- Conformance cases in `@kokuin/controller-conformance`, at minimum: member revoke folds with no
  clock; a lapsed-but-unremoved member's events still fold; self-renew, member add, member revoke of
  a member, and a non-Ed25519 or short-form-peer add all fail; a removed member's later events fail;
  each fork rule wins its case and the mutual-removal fork is duplicity; a root `rot` snapshot
  settles it; sync and async folds agree; a member grant with `exp` past the lease end, past the
  12 h maximum, or from a removed member fails. Mutate each rule alone.
- Docs: `docs/reference/controller.md` custody tiers, events, branch selection; and
  `docs/reference/security.md` remedy ladder. Release note for the breaking removal.
