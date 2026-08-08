# Profile DIDs with rotating keys

**Scope:** kokuin (owner), kumiai (registry transport), kubun (ownership + apply-time checks).
**Written:** 2026-08-07. **Revised:** 2026-08-08 after the design questions were resolved.
**Status:** design agreed. The kokuin half is specified in
`docs/superpowers/specs/2026-08-08-profile-did-key-events-design.md`, which is authoritative for
every kokuin detail. This document is the cross-repo picture.

One canonical, stable DID per user profile, whose key set rotates over time, held across multiple
devices that never copy key material, verifiable inside and outside MLS groups, and able to gain
post-quantum keys without changing the identifier.

## Why today's identity does not carry this

`@kokuin/token` builds `did:key` for a single classical signing key and `did:peer:4` for anything
else (`packages/token/src/identity.ts`, `chooseMethod` / `createIdentity`). Both are static: the
identifier is a hash of the key material, so a key change is a new DID. `createRotationAssertion`
(`packages/token/src/rotation.ts`) papers over this by signing an assertion linking the old
identity to the new one — a rotation chain, not a rotating identity.

That is fine while a DID names a session or a device. It fails as soon as a DID names a *user*:

- Kubun keys ownership on the DID string — `documents.owner`, `catalogs.owner_did`, the
  access-default rows, and delegation `aud` (`kubun/packages/store-graph/src/api.ts`). Rotating
  the identifier turns every rotation into a data migration, and every read-access and write check
  into a chain walk of unbounded length that must also work offline.
- Adding an ML-DSA key to a `did:peer:4` identity mints a different DID, so the post-quantum
  migration in `backlog/2026-06-30-post-quantum-algorithms.md` would break every ownership row in
  every downstream repo.

## Requirements

1. **Stable canonical DID.** One identifier per profile, unchanged for the profile's lifetime.
2. **Multiple concurrent keys.** Several devices, several purposes (`sig`, `keyAgreement`).
3. **Rotation and revocation.** Including recovery from a stolen device key.
4. **Cross-group and offline.** Verifiable in any MLS group and outside every group.
5. **Algorithm agility.** ML-DSA / ML-KEM arrive without changing the identifier.
6. **Mnemonic-rooted recovery.** A restored mnemonic reproduces the DID with no other input, and
   restores control with at most a head digest alongside it.
7. **Cold root, warm operations.** The seed is needed for rare ceremonies only. Nothing on the
   daily path requires it.

Requirements 6 and 7 were added on revision. They are what turned the original multi-key authority
tier into a single seed-rooted one.

## Methods considered

| Method | Verdict |
| --- | --- |
| `did:key`, `did:jwk` | Identifier *is* the key. Fails 1, 2, 3, 5. |
| `did:peer:4` + rotation assertion (today) | Fails 1 and 5, as above. Fine for ephemeral session identities. |
| `did:webvh` | Requires an HTTP origin; the method string embeds a domain. Its *log format* is worth copying: SCID = hash of the genesis entry, append-only signed DIDDoc versions, pre-rotation key hashes, optional witnesses. |
| `did:dht` | Mainline DHT — no blockchain and no own server, but needs public DHT reachability, caps payloads at 1 KB (ML-DSA keys do not fit), guarantees no retention, and lost its maintainer when TBD wound down. Viable only as an optional mirror. |
| `did:crdt` (arXiv 2606.16223) | Content-addressed genesis, CRDT merge, gossip discovery, no server. Closest published match to a peer-to-peer registry, but any non-revoked key may authorise any operation — no tiered authority, no pre-rotation. Research-grade. |
| **KERI / `did:keri` / `did:webs`** | Meets all five original requirements. Rejected as a *dependency* (CESR weight, thin JS, no ML-DSA path we control), adopted as the *specification to imitate*. |

Ledger-backed methods (`did:ion`, `did:ethr`, `did:cheqd`) and server-backed ones (`did:web`,
`did:plc`) are out by construction — the stack has neither.

## Design

### The correction that shaped everything else

The first draft proposed a 2-of-3 authority quorum while also deriving every authority key from one
master seed at `m/<base>/<profile>'`. Those two cannot both be true: anyone holding the seed
reconstitutes all three keys, so the quorum is a device-compromise control, not a cryptographic one,
and "losing two devices loses the profile" was never accurate — restoring the seed restores
everything.

Taking the seed seriously as the root collapses several open questions instead of answering them.
Recovery becomes "restore the mnemonic". Single-authority starter profiles stop being a special
case, because every profile is single-authority and a Ledger profile differs from an app profile
only in where the seed lives. The tier table's thresholds disappear.

### Identifier

`did:kokuin:<multibase multihash(inception)>`. Globally unique by hash, needs no registry or
namespace authority, and never changes. This is the only identity value any downstream repo stores.

No version segment: multihash self-describes its hash function, the inception format version lives
in the event, and log evolution never reaches the identifier. Not registered with DIF for now.

### Keys live in the log, not in the identifier

The DID document is a *projection* of a folded event log, not a stored artefact. Three event types
— `inception`, `rotate`, `revoke` — each carrying `gen`, `seq`, a `prev` digest, and a criticality
marker. `reset` is a `rotate` variant, not a fourth type. `interact` was dropped: nothing consumes
it, and anchoring is served by a seal field on `inception` and `rotate`.

Field names track KERI's (`i`, `s`, `p`, `k`, `n`, `kt`, `nt`, `a`) so the design stays auditable
against a published specification.

### Deterministic inception

Inception is canonical — no timestamp, no nonce, no user label — so its contents, and therefore the
DID, are a pure function of the seed and the profile index. Three properties fall out:

- The DID regenerates from the mnemonic alone.
- Profiles are enumerable by index, which is what makes an offline recovery picker possible.
- Re-derivation is idempotent, so legitimate recovery cannot be mistaken for duplicity.

Rotations are deterministic by default and stop being reproducible only when they carry a seal, a
deny-set snapshot, or a recovery-commitment update.

### Pre-rotation and superseding recovery

`inception` commits *digests* of the next keys rather than the keys. A stolen device key cannot
rotate the DID, and the next public keys are unpublished until used, so a quantum adversary has
nothing to pre-compute against.

A `rotate` signed by the pre-committed next keys outranks any operation signed by current keys, per
KERI. The fold rewinds current-key operations authored after a divergence point rather than treating
the recovery as a fork. Precedence overall is `(gen, seq)` lexicographic.

### Authority tiers

One authority key per generation. No quorum and no thresholds.

| Tier | Custody | May do |
| --- | --- | --- |
| Root seed | Ledger, or cold mnemonic | Rotate, reset, clear the deny set, mint the management capability |
| Management capability | Primary device, hot, long-lived | Mint and renew device and connector capabilities; author `revoke` |
| Device capability | Per device, lifetime in days | Sign documents |

The management capability replaces the earlier scoped renewal capability, which existed only because
authority was assumed unreachable. It holds **no key-event authority beyond `revoke`**: it cannot
rotate, cannot reset, and cannot touch the key set — which preserves the pre-rotation guarantee that
handing a device the profile sub-seed would have voided.

`revoke` is the deliberate exception, on the design's own reasoning that revocation is the fail-safe
direction. Requiring the Ledger to revoke a stolen phone is a compromise you cannot undo without the
hardware in hand, at the moment speed matters most.

### Revocation on the log

`revoke` adds a DID to a **deny set**: no capability whose `aud` is that DID is valid from that
position onward. It names the device DID rather than a capability `jti`, so it is one entry per
device for that device's life and it covers capabilities the verifier has never seen.

This narrows the design's weakest cost. Capability revocation propagation is best-effort — kubun's
`kubun_revoked_capabilities` table, per-author rows keyed `(jti, revoker_did)`, LWW within one
author, plus a broadcast — which is why short expiry was the only real guarantee. A deny set on the
key log is covered by the group head, replays at welcome, and verifies offline as part of key state.
The accepted-loss window shrinks to propagation delay for online verifiers and remains bounded by
expiry only for those that have not heard.

The deny set is position-dependent state: clearing a DID at a later position does not retroactively
validate its earlier actions. The hot key may add; only cold key-event authority may clear.

### Devices hold capabilities, not document entries

Device keys stay out of the profile DID document. `@kokuin/capability` is already the primitive:
`sub` = profile DID, `aud` = device DID, and chain validation enforces that `iss` is the parent's
`aud` and that `sub` matches (`packages/capability/src/index.ts:196-220`). Kubun already verifies
this shape on `mutation.cap`.

Onboarding a device: the device generates its own key, sends its DID over QR / hub tunnel / the
group, and the management capability holder mints a `document/write` capability for it. No key
material moves, no rotation event, no group commit, no flag day.

**Two distinct flows, deliberately not merged.** Device onboarding is the routine path and needs no
seed: the new app shows its `did:key` as a QR, the existing app mints and returns a capability, and
nothing secret travels in either direction. Mnemonic entry is *recovery*, for when no working device
remains. Putting mnemonic entry on the onboarding path would make every app a seed holder, which is
what the single-holder rule exists to prevent.

Device capabilities must **mandate** `exp` at the mint and verify policy layer — `exp` is optional
in `@kokuin/capability` and enforced only when present (`index.ts:300`), so the schema will not do
it. Lifetimes on the order of days, renewed by the management capability while the device is in good
standing. A device that fails to renew must surface a visible expired state and a one-step renewal,
not a mystery sync failure.

Delegation depth is capped at 4 — three links (management → device → connector) plus headroom, down
from `DEFAULT_MAX_DELEGATION_DEPTH` of 20.

### Profiles

A profile is a persona the user chooses: personal, professional, per-group if they want it. Each is
its own `inception` event and its own DID.

Keys are HD-derived hardened from a master seed. The recovery key sits on a **root-retained branch**,
outside the delegable profile subtree, so hardened derivation alone guarantees that a sub-seed holder
cannot reach it — the root always retains the one key that can supersede. One Ledger holds authority
for every profile, with no key copying and no shared key material appearing in any published
document, so profiles stay mutually unlinkable to observers.

App-generated profiles use the same shape with the seed in the platform keystore. The upgrade path
to hardware is a rotation event: same DID, same ownership rows, no migration.

**A device must generate one key per profile**, never one reused across profiles. Reuse makes
personal and professional trivially linkable to any group that sees both, and blocks removing a
device from one profile while keeping it in another.

### Recovery

Two guarantees with different requirements, previously blurred:

- **Control recovery** — can this profile keep signing and rotating? Mnemonic, plus a head digest
  and `seq` where the log holds non-reproducible events. Survives total device loss, because the
  recovery-key commitment lives in the deterministic inception and the root can always author a
  superseding `reset` with no log at all.
- **Provability recovery** — can it prove its key history to a stranger, offline? Needs the full
  log. Does not survive total device loss unless the log was independently retained.

Retrieval is not a recovery path. Ledger entries are sealed under `kumiai/ledger-entries/v1` and MLS
leaves are per-device, so a user who lost every device holds no leaf and may retrieve nothing —
recovery-by-retrieval needs exactly the authenticated channel that device loss destroys.

### What names what

- Kubun `documents.owner` is the **profile** DID. Never a device. It survives device churn, device
  loss, and authority rotation.
- An MLS leaf credential is a **device**. MLS binds one signature key and one HPKE key per leaf and
  this design forbids copying key material, so leaves are per-device by construction. Device DIDs
  stay `did:key` / `did:peer:4` — self-contained, preserving the invariant recorded at
  `kumiai/packages/mls/src/credential.ts` that no DID cache is needed because every reachable
  document already sits inside a signed artifact. A profile DID's document is a fold of a log and has
  no self-contained form, so a leaf naming one would force exactly that cache.
- Kumiai's **roster keys profile DIDs**. `RosterState` is already DID-keyed rather than leaf-keyed
  (`packages/mls/src/roster.ts:19`), so its shape does not change. Today's device-keyed roles are a
  wart independent of profiles: grant yourself admin on your phone and your laptop is not admin.
- `rosterDIDs` continues to yield device DIDs; profile membership is a projection.

## Landing it on each repo

### kokuin

Specified in full at `docs/superpowers/specs/2026-08-08-profile-did-key-events-design.md`. Summary:

- **`@kokuin/controller`** (new) — derivation, event schema, self-addressing digest, fold, key state
  at position, duplicity detection, handle derivation, profile enumeration. Named for DID Core's
  term for the entity that may change a DID document.
- **`@kokuin/controller-conformance`** (new, private) — framework-agnostic contract suite, following
  the `@kokuin/keystore-conformance` habit.
- **`@kokuin/token`** — resolve `iss` through an injected `DIDMethodResolver` rather than the
  embedded document; built-in methods behind subpath exports; keep `embedLongForm` for genesis
  bootstrap; deprecate `rotation.ts`. Add ML-DSA to `SUPPORTED_ALGORITHMS`
  (`packages/token/src/schemas.ts:4`) per RFC 9964, optionally PQ/T composite once
  `draft-ietf-jose-pq-composite-sigs` settles.
- **`@kokuin/jwe`** (new) — split out of token, its sole `@noble/ciphers` consumer.
- **`@kokuin/capability`** — depth cap lowered; device capabilities mandate `exp`.

The resolver interface is not optional: `@kokuin/controller` depends on `@kokuin/token` for signing,
so token importing the fold would be a cycle.

Shipping the controller package and the `iss` change makes rotation work proof-carrying, with no
group involved.

### kumiai

The control ledger is already key-event-log shaped: signed kokuin tokens with content-addressed
digests (`packages/mls/src/ledger.ts`), a running head authenticated in GroupContext
(`packages/mls/src/head.ts`, extension `0xf101`), pluggable reducers whose authority is evaluated
against state-so-far rather than final state (`packages/mls/src/fold.ts`) — exactly the rule rotation
needs. Late joiners receive the full entry set at welcome, verified against the authenticated head,
so recovery does not depend on hub retention.

Two structural constraints:

- `foldEnvelope` requires every entry to be admin-authored in state-so-far
  (`packages/mls/src/envelope-fold.ts:61`), so a plain member cannot publish its own rotation.
  Addressed by a deliberate policy relaxation — see below.
- Entries are group-scoped; a cross-group entry is rejected as a replay (`envelope-fold.ts:56`).
  Dissolved by nesting.

So the outer ledger entry is group-scoped and notarises *ordering and inclusion only*; its `value`
carries a group-independent, self-authorising inner key event signed by the subject's own
pre-committed key. The admin cannot forge the inner event, and cannot remove one *after inclusion*
without the head diverging; the same inner bytes replay into every group unchanged.

What the head does **not** prevent is pre-inclusion censorship: an admin can simply never include a
member's rotation entry, and no head diverges over an entry that never existed. A group where the
thief *is* the admin would never learn the revocation at all.

**Rotation entries are member-publishable.** `foldEnvelope`'s admin-only invariant is relaxed for
exactly one predicate: a non-admin-authored entry is admitted iff its type is in the rotation
application namespace *and* the inner event's subject DID matches the authoring member. That removes
the admin from the rotation path structurally. Costs, borne knowingly:

- **A policy change with a flag day.** Every peer must ship the relaxed fold before the first
  member-authored entry appears, or that entry fails the commit closed. It needs a version gate:
  peers advertise support, and the entry type is only used once the group's policy floor includes it.
- **Member writes need bounding.** Per-member rate and size limits on the relaxed types, so the rule
  is not a spam channel into the replayed-at-welcome ledger.

The device→profile binding entry rides the *same* predicate and therefore the same flag day — one
policy version gate covering an application namespace, not two.

Verifiers should treat the highest inner `(gen, seq)` seen for a DID *anywhere* — any group, any
direct presentation — as a monotonic floor: cheap, covers groups a rotation has not reached, and is
the comparison that makes cross-group duplicity detectable.

Use an application-namespace entry type, not `kumiai.*` — an unknown `kumiai.*` type fails the whole
commit closed. Do not plan on GroupContext extension `0xf102` either: populating it is a policy
change every peer must ship first (`packages/mls/src/policy.ts:99-118` admits only zero-length data).

**Genesis changes.** `roleReducer.seed` makes `anchor.creatorDID` the epoch-0 admin. Under
profile-keyed roles that must be the creator's *profile* DID — but then the creator's own device has
no folded binding and cannot author the first entry. The anchor must seed both maps: creator profile
DID as admin, creator device DID bound to it. That is a breaking change to group creation.

**The projection lands in two places**, not one: `roleReducer.verifyAuthority` (`roster.ts:48`) and
the universal admin invariant (`envelope-fold.ts:61`) both do `roles.get(issuer)` with `issuer` a
device DID, which under profile-keyed roles never matches.

Tracked in `kumiai/docs/agents/plans/backlog/2026-08-07-did-registry-ledger-entries.md`.

### kubun

- `documents.owner` unchanged in shape, now always a profile DID. No migration on rotation.
- New resolver interface: **key state of a DID at a position**, replacing "keys from `iss`". The
  local cache needs invalidation on supersession, not append-only updates, because a superseding
  `rotate` retroactively invalidates cached state.
- **The position must not be the HLC.** The HLC is author-supplied and attacker-controllable; a
  thief backdates and its mutations stay valid. Anchor the cut-off to the group's epoch / ledger
  position. Kubun already has this instinct — the `removed_at_hlc` membership check and the
  `cap.iat` backdate floor exist for exactly this hole.
- **"The group's position" is ambiguous for documents that sync across groups.** A mutation on a
  document reachable from several groups has several candidate ledger positions, and cross-group
  duplicity means they can disagree. Which group anchors the cut-off — arrival group, home group, or
  newest state seen anywhere — must be pinned down explicitly.
- Device writes become the normal path rather than the delegated-write special case: with `owner` a
  profile DID and the signer a device DID, owner-self never matches.
- Delegation `aud` naming a DID survives grantee rotation, which today it silently would not.
- The deny set gives an authoritative revocation source alongside `kubun_revoked_capabilities`.

Tracked in `kubun/docs/agents/plans/backlog/2026-08-07-profile-did-ownership.md`.

## Costs and constraints

- **A stolen mnemonic is terminal.** The thief holds every key at every index, including the
  recovery key, and can always rotate ahead of the owner. This is the price of seed-rooting and
  replaces the earlier, weaker claim that losing two of three devices loses the profile.
- **Post-quantum token size.** ML-DSA-65 signatures are ~3.3 KB, taking tokens from ~200 bytes to
  ~7 KB (`backlog/2026-06-30-post-quantum-algorithms.md`). Every ledger entry is a signed token, so
  this hits the kumiai welcome transfer, the `did:peer:4` document-size guards
  (`packages/token/src/peer4.ts`), and hub retention at once. A first-order constraint: it argues for
  rare rotation events, a checkpoint story, and keeping device onboarding on the capability path
  where it produces no ledger entry at all.
- **Ledger growth.** Every rotation is permanent, replayed at every welcome, and covered by the head.
  There is no compaction path today.
- **Retention.** Kumiai members request 28 days on both the commit and app logs. Past that window an
  absent member rebuilds from a peer, not the hub.
- **The registry dies with the group.** Verification must never depend on it: a self-certifying
  identifier plus a self-authorising inner chain keeps the DID valid afterwards. Kumiai is one
  witness, not the authority.
- **Log backup is narrowed, not eliminated.** Deterministic inception means losing the log never
  loses the DID, and a profile whose events are all reproducible needs no backup at all. A profile
  that has performed a non-reproducible rotation needs its head digest — 32 bytes — alongside the
  mnemonic.
- **No outside resolution.** Ledger entries are sealed under `kumiai/ledger-entries/v1`; non-members
  read nothing. External verification stays proof-carrying, as `embedLongForm` already is.
- **Cross-group duplicity is unsolved.** Kumiai orders per group only, so a controller can present
  divergent chains to disjoint groups. Nesting makes it detectable but does not prevent it. Detection
  needs a member of both groups, an external witness, or a public mirror.
- **Unanchored capabilities remain backdatable.** `cap.iat` is author-supplied. Sealing closes it for
  anchored grants; for the rest the exposure is bounded by the accepted-loss window.
- **Rolling our own key management is the classic footgun.** Mitigated by copying KERI semantics
  field-for-field rather than inventing, and by justifying each delta explicitly: JSON/JOSE instead
  of CESR, MLS groups plus proof-carrying verification instead of a witness network, and a deny set
  instead of a separate revocation registry.

## Resolved

Recorded here so the reasoning is not re-litigated. Full arguments in the spec.

- **Recovery when the quorum is lost** — dissolved. There is no quorum; the seed is the root and the
  mnemonic is the recovery path.
- **Single-authority starter profiles** — dissolved. Every profile is single-authority.
- **Roster identity** — leaves name devices, roster keys profiles, the projection lives at the two
  authority checks.
- **Profile granularity** — default to coarse personas; support per-group profiles; surface the
  unlinkability-versus-sharing trade-off in the UI rather than burying it. Ceremony cost scales as
  profiles × devices, which pushes users toward coarse personas regardless of framing.
- **Chain depth** — 4.
- **Method name and registration** — `did:kokuin:`, no DIF registration for now.

## Open questions

- **Implicit delegation, total or capped.** A device inherits its profile's role through membership,
  so a stolen device of an admin *is* an admin in that group — it can manipulate the roster, not just
  write documents. A ceiling field in the binding entry (effective role = `min(profile role,
  ceiling)`) would allow a phone bound as `member` while the laptop is `admin`. Owned by the kumiai
  brainstorming.
- **Which group anchors the cut-off position** for documents reachable from several groups. Owned by
  kubun.
- **Adopted profiles.** A device could operate under its own `did:kokuin:` profile before onboarding
  and later adopt an HD-derived authority key by a co-signed `rotate`, keeping the same DID and
  needing no migration. Such a profile sits at no derivation path, so it is invisible to the offline
  picker and outside the pure-mnemonic guarantee. The co-signature-gated recovery field on `rotate`
  is retained so this stays possible without a format break; nothing implements it.
- **Checkpointing or compaction** for the ledger, once post-quantum entry sizes land.

## References

- KERI: <https://arxiv.org/pdf/1907.02143>, Q&A <https://identity.foundation/keri/docs/Q-and-A.html>
- `did:keri`: <https://github.com/WebOfTrust/did-keri>
- `did:webvh` v1.0: <https://identity.foundation/didwebvh/v1.0/>
- Peer DID method: <https://identity.foundation/peer-did-method-spec/>
- DIDComm v2 DID rotation: <https://didcomm.org/book/v2/didrotation/>
- `did:dht`: <https://did-dht.com/>
- `did:crdt`: <https://arxiv.org/html/2606.16223>
- RFC 9420 (MLS): <https://www.rfc-editor.org/rfc/rfc9420.pdf>
- RFC 9964 (ML-DSA for JOSE and COSE): <https://www.rfc-editor.org/info/rfc9964/>
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) — seed-based key generation, which is what makes
  post-quantum keys HD-derivable
- PQ/T hybrid composite signatures: <https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/>
- IETF Key Transparency architecture: <https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/>

## Related

- `docs/superpowers/specs/2026-08-08-profile-did-key-events-design.md` — the resolved kokuin design.
- `backlog/2026-06-30-post-quantum-algorithms.md` — the algorithm work this design depends on.
- `backlog/2026-06-30-ledger-root-identity.md` — multi-Ledger support, needed for one device to
  hold authority across several profiles.
- kumiai `backlog/2026-08-07-did-registry-ledger-entries.md`
- kubun `backlog/2026-08-07-profile-did-ownership.md`
