# Profile DIDs with rotating keys

**Scope:** kokuin (owner), kumiai (registry transport), kubun (ownership + apply-time checks).
**Written:** 2026-08-07. Design only — no implementation plan yet.

A design for one canonical, stable DID per user profile, whose key set rotates over time, held
across multiple devices that never copy key material, verifiable inside and outside MLS groups,
and able to gain post-quantum keys without changing the identifier.

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

## Methods considered

| Method | Verdict |
| --- | --- |
| `did:key`, `did:jwk` | Identifier *is* the key. Fails 1, 2, 3, 5. |
| `did:peer:4` + rotation assertion (today) | Fails 1 and 5, as above. Fine for ephemeral session identities. |
| `did:webvh` | Requires an HTTP origin; the method string embeds a domain. Its *log format* is worth copying: SCID = hash of the genesis entry, append-only signed DIDDoc versions, pre-rotation key hashes, optional witnesses. |
| `did:dht` | Mainline DHT — no blockchain and no own server, but needs public DHT reachability, caps payloads at 1 KB (ML-DSA keys do not fit), guarantees no retention, and lost its maintainer when TBD wound down. Viable only as an optional mirror. |
| `did:crdt` (arXiv 2606.16223) | Content-addressed genesis, CRDT merge, gossip discovery, no server. Closest published match to a peer-to-peer registry, but any non-revoked key may authorise any operation — no tiered authority, no pre-rotation. Research-grade. |
| **KERI / `did:keri` / `did:webs`** | Meets all five. Rejected as a *dependency* (CESR weight, thin JS, no ML-DSA path we control), adopted as the *specification to imitate*. |

Ledger-backed methods (`did:ion`, `did:ethr`, `did:cheqd`) and server-backed ones (`did:web`,
`did:plc`) are out by construction — the stack has neither.

## Design

### Identifier

`did:<method>:<multibase multihash(genesis event)>`. Globally unique by hash, needs no registry or
namespace authority, and never changes. This is the only identity value any downstream repo stores.

### Keys live in the log, not in the identifier

The DID document is a *projection* of a folded event log, not a stored artefact. The existing
multi-key document builder (`identity.ts`, `buildDoc`) already produces the shape; it just stops
being the thing that determines the identifier.

Events, each carrying `seq` and a `prev` digest, signed by keys authorised in the prior event:

- `inception` — initial key set, `nextKeyDigests`, signing threshold, rotation threshold.
- `rotate` — new key set, new `nextKeyDigests`.
- `interact` — anchors an external digest (useful for pinning a capability grant to a position).

Field names should track KERI's (`i`, `s`, `p`, `k`, `n`, `kt`, `nt`) so the design stays auditable
against a published specification and mappable to `did:keri` later.

### Pre-rotation

`inception` commits *digests* of the next keys rather than the keys. Two consequences:

- A stolen device key cannot rotate the DID. It can sign as itself until revoked, nothing more.
- The next public keys are not published until used, so a quantum adversary has nothing to
  pre-compute against. This is post-quantum hedging that costs nothing and does not wait on ML-DSA.

### Tiered authority

Rotation authority is **not** "any key in the document". If any device key could rotate the whole
set, one stolen phone is a full profile takeover and pre-rotation buys nothing — the thief holds a
rotation-authorised key. That is the weakness `did:crdt` concedes in its own paper.

| Tier | Held by | May do | Add threshold | Revoke threshold |
| --- | --- | --- | --- | --- |
| Authority keys | Ledger device, offline backup, recovery share | Rotate the key set, add authority | **quorum** (2-of-3) | any 1, superseded by next-key `rotate` |
| Device keys | Generated on-device, never leave it | Sign documents, request renewal | one authority key | any 1 authority key |
| Capabilities | Minted per device / connector | Scoped writes | one authority key to mint | any 1 authority key |

**The thresholds are deliberately asymmetric: adding authority needs a quorum, revoking needs one
key.** Revocation is the fail-safe direction — the same reasoning behind kumiai's earliest-wins
removal tombstone. Requiring a quorum to revoke means a compromise you cannot undo without two
devices in hand.

That asymmetry is correct for device keys and capabilities, but it **must not extend to the
authority tier unguarded**: if one authority key could revoke another with finality, a thief
holding one stolen authority key could not add keys but *could* revoke the other two, making the
quorum permanently unreachable — a takeover-grade denial of service, or at best a race between
the thief and the owner over who revokes whom first.

**Decision: superseding recovery, per KERI.** A `rotate` signed by the pre-committed **next** keys
outranks any operation signed by current keys. If a thief revokes the other authority keys, the
owner rotates to the next key set; the thief's revocations are superseded and discarded, and the
new set excludes the stolen key — the owner wins the race regardless of order. Revocation stays
1-key and fast as the everyday fail-safe; supersession is the backstop. Two consequences: the
verifier's fold needs precedence logic (a superseding `rotate` rewinds operations authored by
current keys after the divergence point), and next-key custody becomes the profile's real root of
trust — the pre-committed digests must be derived and stored with at least the care of the
authority keys themselves.

### Devices hold capabilities, not document entries

Device keys stay out of the profile DID document. `@kokuin/capability` is already the primitive:
`sub` = profile DID, `aud` = device DID, and chain validation enforces that `iss` is the parent's
`aud` and that `sub` matches (`packages/capability/src/index.ts:196-220`). Kubun already verifies
this shape on `mutation.cap`.

Onboarding a device: the device generates its own key, sends its DID over QR / hub tunnel / the
group, and a device holding an authority key mints a `document/write` capability for it. No key
material moves, no rotation event, no group commit, no flag day.

For a *stolen* device, short expiry beats revocation. Capability revocation propagation is
best-effort (kubun's `kubun_revoked_capabilities` table plus a broadcast — per-author rows keyed
`(jti, revoker_did)`, LWW only within one author, so a third party cannot un-revoke); an unrenewed
expiry is unconditional. Device capabilities should carry lifetimes on the order of days, renewed
by an authority key while the device is in good standing. Revocation stays the fast path; expiry
is the guarantee.

Two consequences of "expiry is the guarantee":

- **The expiry length *is* the accepted-loss window.** An offline verifier with a stale ledger
  keeps accepting a stolen device's signatures until the capability expires — revocation never
  reaches it. Pick the lifetime by deciding how many days of a thief writing as the victim is
  acceptable, not by renewal convenience. This argues for days, not weeks.
- **`exp` is optional in `@kokuin/capability`** (`packages/capability/src/index.ts:68`; enforced
  only when present, `assertNonExpired`). Device capabilities must *mandate* expiry at the mint
  and verify policy layer — the schema will not do it for us.

Renewal cannot come from the authority keys directly — they live on a Ledger, an offline backup,
or a recovery share, none of which is silently reachable every few days. **Decision: a scoped
renewal capability.** One daily device holds a medium-lived capability (order of 30–90 days)
scoped to *renewing existing device capabilities only* — it cannot mint capabilities for new
devices and cannot author key events. It renews the short-lived device capabilities silently; its
own renewal is the periodic hardware ceremony, and minting a new device stays an authority-key
act. Compromise of the renewing device extends the thief's existing window by at most the scope
lifetime but grants no new authority; revocation plus, at worst, a superseding rotate ends it.
This is a hot key one level down, deliberately: scoped, expiring, and outside the key log.

A device that fails to renew must also *surface* it: a device offline for a few weeks silently
loses write access, which needs a visible expired state and a one-step renewal, not a mystery
sync failure.

The pay-off is that rotation events become rare — authority key changes, post-quantum migration,
recovery — which is what keeps the kumiai control ledger from growing without bound.

### Profiles

A profile is a persona the user chooses: personal, professional, per-group if they want it. Each is
its own `inception` event and its own DID.

Authority keys are HD-derived hardened from a master seed, `m/<base>/<profile>'`.
`@kokuin/deterministic` already refuses non-hardened paths
(`packages/deterministic/src/derivation.ts:12-25`), and `@kokuin/ledger-device` derives per path
over APDU (`GET_PUBLIC_KEY` plus chunked signing, `packages/ledger-device/src/provider.ts`). So one
Ledger holds authority for every profile, with no key copying and no shared key material appearing
in any published document — profiles stay mutually unlinkable to observers.

App-generated profiles use the same shape with the authority key in the platform keystore. The
upgrade path to hardware is a rotation event: same DID, same ownership rows, no migration.

**A device must generate one key per profile, not one key reused across profiles.** Reuse makes
personal and professional trivially linkable to any group that sees both, and blocks removing a
device from one profile while keeping it in another.

### What names what

- Kubun `documents.owner` is the **profile** DID. Never a device. It survives device churn, device
  loss, and authority rotation.
- An MLS leaf credential is a **device**, because leaves are per-device. `rosterDIDs` therefore
  yields device DIDs, and profile membership is a projection over the capability.
- This distinction must be made once and explicitly. Kumiai's roster, kubun's delegation `aud`, and
  the access checks all currently say "a DID" without saying which kind, and that ambiguity is
  where the bugs will be.

## Landing it on each repo

### kokuin

- New key-event module (its own package, or inside `@kokuin/token`): event schema, self-addressing
  digest, fold, key-state-at-position, duplicity detection. It owes a conformance suite, following
  the `@kokuin/keystore-conformance` habit.
- `@kokuin/token`: resolve `iss` through key state rather than the embedded document. Keep
  `embedLongForm` for genesis bootstrap. Add ML-DSA to `SUPPORTED_ALGORITHMS`
  (`packages/token/src/schemas.ts:4`) per RFC 9964, optionally PQ/T composite once
  `draft-ietf-jose-pq-composite-sigs` settles.

Shipping just these two makes rotation work proof-carrying, with no group involved.

### kumiai

The control ledger is already key-event-log shaped: signed kokuin tokens with content-addressed
digests (`packages/mls/src/ledger.ts`), a running head authenticated in GroupContext
(`packages/mls/src/head.ts`, extension `0xf101`), pluggable reducers whose authority is evaluated
against state-so-far rather than final state (`packages/mls/src/fold.ts`) — which is exactly the
rule rotation needs. Late joiners receive the full entry set at welcome, verified against the
authenticated head, so recovery does not depend on hub retention.

Two structural constraints:

- `foldEnvelope` requires every entry to be admin-authored in state-so-far
  (`packages/mls/src/envelope-fold.ts:61`), so a plain member cannot publish its own rotation.
  Addressed by a deliberate policy relaxation — see the member-publishable decision below.
- Entries are group-scoped; a cross-group entry is rejected as a replay (`envelope-fold.ts:56`).
  Dissolved by nesting.

So the outer ledger entry is group-scoped and notarises *ordering and inclusion
only*; its `value` carries a group-independent, self-authorising inner key event signed by the
subject's own pre-committed key. The admin cannot forge the inner event, and cannot remove one
*after inclusion* without the head diverging; the same inner bytes replay into every group
unchanged.

What the head does **not** prevent is pre-inclusion censorship: an admin can simply never include
a member's rotation entry, and no head diverges because the entry never existed. Rotation liveness
in each group would then depend on that group's admin — and a group where the thief *is* the admin
would never learn the revocation at all.

**Decision: rotation entries are member-publishable.** `foldEnvelope`'s admin-only invariant is
relaxed for exactly one case: a non-admin-authored entry is admitted iff its type is the rotation
application namespace *and* the inner event's subject DID matches the authoring member. That
removes the admin from the rotation path structurally — a member can always publish its own
rotation into every group it belongs to, including one where the thief holds admin. Costs, borne
knowingly:

- **This is a policy change with a flag day.** Every peer must ship the relaxed fold before the
  first member-authored entry appears, or that entry fails the commit closed — the same mechanism
  that rules out extension `0xf102`. It needs a version gate: peers advertise support, and the
  entry type is only used once the group's policy floor includes it.
- **Member writes need bounding.** Rotation entries are rare by design; enforce that — per-member
  rate and size limits on the rotation type, so the relaxed authorship rule is not a spam channel
  into the replayed-at-welcome ledger.

Verifiers should still treat the highest inner `seq` seen for a DID *anywhere* — any group, any
direct presentation — as a monotonic floor: it is cheap, covers groups the rotation has not
reached yet, and is the comparison that makes cross-group duplicity detectable.

Use an application-namespace entry type, not `kumiai.*` — an unknown `kumiai.*` type fails the whole
commit closed, so adding one is a flag day. Do not plan on GroupContext extension `0xf102` either:
populating it is a policy change every peer must ship first
(`packages/mls/src/policy.ts:99-118` admits only zero-length data). The relaxed authorship rule
above is the one policy flag day this design accepts; keep it the only one.

### kubun

- `documents.owner` unchanged in shape, now always a profile DID. No migration on rotation.
- New resolver interface: **key state of a DID at a position**, replacing "keys from `iss`".
- **The position must not be the HLC.** The HLC is author-supplied and attacker-controllable; a
  thief backdates and its mutations stay valid. Anchor the cut-off to the group's epoch / ledger
  position. Kubun already has this instinct — the `removed_at_hlc` membership check and the
  `cap.iat` backdate floor exist for exactly this hole.
- **"The group's position" is ambiguous for documents that sync across groups.** A mutation on a
  document reachable from several groups has several candidate ledger positions, and cross-group
  duplicity means they can disagree about key state. Which group anchors the cut-off — the group
  the mutation arrived through, the document's home group, or the newest state seen anywhere —
  must be pinned down explicitly.
- Delegation `aud` naming a DID survives grantee rotation, which today it silently would not.

## Costs and constraints

- **Post-quantum token size.** ML-DSA-65 signatures are ~3.3 KB, taking tokens from ~200 bytes to
  ~7 KB (`backlog/2026-06-30-post-quantum-algorithms.md`). Every ledger entry is a signed token, so
  this hits the kumiai welcome transfer, the `did:peer:4` document-size guards
  (`packages/token/src/peer4.ts`), and hub retention at once. It is a first-order constraint on the
  design, not a footnote: it argues for rare rotation events, a checkpoint story, and keeping device
  onboarding on the capability path where it produces no ledger entry at all.
- **Ledger growth.** Every rotation is permanent, replayed at every welcome, and covered by the
  head. There is no compaction path today.
- **Retention.** Kumiai members request 28 days on both the commit and app logs, aligned by choice.
  Past that window an absent member rebuilds from a peer, not the hub.
- **The registry dies with the group.** Verification must never depend on it: a self-certifying
  identifier plus a self-authorising inner chain keeps the DID valid afterwards. Kumiai is one
  witness, not the authority.
- **The event log itself needs a backup story.** The DID is the hash of the genesis event and
  verification requires the full log; losing the log does not lose *control* (the keys still
  sign), but it loses *provability*. With 28-day hub retention and no surviving peer, the chain is
  gone. The controller must durably retain its own log, and that retention is currently
  undesigned.
- **No outside resolution.** Ledger entries are sealed under `kumiai/ledger-entries/v1`; non-members
  read nothing. External verification stays proof-carrying, as `embedLongForm` already is.
- **Cross-group duplicity is unsolved.** Kumiai orders per group only, so a controller can present
  divergent chains to disjoint groups. Nesting makes it detectable (inner event ids are comparable
  across groups) but does not prevent it. Detection needs a member of both groups, an external
  witness, or a public mirror.
- **Rolling our own key management is the classic footgun.** Mitigate by copying KERI semantics
  field-for-field rather than inventing, and by justifying the deltas explicitly: JSON/JOSE instead
  of CESR, and MLS groups plus proof-carrying verification instead of a witness network.

## Open questions

- **Single-authority starter profiles.** An app-keystore profile begins with one authority key on
  a daily device — a quorum of 1 is not the model the tier table describes. What thresholds,
  next-key custody, and recovery mean before the hardware upgrade needs its own statement; the
  scoped renewal capability does not resolve it.
- **Recovery when the quorum is lost.** 2-of-3 means losing two devices loses the profile. Needs a
  designed answer — social recovery shares, or a sealed offline share — before anything ships. The
  inverse journey also needs walking end-to-end: after a stolen phone, the user must locate two
  authority keys, then revoke and rotate per profile, per group, gated on each group's admin.
- **Roster identity.** Whether kumiai's roster and kubun's delegation `aud` name device DIDs,
  profile DIDs, or both, and where the projection between them lives.
- **Profile granularity is the privacy dial.** Per-group profiles maximise unlinkability but
  fragment ownership: documents cannot cross profiles without an explicit re-grant and re-owning.
  Coarse personas keep sharing workable. Ceremony cost also scales as profiles × devices — every
  profile-device pair is a separate capability to mint and renew — which pushes users toward
  coarse personas regardless of UI framing. The trade-off should surface in the UI, not be buried.
- **Chain depth.** `DEFAULT_MAX_DELEGATION_DEPTH` is 20 and every offline verifier walks it. Profiles
  want a much lower cap — authority to device to connector is two links.
- **Method name and registration**, and whether to pursue a DIF specification or stay private.

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
- PQ/T hybrid composite signatures: <https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/>
- IETF Key Transparency architecture: <https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/>

## Related

- `backlog/2026-06-30-post-quantum-algorithms.md` — the algorithm work this design depends on.
- `backlog/2026-06-30-ledger-root-identity.md` — multi-Ledger support, needed for one device to
  hold authority across several profiles.
- kumiai `backlog/2026-08-07-did-registry-ledger-entries.md`
- kubun `backlog/2026-08-07-profile-did-ownership.md`
