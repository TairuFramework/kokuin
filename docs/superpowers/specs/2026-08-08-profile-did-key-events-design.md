# Profile DIDs with rotating keys — resolved design

**Status:** design agreed, not yet planned.
**Scope of this document:** kokuin only. It closes the open questions left by
`docs/agents/plans/milestones/2026-08-07-profile-did-key-events.md` and supersedes that
document wherever the two disagree.
**Out of scope:** kumiai and kubun implementation, which keep their own backlog items.

## What changed from the milestone

The milestone proposed a KERI-shaped key event log with a 2-of-3 authority quorum, a scoped
renewal capability, and an undesigned recovery story. Working through the questions it left
open produced a different and simpler shape, because one observation invalidated the tier
table: the milestone derives authority keys from a single master seed at `m/<base>/<profile>'`,
so a threshold over those keys is not a cryptographic control. Anyone holding the seed
reconstitutes all of them.

Taking the seed seriously as the root of trust collapses most of the open questions rather than
answering them. The quorum becomes a device-compromise control, "recovery when the quorum is
lost" becomes "restore the seed", and "single-authority starter profiles" stops being a special
case because every profile is single-authority.

## Requirements

Unchanged from the milestone:

1. **Stable canonical DID.** One identifier per profile, unchanged for the profile's lifetime.
2. **Multiple concurrent keys.** Several devices, several purposes (`sig`, `keyAgreement`).
3. **Rotation and revocation**, including recovery from a stolen device key.
4. **Cross-group and offline** verifiability.
5. **Algorithm agility.** ML-DSA / ML-KEM arrive without changing the identifier.

Added by this design:

6. **Mnemonic-rooted recovery.** A restored mnemonic reproduces the DID with no other input, and
   restores control with at most a head digest alongside it.
7. **Cold root, warm operations.** The seed is needed for rare ceremonies only. Nothing on the
   daily path requires it.

## Identifier

```
did:kokuin:<multibase multihash(inception)>
```

Self-certifying, needs no registry or namespace authority, never changes. This is the only
identity value any downstream repo stores.

Not registered with the DIF DID method registry for now. Revisit once the event format has
stabilised; nothing in the design depends on registration.

### No version segment

The string carries no version. It does not need one, and the string is the one thing that can never
change, so it should carry as little as possible.

- **Hash agility is already covered.** Multihash self-describes its hash function.
- **The inception format version lives in the event**, as `v`. Self-addressing makes that safe from
  confusion: a forged event claiming a later version would have to hash to a DID minted under the
  earlier rules, which is a collision the hash prevents.
- **A future construction coexists rather than migrating.** Profiles minted under v1 keep resolving
  under v1 rules forever; a v2 construction produces new DIDs for new profiles.
- **Log evolution never reaches the identifier.** New event types, deny sets, and algorithm changes
  are verified after resolution and folding. None of them can move `hash(inception)`.

A version segment would only buy dispatch before fetching, and there is nothing to dispatch — a
resolver fetches the log either way.

The HKDF `info` string is `did:kokuin/v1`, a protocol identifier deliberately independent of package
naming. Because the DID is a function of derived keys, that string can never change once a profile
exists, so it must not track anything as mutable as a package name.

## Derivation

`@kokuin/deterministic` is SLIP-0010 ed25519 and rejects non-hardened segments outright
(`packages/deterministic/src/derivation.ts:12-25`), so every segment below is hardened. Base path
is the existing `44'/876'`.

```
delegable:  m/44'/876'/0'/<profile>'/<role>'/<gen>'/<seq>'
            role 0' = authority, role 1' = keyAgreement

root-only:  m/44'/876'/1'/<profile>'
            recovery key

key_seed = HKDF-SHA256(ikm, info = "did:kokuin/v1|<alg>", L = <alg seed length>)
```

Two properties this layout exists to guarantee, neither of which can be retrofitted because the
DID is a function of the paths:

**The recovery key is unreachable from the delegable branch.** Hardened derivation is one-way, so
a holder of the sub-seed at `m/44'/876'/0'/<profile>'` cannot derive the recovery key. Handing out
that sub-seed therefore delegates day-to-day authority while the root retains the one key that can
supersede it. This design does not use sub-seed delegation (see *Authority tiers*), but the layout
must permit it.

**Algorithm separation and length come from HKDF, not from the path.** SLIP-0010 yields 32 bytes;
ML-DSA-65 needs a 32-byte ξ and ML-KEM needs 64 bytes of `(d, z)`. Expanding through HKDF with an
algorithm-tagged `info` string gives any length and gives distinct algorithms at the same position
independent key material. Adding an algorithm later needs a new `info` string and no path change,
so there is no `alg → index` registry to keep stable forever.

The pre-committed next key is simply the authority key at `seq + 1`. There is no separate next-key
branch.

## Events

Three event types — `inception`, `rotate`, `revoke`. `reset` is a `rotate` variant, not a fourth
type. Field names track KERI's (`i`, `s`, `p`, `k`, `n`, `kt`, `nt`, `a`) so the design stays
auditable against a published specification. Every event carries `gen` and `seq`.

### `inception`

Canonical and deterministic: no timestamp, no nonce, no user label, no device-supplied value. Its
contents are a pure function of the seed and the profile index, so `hash(inception)` — and therefore
the DID — is too.

Commits the initial key set, the next-key digests, **the digest of the recovery key**, and **the
key agreement key set (`ka`)**.

A user label must never enter inception. The DID depends on every byte, so a mistyped label on
recovery would reproduce a different DID.

### Key agreement

A profile publishes an X25519 key agreement key set (`ka`) alongside its authority keys, derived on
the reserved `role 1'` branch at the same `(gen, seq)` position as the authority key. Encrypting to
a profile means encrypting to `ka`; device keys are never the target, because devices hold their own
disposable DIDs.

`ka` lives in the **inception**, not in a later event. Determinism is unaffected either way —
`agreementPath` is as pure a function of `(seed, profile)` as `authorityPath` is. The reason is the
minimal valid log: were `ka` introduced by a first `rotate`, an inception alone would be a complete,
signature-valid `did:kokuin:` publishing no agreement key, and a verifier holding a truncated log
could not distinguish "this profile does key agreement nowhere" from "I am missing events". It would
either fail closed on a legitimate DID or fall back silently. With `ka` in the inception, the
smallest valid log already carries every purpose the profile has.

Converting the Ed25519 authority key to X25519 was rejected. It needs no schema field, but it
couples encryption to rotation authority — the key others encrypt to would also be the key that
rotates the profile — and it re-addresses encryption on every authority rotation. It would also
leave `role 1'` reserved and unused, contradicting the several-purposes requirement above.

`ka` carries **no pre-rotation commitment**. Pre-rotation exists so a stolen current key cannot
rotate; an exposed agreement key discloses past ciphertexts to its holder but confers no authority,
so there is nothing for a commitment to protect. A `rotate` may replace `ka` freely, because only a
signer holding the pre-committed authority key can author one at all.

A `revoke` establishes no keys, so `ka` rides forward across it exactly as the authority key set
does.

**`ka` is an OR set.** Every entry is independently sufficient, and a sender picks the strongest
algorithm it supports. Entries are never combined.

This has to be stated, because a set of keys can mean two opposite things. Hybrid post-quantum
encryption means encrypting to X25519 *and* ML-KEM and mixing both shared secrets, so that an
attacker must break both — AND semantics. A verifier that reads `ka` as OR when the author meant AND
silently delivers the security of the weaker key.

The ambiguity is removed rather than answered: hybrid arrives as a **single** entry under its own
hybrid codec — X-Wing (X25519 + ML-KEM-768) is exactly this, one KEM primitive with one public key
and one shared secret — not as two entries a verifier must know to combine. `ka` semantics then
never change.

### Key encoding

Every key in `k` and `ka` is **multicodec-prefixed before multibase encoding**, following the
`did:key` convention — `0xed 0x01` for Ed25519, `0xec 0x01` for X25519. Entries are therefore
self-describing, and a resolver reads the algorithm off the key rather than assuming one.

This is what makes a new algorithm additive. Bare multibase, as the first implementation used, is
opaque bytes: telling X25519 from ML-KEM-768 would mean sniffing the length. Tagging costs nothing
in this release, because `ka` changes the inception bytes and therefore every DID value anyway; done
later it costs a second DID migration against published identifiers.

A verifier meeting an unknown codec still chooses between skipping the entry and failing closed.
That is a policy decision at adoption time, not a vulnerability: `k` and `ka` sit inside a signed
event covered by the digest, so an attacker cannot strip a stronger key to force a weaker one.

### Post-quantum readiness

The design is post-quantum **ready**, not post-quantum **implementing**. Tagged keys, `ka` as a set
rather than a single key, HKDF `info` already separating algorithms in `deriveKeyMaterial`, and
`KEY_LENGTHS` already carrying `ML-DSA-65` and `ML-KEM-768` mean a hybrid key set arrives by
rotation as a data change, with no schema movement.

Signatures and encryption run on different clocks. Forging a signature requires a quantum computer
at the moment of use, so PQ signatures can wait for a rotation once the threat is real. Encryption
cannot: see the harvest-now-decrypt-later limitation below.

Adoption is blocked on the wire format, not on effort. ML-KEM is standardized (FIPS 203) and
implementations are available, but JOSE has no finalized `alg` for it, and ECDH-ES does not
structurally fit a KEM — X25519 agrees a key, ML-KEM encapsulates one, producing a ciphertext that
needs a defined home in the JWE. Choosing a value now most likely means choosing wrongly, which is
the second breaking change this readiness work exists to avoid.

**Trigger:** adopt when the JOSE ML-KEM draft reaches RFC, as hybrid X25519 + ML-KEM-768 introduced
by rotation.

### `rotate`

New key set, new next-key digests, new agreement key set. Three optional fields:

- **Seal (`a`)** — anchors an external digest, used to pin a high-value capability grant to a log
  position.
- **Deny-set snapshot** — replaces the accumulated deny set, pruning it.
- **Recovery-commitment update** — permitted **only when the event is co-signed by the current
  recovery key**. Without the co-signature requirement, whoever holds key-event authority at any
  moment could seize the profile from the root; with it, only the current recovery holder can move
  the role.

A `rotate` carrying any of these three is not reproducible from the seed alone. See *Determinism
and its boundary*.

### `revoke`

Adds a DID to the profile's **deny set**: no capability whose `aud` is that DID is valid from this
position onward.

Revoking the device DID rather than a capability `jti` is deliberate — it is one entry per device
for that device's whole life, it covers capabilities the verifier has never seen, and it covers
future re-mints. Per-`jti` revocation would grow with every renewal, which is the growth this design
exists to avoid.

Revocation is monotonic. A device that returns generates a fresh DID, which costs nothing because
device DIDs are disposable by construction.

### `reset`

Not a distinct type: a `rotate` signed by the recovery key that increments `gen`. It discards
everything under the prior generation, including every capability minted there.

### `interact`

`interact` from the milestone is **not** included. Nothing in this design consumes it; anchoring is
served by the seal field on `inception` and `rotate`; and since an `interact` costs exactly as much
ledger space as a `rotate`, it buys only the option to anchor without rotating — and the one
anchor-worthy grant is the management capability, whose replacement is a moment that warrants a
rotation anyway. Add it later if a consumer appears.

### Criticality

Every event carries a criticality marker in the common envelope, borrowing JOSE's `crit` idea. The
marker sits alongside `gen` and `seq` rather than inside the type-specific body, so a verifier can
read it without understanding the type it belongs to. An event the verifier does not understand
fails the fold closed when marked critical, and is skipped when not.

This is the only lever that makes the log extensible without a coordinated upgrade for every
addition. Unknown events cannot simply be ignored by default — a verifier that skips a `revoke` it
does not understand accepts a revoked device — so security-relevant additions must fail closed
regardless. Marking non-security additions as non-critical lets them land without a flag day. Adding
`interact` later is exactly such a case.

It has to exist from the first event. A log written before the field existed cannot be reinterpreted
safely once it does, because a verifier has no way to tell whether an absent marker meant
"non-critical" or "written before criticality was a concept".

## Fold and precedence

Precedence is `(gen, seq)` lexicographic; higher wins outright. Verifiers keep a monotonic
`(gen, seq)` floor for each DID — the highest seen anywhere, in any group or direct presentation.
That floor is both the staleness guard and the comparison that makes cross-group duplicity
detectable.

**Superseding recovery**, per KERI: a `rotate` signed by the pre-committed next keys outranks any
operation signed by current keys. The fold therefore needs precedence logic that rewinds
current-key operations authored after a divergence point, rather than treating the recovery as a
fork.

**The deny set is position-dependent state, not a flag.** `revoke` adds; a `rotate` carrying a
snapshot replaces. Clearing a DID at seq 10 does not retroactively validate that DID's actions
between its revocation and seq 10 — a verifier evaluating at position 5 still denies. The
authority is asymmetric: the hot revoke-only key may add, only cold key-event authority may clear.
The set is bounded by device count and a snapshot-carrying rotate prunes it.

**Duplicity** is a same-position divergence and is surfaced, not merged — rotation is sequential per
controller. Re-derivation over reproducible events is idempotent (the same seed and index yield the
same bytes and the same digest), so a fork can only arise from a non-reproducible event.

## Key state

The consumable output is a resolver interface: **key state of a DID at a position** — authority key
set, agreement key set, deny set, thresholds. `@kokuin/token` uses it to resolve `iss`; `@kokuin/jwe`
uses the agreement set to encrypt to a profile; kubun uses it on the apply path; kumiai uses it for
the roster projection.

The position must not be an HLC. HLCs are author-supplied and attacker-controllable; anchoring the
cut-off to a group's epoch or ledger position is the sibling repos' responsibility and is recorded
in their backlog items.

## Authority tiers

One authority key per generation. No quorum and no thresholds: the seed is the root, so a threshold
over seed-derived keys is theatre.

| Tier | Custody | May do |
| --- | --- | --- |
| Root seed | Ledger, or cold mnemonic | Rotate, reset, clear the deny set, mint the management capability |
| Management capability | Primary device, hot, long-lived | Mint and renew device and connector capabilities; author `revoke` |
| Device capability | Per device, lifetime in days | Sign documents |

The management capability replaces the milestone's scoped renewal capability, which existed only
because authority was assumed unreachable. It deliberately holds **no key-event authority** beyond
`revoke`: it cannot rotate, cannot reset, and cannot touch the key set. That preserves the
pre-rotation guarantee — a stolen device cannot take over the identity — which handing a device the
profile sub-seed would have voided.

`revoke` is the one exception, and it follows the design's own reasoning that revocation is the
fail-safe direction. Requiring the Ledger to revoke a stolen phone is a compromise you cannot undo
without the hardware in hand, at exactly the moment speed matters. The cost is that a thief holding
the management capability can revoke your other devices; the remedy is a cold `rotate` clearing the
deny set, with `reset` as the backstop.

**Delegation depth** is capped at 4 — three links (management → device → connector) plus headroom.
`DEFAULT_MAX_DELEGATION_DEPTH` drops from 20 (`packages/capability/src/index.ts:30`); lowering the
default can only reject chains, never accept new ones, and `maxDepth` stays overridable per call
(`index.ts:336`).

**Device capabilities must mandate `exp`** at the mint and verify policy layer. `exp` is optional in
`@kokuin/capability` and enforced only when present (`assertNonExpired`, `index.ts:300`), so the
schema will not do it. The expiry length is the accepted-loss window at an offline verifier, which
argues for days rather than weeks — narrowed, but not eliminated, by on-log revocation.

## Determinism and its boundary

Deterministic inception is the load-bearing property. It gives three things at once: the DID
regenerates from the mnemonic alone; profiles are enumerable by index for the recovery picker; and
re-derivation is idempotent, so legitimate recovery cannot be mistaken for duplicity.

Rotations are deterministic **by default** — a rotate carries only authority keys, next-key digests,
`seq` and `prev`, all seed-derivable, because device keys deliberately live outside the document on
the capability path. They stop being reproducible when they carry a seal, a deny-set snapshot, or a
recovery-commitment update.

A canonical algorithm ladder — a versioned table mapping index to algorithm set, which would keep
even post-quantum rotations reproducible — was considered and rejected. Recovery happens in whatever
app the user reaches for, not necessarily the one that performed the rotation, so the table would
have to agree across independent apps releasing on independent cadences. Two apps at different
versions produce different bytes at the same index, which is a genuine fork rather than an
idempotent re-derivation. Single-seed-holder custody narrows who can *write* a divergent event but
not who must *reproduce* one, so it does not rescue the ladder.

The consequence is accepted rather than engineered around: a profile that has performed a
non-reproducible rotation needs its head digest alongside the mnemonic. That is a 32-byte addition
to a backup artefact, against a cross-application coordination burden.

## Recovery

Two distinct guarantees with different requirements. The milestone blurred them.

**Control recovery** — can this profile keep signing and rotating? Needs the mnemonic, plus the head
digest and `seq` where the log contains non-reproducible events. Survives total device loss. The
recovery-key commitment lives in the deterministic inception, so the root can always author a
superseding `reset` with no log at all.

**Provability recovery** — can this profile prove its key history to a stranger, offline, with no
group context? Needs the full log. Does not survive total device loss unless the log was
independently retained.

Retrieval is not a recovery path. Ledger entries are sealed under `kumiai/ledger-entries/v1` and MLS
leaves are per-device, so a user who lost every device holds no leaf and is authorised to retrieve
nothing. Recovery-by-retrieval requires exactly the authenticated channel that device loss destroys.

**The cold profile picker** enumerates profile indices and renders a handle derived from the DID — a
word triple or an identicon — with no probe and no network. Which profiles were actually used, and
what the user called them, are not seed-derived, so enumeration shows every index as an equally
valid candidate. Probing a group, hub, or local cache to grey out unused profiles is an enhancement
for when it is reachable, never a requirement.

## What names what

- Ownership in kubun is the **profile** DID, never a device. It survives device churn, device loss,
  and authority rotation.
- An MLS leaf credential is a **device**. MLS binds one signature key and one HPKE key per leaf and
  this design forbids copying key material, so leaves are per-device by construction. Device DIDs
  stay `did:key` or `did:peer:4` — self-contained, which preserves the invariant recorded at
  `kumiai/packages/mls/src/credential.ts` that no DID cache is needed because every reachable
  document is already inside a signed artifact. A profile DID's document is a fold of a log and has
  no self-contained form, so a leaf naming one would force exactly that cache.
- Roles in kumiai key the **profile** DID. `RosterState` is already DID-keyed rather than
  leaf-keyed, so the shape does not change; the projection from signer to profile is what kumiai
  must add.

## Packages

| Package | Contents |
| --- | --- |
| `@kokuin/controller` | Derivation, event schema, self-addressing digest, fold, key state at position, duplicity detection, handle derivation, profile enumeration |
| `@kokuin/controller-conformance` | Private, framework-agnostic contract suite, following the `@kokuin/keystore-conformance` habit |
| `@kokuin/token` | `iss` resolved through an injected `DIDMethodResolver`; built-in methods behind subpath exports; `embedLongForm` retained for genesis bootstrap |
| `@kokuin/jwe` | Split out of `@kokuin/token`; async recipient path for resolver-backed methods |
| `@kokuin/capability` | Depth cap lowered; device capabilities mandate `exp` at the mint and verify policy layer |

The name follows DID Core, which calls the entity that may change a DID document its **controller**.
That is precisely what this package models: who may rotate, who may revoke, and what the key state
is at a given position.

The resolver interface is not optional: `@kokuin/controller` depends on `@kokuin/token` for signing,
so token resolving `iss` by importing the fold would be a cycle. Injecting the resolver keeps the
dependency one-way, and `@kokuin/controller` becomes the first out-of-tree method — the best
available test that the interface is real.

Built-in methods stay behind subpath exports rather than becoming packages. Every new package joins
the coupled-release judgement AGENTS.md warns about, and no consumer has asked for method-level
decoupling. `jwe.ts` is the one split with a measured payoff: it is the sole `@noble/ciphers`
consumer, so verify-only consumers currently pay for a cipher dependency they never call.

`packages/token/src/rotation.ts` and `createRotationAssertion` become dead — rotation chains are
what this design replaces. They are **deleted**, not deprecated: nothing in the workspace consumes
them, and the JWE split already makes this a breaking `@kokuin/token` major, so a deprecation would
buy a cycle of dead code and no migration window anyone needs.

Encrypting to a `did:kokuin:` recipient needs an async path, because the agreement key comes from
the fold rather than from the identifier. The existing sync `deriveSharedSecret` and
`createTokenEncrypter` are retained unchanged for self-contained DIDs — `did:key` and `did:peer:4`
long form — and async siblings take a resolver registry. `DIDMethodResolver` gains an optional
`resolveAgreementKey` returning the tagged `ka` set; jwe selects by its own preference order and
fails with a named error when it supports none of the entries. Keeping selection in jwe means a
future hybrid codec changes one preference list rather than every method implementation.

`@kokuin/controller` releases independently of the token / capability / browser / node /
deterministic judgement group, which matters while the event format is still moving.

## Named limitations

- **A stolen mnemonic is terminal.** The thief holds every key at every index, including the
  recovery key, and can always rotate ahead of the owner. No pre-rotation defence applies. This is
  the price of seed-rooting.
- **Adopted profiles are out of scope.** A device could start under its own `did:kokuin:` profile
  with a device-generated inception and later adopt an HD-derived authority key by a co-signed
  `rotate`, keeping the same DID and requiring no migration. Such a profile sits at no derivation
  path, so it is invisible to the cold picker and outside the pure-mnemonic recovery guarantee. The
  co-signature-gated recovery field on `rotate` is retained precisely so this remains possible
  later without a format break; nothing implements it now. Deferred onboarding is therefore an
  app-side concern: work locally until onboarding, then derive a normal profile.
- **Cross-group duplicity is detectable, not preventable.** Kumiai orders per group only. Nesting
  makes divergent chains comparable across groups; detection still needs a member of both groups, an
  external witness, or a public mirror.
- **Unanchored capabilities remain backdatable.** `cap.iat` is author-supplied. Anchoring closes it
  for sealed grants; for the rest the exposure is bounded by the accepted-loss window rather than
  eliminated.
- **No log compaction path.** Every rotation is permanent and replayed at every welcome. The design
  keeps rotations rare — authority changes, post-quantum migration, recovery — which is what keeps
  the kumiai control ledger bounded.
- **Harvest-now-decrypt-later applies to `ka`.** X25519 is the only key agreement algorithm shipping
  in this release, so anything encrypted to a profile today can be captured now and opened once a
  cryptographically relevant quantum computer exists. The exposure lasts as long as the data's
  confidentiality lifetime, and the spec says durable data encrypts to these keys — so this is a
  real window, not a theoretical one. Signatures do not share it: forgery requires a quantum
  computer at the moment of use, which a rotation can stay ahead of. The format is ready (see
  *Post-quantum readiness*); only the wire standard is missing.
- **Post-quantum token size.** ML-DSA-65 signatures are ~3.3 KB, taking tokens from ~200 bytes to
  ~7 KB. Every ledger entry is a signed token, so this hits the kumiai welcome transfer, the
  `did:peer:4` document-size guards, and hub retention at once. It is a first-order constraint, not
  a footnote.
- **Profile granularity.** Default to coarse personas (personal, professional). Per-group profiles
  maximise unlinkability but fragment ownership — documents cannot cross profiles without an
  explicit re-grant and re-owning — and ceremony cost scales as profiles × devices. Surface the
  trade-off in the UI rather than burying it.
- **Rolling our own key management is the classic footgun.** Mitigated by copying KERI semantics
  field-for-field rather than inventing, and by justifying each delta explicitly: JSON/JOSE instead
  of CESR, MLS groups plus proof-carrying verification instead of a witness network, and a deny set
  instead of a separate revocation registry.

## Deferred, with owners

- **kumiai** — whether implicit device delegation is total or capped by a ceiling in the binding;
  the device→profile binding entry; the roster projection at `roleReducer.verifyAuthority` and at
  the universal admin invariant in `envelope-fold.ts`; the genesis anchor carrying both the
  creator's profile DID and their device DID. Tracked in
  `kumiai/docs/agents/plans/backlog/2026-08-07-did-registry-ledger-entries.md`.
- **kubun** — which group anchors the cut-off position for documents reachable from several groups;
  cache invalidation under superseding recovery. Tracked in
  `kubun/docs/agents/plans/backlog/2026-08-07-profile-did-ownership.md`.
- **kokuin** — ML-DSA in `SUPPORTED_ALGORITHMS` per RFC 9964, and PQ/T composite signatures once
  `draft-ietf-jose-pq-composite-sigs` settles. Tracked in
  `backlog/2026-06-30-post-quantum-algorithms.md`.
- **kokuin** — post-quantum key agreement in `ka`. **Trigger:** the JOSE ML-KEM draft reaching RFC.
  Ships as hybrid X-Wing (X25519 + ML-KEM-768) under its own multicodec, introduced by a `rotate`,
  as a single `ka` entry rather than two combined ones. No schema change is required; the work is a
  new codec, a new branch in jwe's preference order, and a `deriveKeyPair` that handles the
  algorithm. See *Post-quantum readiness* and the harvest-now-decrypt-later limitation.
- **kokuin** — token repackaging beyond the JWE split, if a consumer's bundle ever justifies it.
- **DIF registration** of `did:kokuin:`.

## References

- KERI: <https://arxiv.org/pdf/1907.02143>, Q&A <https://identity.foundation/keri/docs/Q-and-A.html>
- `did:keri`: <https://github.com/WebOfTrust/did-keri>
- `did:webvh` v1.0: <https://identity.foundation/didwebvh/v1.0/>
- RFC 9420 (MLS): <https://www.rfc-editor.org/rfc/rfc9420.pdf>
- RFC 9964 (ML-DSA for JOSE and COSE): <https://www.rfc-editor.org/info/rfc9964/>
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) — seed-based key generation, which is what makes PQ keys
  HD-derivable
- PQ/T hybrid composite signatures: <https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/>
