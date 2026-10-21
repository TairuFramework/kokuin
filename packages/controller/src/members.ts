import { normalizeDID, signingKeysOf } from '@kokuin/token'

import { digestOf } from './canonical.js'
import {
  isKeyList,
  isMemberEntry,
  keyTarget,
  type MemberEntry,
  type StateSnapshot,
} from './events.js'
import { encodeKey, tryDecodeKey } from './keys.js'

/** What a non-reset rotate missing either half of its state snapshot fails with. */
export const ROTATE_NEEDS_SNAPSHOT = 'rotate carries no state snapshot'

/**
 * What a snapshot fails with when its shape is wrong: `m` not a list of {@link MemberEntry}, a pin
 * that is not an Ed25519 key, two entries for one `add` or one pinned key, or `d` not a key list.
 */
export const SNAPSHOT_MALFORMED = 'malformed state snapshot'

/** A snapshot member pinning a key on, or committed by, the generation's root chain. */
export const SNAPSHOT_MEMBER_KEY_IS_ROOT = 'snapshot member key is a root key'

/** A snapshot member whose DID is not a `did:key` or long-form `did:peer:4` carrying its pin. */
export const SNAPSHOT_MEMBER_DID_MISMATCH = 'snapshot member DID does not carry its key'

/** A rotate whose deny set leaves out a retired-key denial an earlier rotate checkpointed. */
export const SNAPSHOT_DROPS_RETIRED_KEY = 'snapshot drops a retired key denial'

/**
 * Whether `did` carries exactly `key` as its signing key: a `did:key` of that key, or a long-form
 * `did:peer:4` whose document carries that one Ed25519 signing key and no other. Everything else is
 * false — a short-form `did:peer:4` or a network-backed DID carries no key to check, and a document
 * carrying a second signing key would let a grant verifier that reads the DID rather than the pin
 * accept a key the log never admitted.
 *
 * Total: an identifier that claims to carry a key and does not (`signingKeysOf` throws on it) is
 * simply not a match.
 */
export function memberCarriesKey(did: string, key: string): boolean {
  let keys: ReturnType<typeof signingKeysOf>
  try {
    keys = signingKeysOf(did)
  } catch {
    return false
  }
  if (keys == null || keys.length !== 1) {
    return false
  }
  const [carried] = keys
  return carried != null && carried.alg === 'EdDSA' && encodeKey(carried.publicKey, 'EdDSA') === key
}

/**
 * `normalizeDID`, total: it reads a `did:peer:4` long form apart, and a deny entry is arbitrary wire
 * data. An entry it cannot read names nobody under canonical equivalence, so it compares as itself.
 */
function canonicalDID(did: string): string {
  try {
    return normalizeDID(did)
  } catch {
    return did
  }
}

/**
 * **The** predicate for "this denial targets this membership", and the only one: the member-revoke
 * guard and denial dominance use exactly this. True iff `entry` is `#` plus the member's pinned key,
 * or the member's DID under canonical DID equivalence (`normalizeDID`: the long and short forms of a
 * `did:peer:4` are one DID).
 *
 * Nothing broader. "Any DID containing that public key" is not an alias: anyone can manufacture a
 * document containing someone else's public key, so a `did:key` of a peer member's pin is a
 * different DID, denied through the key target or not at all.
 */
export function denialTargetsMember(entry: string, member: MemberEntry): boolean {
  if (entry === keyTarget(member.key)) {
    return true
  }
  return entry.startsWith('did:') && canonicalDID(entry) === canonicalDID(member.did)
}

export type ValidateSnapshotParams = {
  snapshot: StateSnapshot
  /** Every `k`/`ka` on the current generation's chain, including the event carrying the snapshot. */
  generationKeys: Array<string>
  /** Every `n` on the current generation's chain, including the event carrying the snapshot. */
  generationCommitments: Array<string>
  /**
   * The retired-key denials the snapshot must keep: the prior chain state's key-target denials that
   * name a key in `generationKeys`. Empty on a reset, which opens a new generation.
   */
  tombstones: ReadonlySet<string>
}

/**
 * Judge a state snapshot against the generation it lands on: `null` when it may become the state,
 * else the fold reason. Total on wire data — `snapshot` arrives from `JSON.parse` like everything
 * else on the log, so no part of it is trusted to have the type it claims.
 *
 * Rules, in order:
 *
 * - **Shape** ({@link SNAPSHOT_MALFORMED}): `members` is a list of {@link MemberEntry} whose pins
 *   decode as Ed25519, no two sharing an `add` (one incarnation, one entry) or a pinned key (one key
 *   twice would let it renew itself through the alias); `deny` is a key list.
 * - **Disjoint from root** ({@link SNAPSHOT_MEMBER_KEY_IS_ROOT}): no pin is a `k`/`ka` on the
 *   generation's chain or committed in one of its `n`. A management device never holds a root key, so
 *   member authority and root authority cannot be confused for each other.
 * - **The DID carries the pin** ({@link SNAPSHOT_MEMBER_DID_MISMATCH}): see {@link memberCarriesKey}.
 * - **Checkpointed retirements stay** ({@link SNAPSHOT_DROPS_RETIRED_KEY}): every tombstone is in
 *   `deny`. Historic resolution would otherwise accept fresh tokens signed with a retired key again,
 *   and the chain alone enforces it, so a pruned and a full store agree. Holder DID denials carry no
 *   such rule: dropping one is a deliberate re-authorisation.
 */
export function validateSnapshot(params: ValidateSnapshotParams): string | null {
  const { snapshot, generationKeys, generationCommitments, tombstones } = params
  const members: unknown = snapshot.members
  const deny: unknown = snapshot.deny
  if (!Array.isArray(members) || !isKeyList(deny)) {
    return SNAPSHOT_MALFORMED
  }
  const adds = new Set<string>()
  const pins = new Set<string>()
  for (const entry of members) {
    if (!isMemberEntry(entry) || tryDecodeKey(entry.key)?.alg !== 'EdDSA') {
      return SNAPSHOT_MALFORMED
    }
    if (adds.has(entry.add) || pins.has(entry.key)) {
      return SNAPSHOT_MALFORMED
    }
    adds.add(entry.add)
    pins.add(entry.key)
  }
  const rootKeys = new Set(generationKeys)
  const commitments = new Set(generationCommitments)
  for (const entry of members as Array<MemberEntry>) {
    if (rootKeys.has(entry.key) || commitments.has(digestOf(entry.key))) {
      return SNAPSHOT_MEMBER_KEY_IS_ROOT
    }
  }
  for (const entry of members as Array<MemberEntry>) {
    if (!memberCarriesKey(entry.did, entry.key)) {
      return SNAPSHOT_MEMBER_DID_MISMATCH
    }
  }
  const denied = new Set(deny)
  for (const tombstone of tombstones) {
    if (!denied.has(tombstone)) {
      return SNAPSHOT_DROPS_RETIRED_KEY
    }
  }
  return null
}
