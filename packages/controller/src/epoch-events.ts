import { canonicalBytes, isCanonicalizable } from './canonical.js'
import { authorityPath, deriveKeyPair } from './derivation.js'
import { didFor, type SignedEvent, signEvent, verifySignatures } from './events.js'
import type { KeyState } from './fold.js'
import { encodeKey } from './keys.js'
import { MAX_EVENT_BYTES, MAX_EVENT_PARENTS, MAX_EVENT_SIGNATURES } from './limits.js'

// The management tier. An epoch is everything between one root-chain event and the next; its events
// (root adds, member actions, root and member revokes) form a DAG rooted at the root-chain event that
// opened it, and the fold merges their effects. Nothing here judges authorisation -- who may sign
// what is a question about the causal past, which only the fold has. This file owns what an event
// *is*: its fields, the bytes it signs, and whether a signature over them verifies under a named key.

export type EpochEventType = 'add' | 'ren' | 'rmv' | 'rev'

const EPOCH_EVENT_TYPES: ReadonlySet<unknown> = new Set<EpochEventType>([
  'add',
  'ren',
  'rmv',
  'rev',
])

export type EpochEventCommon = {
  /** Format version. Always written, never inferred. */
  v: 1
  t: EpochEventType
  /** Profile DID. */
  i: string
  /** Generation of the root chain this event's epoch belongs to. */
  g: number
  /**
   * Digest of the root-chain event that opened the epoch. An event naming any other epoch has no
   * effect: its effect is either in the newer snapshot or was dropped by it.
   */
  e: string
  /**
   * Parents: `e` itself or digests of events of the same epoch -- every head the author knows, a
   * recommendation the fold cannot enforce. 1 to {@link MAX_EVENT_PARENTS} entries, no duplicates. A
   * list, not a single predecessor, because concurrent members branch and a later event joins them.
   */
  p: Array<string>
  /**
   * Criticality, in the envelope for the same reason as on the root chain. Always `true` here, so a
   * verifier predating the management tier fails closed rather than skipping a revoke.
   */
  crit: boolean
  /**
   * The signing member's add digest -- its incarnation, not its DID, so a removed and re-added member
   * signs under a different reference. Absent means root: n-of-n over the chain head's `k`.
   */
  by?: string
}

/** Root-only: a member is admitted only by a root signature. */
export type AddEvent = EpochEventCommon & {
  t: 'add'
  /** The member's DID: an Ed25519 `did:key`, or a long-form `did:peer:4` carrying `key`. */
  did: string
  /** The pinned Ed25519 key, encoded as a key in `k` is. Everything the member signs verifies under it. */
  key: string
  /** Lease end, unix seconds. Bounds the member's grants; the fold never reads it. */
  lease: number
}

export type RenewEvent = EpochEventCommon & {
  t: 'ren'
  /** The incarnation renewed, by add digest, so a delayed renew never carries over to a re-add. */
  add: string
  /** New lease end, unix seconds. Merges as the maximum per incarnation. */
  lease: number
}

export type RemoveEvent = EpochEventCommon & {
  t: 'rmv'
  /** The incarnation removed, by add digest. Dominates any renewal of it. */
  add: string
}

export type RevokeEvent = EpochEventCommon & {
  t: 'rev'
  /** A DID or a key target, the two spellings the root chain's deny set takes -- see `keyTarget`. */
  x: string
}

export type EpochEvent = AddEvent | RenewEvent | RemoveEvent | RevokeEvent

export type EpochSigner =
  | { root: { seed: Uint8Array; profile: number } }
  | { member: { privateKey: Uint8Array; add: string } }

type BuildBase = { did: string; head: KeyState; parents: Array<string> }

export type CreateAddParams = BuildBase & {
  seed: Uint8Array
  profile: number
  member: { did: string; key: string; lease: number }
}

export type CreateRenewParams = BuildBase & { signer: EpochSigner; add: string; lease: number }

export type CreateRemoveParams = BuildBase & { signer: EpochSigner; add: string }

export type CreateRevokeParams = BuildBase & { signer: EpochSigner; target: string }

type Body<E extends EpochEvent> = Omit<E, keyof EpochEventCommon>

/**
 * Sign `fields` as an event of `head`'s epoch.
 *
 * **Throws rather than emitting an event the fold will reject**, the rule the root-chain builders
 * follow: an empty or oversized parent list, a fractional lease, or a body past the byte limit is
 * refused here, where the caller can still act. So is a root signer whose derived key `head` does
 * not publish, when the seed is this DID's root -- a stale `keyGen`/`keySeq` would otherwise produce
 * a well-formed, signed event no fold accepts. A foreign seed is left alone, as `createRotate` leaves
 * it: a mismatch there says nothing, and the fold is the layer that rejects it.
 */
function buildEvent<E extends EpochEvent>(
  t: E['t'],
  signer: EpochSigner,
  { did, head, parents }: BuildBase,
  fields: Body<E>,
): SignedEvent<E> {
  if (parents.length === 0) {
    throw new Error('Epoch event: at least one parent is required -- the epoch digest at minimum')
  }
  // Code-unit order, so the written list is a function of the set alone.
  const p = [...new Set(parents)].sort()

  let privateKey: Uint8Array
  if ('root' in signer) {
    const { seed, profile } = signer.root
    const pair = deriveKeyPair(seed, authorityPath(profile, head.keyGen, head.keySeq), 'EdDSA')
    const derived = encodeKey(pair.publicKey, 'EdDSA')
    // Exactly the one key: the verifier checks n-of-n, and this generator signs with one.
    if (didFor(seed, profile) === did && !(head.keys.length === 1 && head.keys[0] === derived)) {
      throw new Error(
        `Epoch event: the key at (gen ${head.keyGen}, seq ${head.keySeq}) is not the head's only ` +
          'published key -- pass the folded head, whose keyGen / keySeq name the active authority key',
      )
    }
    privateKey = pair.privateKey
  } else {
    privateKey = signer.member.privateKey
  }

  const common: EpochEventCommon = {
    v: 1,
    t,
    i: did,
    g: head.gen,
    e: head.epoch,
    p,
    crit: true,
  }
  // Conditionally spread: a root event has no `by` key at all, not one set to undefined.
  const event = {
    ...common,
    ...('member' in signer ? { by: signer.member.add } : {}),
    ...fields,
  } as E
  const signed: SignedEvent<E> = { event, sigs: signEvent(event, [privateKey]) }
  if (!isEpochEventShape(signed)) {
    throw new Error(
      `Epoch event: the ${t} built is not a well-formed epoch event -- check the parent count ` +
        `(at most ${MAX_EVENT_PARENTS} distinct), integer leases and the ${MAX_EVENT_BYTES}-byte body limit`,
    )
  }
  return signed
}

/** Admit a member. Root-only by type: there is no member signer for an add. */
export function createAdd({
  seed,
  profile,
  member,
  ...base
}: CreateAddParams): SignedEvent<AddEvent> {
  return buildEvent<AddEvent>('add', { root: { seed, profile } }, base, {
    did: member.did,
    key: member.key,
    lease: member.lease,
  })
}

/** Extend an incarnation's lease. A member may renew another member, never itself. */
export function createRenew({
  signer,
  add,
  lease,
  ...base
}: CreateRenewParams): SignedEvent<RenewEvent> {
  return buildEvent<RenewEvent>('ren', signer, base, { add, lease })
}

/** End an incarnation's log authority. A member may remove another member, never itself. */
export function createRemove({
  signer,
  add,
  ...base
}: CreateRemoveParams): SignedEvent<RemoveEvent> {
  return buildEvent<RemoveEvent>('rmv', signer, base, { add })
}

/**
 * Deny an edge holder or a retired key. Root or any single member; a member may not target a member
 * of its causal past, which removal covers instead.
 */
export function createRevoke({
  signer,
  target,
  ...base
}: CreateRevokeParams): SignedEvent<RevokeEvent> {
  return buildEvent<RevokeEvent>('rev', signer, base, { x: target })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Length is bounded before the walk, so an oversized list costs one comparison. */
function isStringList(value: unknown, max: number): value is Array<string> {
  return Array.isArray(value) && value.length <= max && value.every((e) => typeof e === 'string')
}

/** Unix seconds: a non-negative safe integer, so `"1800000000"` and `1.5` both fail. */
function isSeconds(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 0
}

function hasTypeFields(event: Record<string, unknown>): boolean {
  switch (event.t) {
    case 'add':
      return (
        typeof event.did === 'string' && typeof event.key === 'string' && isSeconds(event.lease)
      )
    case 'ren':
      return typeof event.add === 'string' && isSeconds(event.lease)
    case 'rmv':
      return typeof event.add === 'string'
    case 'rev':
      return typeof event.x === 'string'
    default:
      return false
  }
}

/**
 * Whether `value` has the shape of a signed epoch event: the envelope, the fields its type carries,
 * the parent rules, and a canonical body within {@link MAX_EVENT_BYTES}. Total on anything
 * `JSON.parse` yields, since an epoch event arrives from a peer or an untrusted store. A request-limit
 * check: failing it rejects input and changes no state.
 *
 * Structure only. It says nothing about who signed, whether the signer may, or whether the parents
 * exist -- those belong to {@link verifyEpochSignature} and the fold. `crit` must be exactly `true`:
 * every type here is critical, and a known type declaring otherwise is a body whose envelope
 * contradicts it. A `recoveryKey` on the envelope is refused rather than ignored -- only a reset
 * reveals one, and a member nothing reads is a field that lies.
 */
export function isEpochEventShape(value: unknown): value is SignedEvent<EpochEvent> {
  if (!isRecord(value) || !isRecord(value.event)) {
    return false
  }
  const { event, sigs } = value
  if (
    !isStringList(sigs, MAX_EVENT_SIGNATURES) ||
    sigs.length === 0 ||
    value.recoveryKey !== undefined
  ) {
    return false
  }
  if (
    event.v !== 1 ||
    !EPOCH_EVENT_TYPES.has(event.t) ||
    typeof event.i !== 'string' ||
    !isSeconds(event.g) ||
    typeof event.e !== 'string' ||
    event.crit !== true ||
    (event.by !== undefined && typeof event.by !== 'string')
  ) {
    return false
  }
  const p = event.p
  if (!isStringList(p, MAX_EVENT_PARENTS) || p.length === 0 || new Set(p).size !== p.length) {
    return false
  }
  if (!hasTypeFields(event)) {
    return false
  }
  // Last: the only check whose cost grows with the body, and the one that needs the rest settled.
  return isCanonicalizable(event) && canonicalBytes(event).length <= MAX_EVENT_BYTES
}

/**
 * Whether `signed` verifies under the signer the caller names. The fold names it from `by`: absent,
 * the chain head's keys; present, the key the referenced add pinned.
 *
 * The signer kind must agree with `by`, so a root-signed body cannot pass as a member's or the
 * reverse: a single-key root and a member are otherwise the same check, and an event whose `by` the
 * caller did not consult would be authorised as whoever happened to be asked about. Root is n-of-n
 * over `rootKeys` (via `verifySignatures`); a member signs alone, so exactly one signature, under the
 * pinned key. Total: a malformed body or signature is `false`.
 */
export function verifyEpochSignature(
  signed: SignedEvent<EpochEvent>,
  signer: { rootKeys: Array<string> } | { memberKey: string },
): boolean {
  const { event, sigs } = signed
  if (!isRecord(event) || !Array.isArray(sigs) || sigs.length > MAX_EVENT_SIGNATURES) {
    return false
  }
  if ('rootKeys' in signer) {
    return event.by === undefined && verifySignatures(event, sigs, signer.rootKeys)
  }
  // One key, and `verifySignatures` matches signatures to keys one for one: exactly one signature.
  return (
    sigs.length === 1 &&
    typeof event.by === 'string' &&
    verifySignatures(event, sigs, [signer.memberKey])
  )
}
