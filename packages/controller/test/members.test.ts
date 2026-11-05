import { CODECS, type DIDDoc, encodeMultibase, encodePeer4, getPeer4ShortForm } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  ADD_DID_MISMATCH,
  ADD_KEY_ALREADY_MEMBER,
  ADD_KEY_DENIED,
  ADD_KEY_IS_ROOT,
  ADD_NOT_ROOT,
  type FoldEpochDetail,
  type FoldEpochParams,
  foldEpochDetailed,
  MEMBER_REVOKES_MEMBER,
  REVOKE_NAMES_ROOT_KEY,
  SELF_REMOVE,
  SELF_RENEW,
  UNKNOWN_MEMBER,
} from '../src/epoch.js'
import {
  createAdd,
  createRemove,
  createRenew,
  createRevoke,
  type EpochEvent,
  type EpochSigner,
} from '../src/epoch-events.js'
import {
  createInception,
  createRotate,
  didFromInception,
  keyTarget,
  type MemberEntry,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { type FoldResult, foldLog } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'
import type { ControllerLog } from '../src/log.js'
import { createDenialMatcher, denialTargetsMember } from '../src/members.js'

type RenewParams = { signer: EpochSigner; target: string; lease: number; parents?: Array<string> }

/** {@link foldEpochDetailed}, which these fixtures never drive into the failed-signature refusal. */
async function detailOf(params: FoldEpochParams): Promise<FoldEpochDetail> {
  const detail = await foldEpochDetailed(params)
  if (!detail.ok) throw new Error(`epoch fold refused: ${detail.reason}`)
  return detail
}

const seed = new Uint8Array(32).fill(1)
const profile = 0
const inception = await createInception({ seed, profile })
const did = didFromInception(inception.event)

type KeyPair = { privateKey: Uint8Array; key: string; did: string }

/** A member key pair from a fixed secret, so every run builds the same events and digests. */
function memberKeyPair(fill: number): KeyPair {
  const privateKey = new Uint8Array(32).fill(fill)
  const key = encodeKey({ publicKey: ed25519.getPublicKey(privateKey), alg: 'EdDSA' })
  return { privateKey, key, did: `did:key:${key}` }
}

/** A long-form `did:peer:4` carrying exactly `key` as its one signing key. */
function peerDID(key: string): string {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: '#key-0', type: 'Multikey', publicKeyMultibase: key }],
    authentication: ['#key-0'],
  } as DIDDoc
  return encodePeer4(doc).longForm
}

/** The authority key this seed establishes at `(gen, seq)`, in the spelling `k` carries. */
function rootKeyAt(gen: number, seq: number): string {
  return encodeKey({
    publicKey: deriveKeyPair({
      seed,
      path: authorityPath({ profile, gen, seq }),
      alg: 'EdDSA',
    }).publicKey,
    alg: 'EdDSA',
  })
}

const at = <TValue>(items: ReadonlyArray<TValue>, i: number): TValue => {
  const value = items[i]
  if (value === undefined) throw new Error(`expected element at ${i}`)
  return value
}

const LEASE = 1_900_000_000

function entryOf(pair: KeyPair, add: string): MemberEntry {
  return { did: pair.did, key: pair.key, add, lease: LEASE }
}

// Three members the settling rotate carries, so a removal cycle of three needs no root adds.
const a = memberKeyPair(11)
const b = memberKeyPair(12)
const c = memberKeyPair(13)
const memberA = entryOf(a, digestOf('the add that admitted A'))
const memberB = entryOf(b, digestOf('the add that admitted B'))
const memberC = entryOf(c, digestOf('the add that admitted C'))

const rot = await createRotate({
  seed,
  profile,
  did,
  prior: inception.event,
  snapshot: { members: [memberA, memberB, memberC], deny: [] },
})
const chain: Array<SignedEvent> = [inception, rot]

const settled = await foldLog({ did, input: { chain, events: [] } })
if (!settled.ok) {
  throw new Error(`fixture chain does not fold: ${settled.reason}`)
}
const head = settled.head
const epoch = head.epoch

const root: EpochSigner = { root: { seed, profile } }
const signerA: EpochSigner = { member: { privateKey: a.privateKey, add: memberA.add } }
const signerB: EpochSigner = { member: { privateKey: b.privateKey, add: memberB.add } }
const signerC: EpochSigner = { member: { privateKey: c.privateKey, add: memberC.add } }

function digest(signed: SignedEvent<EpochEvent>): string {
  return digestOf(signed.event)
}

async function add(
  member: { did: string; key: string; lease?: number },
  parents: Array<string> = [epoch],
): Promise<SignedEvent<EpochEvent>> {
  return await createAdd({
    seed,
    profile,
    did,
    head,
    parents,
    member: { did: member.did, key: member.key, lease: member.lease ?? LEASE },
  })
}

async function renew({
  signer,
  target,
  lease,
  parents = [epoch],
}: RenewParams): Promise<SignedEvent<EpochEvent>> {
  return await createRenew({ signer, did, head, parents, add: target, lease })
}

async function remove(
  signer: EpochSigner,
  target: string,
  parents: Array<string> = [epoch],
): Promise<SignedEvent<EpochEvent>> {
  return await createRemove({ signer, did, head, parents, add: target })
}

async function revoke(
  signer: EpochSigner,
  target: string,
  parents: Array<string> = [epoch],
): Promise<SignedEvent<EpochEvent>> {
  return await createRevoke({ signer, did, head, parents, target })
}

/** Re-sign `event` with one private key, as whoever holds it would. */
async function signedBy(
  event: EpochEvent,
  privateKey: Uint8Array,
): Promise<SignedEvent<EpochEvent>> {
  return { event, sigs: await signEvent(event, [privateKey]) }
}

/** Why each event of `log` was refused, by digest: what the head alone cannot say. */
async function rejectionsOf(controller: string, log: ControllerLog): Promise<Map<string, string>> {
  const folded = await foldLog({ did: controller, input: { chain: log.chain, events: [] } })
  if (!folded.ok) {
    throw new Error(`chain does not fold: ${folded.reason}`)
  }
  return (await detailOf({ did: controller, chainStates: folded.states, events: log.events }))
    .reasons
}

async function reasonsFor(events: Array<SignedEvent<EpochEvent>>): Promise<Map<string, string>> {
  return await rejectionsOf(did, { chain, events })
}

async function folded(events: Array<unknown>): Promise<Extract<FoldResult, { ok: true }>> {
  const result = await foldLog({
    did,
    input: { chain, events: events as ControllerLog['events'] },
  })
  if (!result.ok) {
    throw new Error(`log does not fold: ${result.reason}`)
  }
  return result
}

/** Everything order independence promises about a fold, in a form `toEqual` compares exactly. */
async function summary(events: Array<unknown>) {
  const result = await folded(events)
  return {
    deny: [...result.head.deny].sort(),
    members: [...result.head.members.entries()].sort(([x], [y]) => (x < y ? -1 : 1)),
    applied: result.applied,
    pending: result.pending,
    rejected: result.rejected,
  }
}

function permutations<TValue>(items: Array<TValue>): Array<Array<TValue>> {
  if (items.length <= 1) {
    return [items]
  }
  return items.flatMap((item, i) => {
    return permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => {
      return [item, ...rest]
    })
  })
}

/** Every presentation order folds to `expected`: the merge, not the arrival, decides. */
async function expectEveryOrder(events: Array<SignedEvent<EpochEvent>>) {
  const expected = await summary(events)
  for (const order of permutations(events)) {
    expect(await summary(order)).toEqual(expected)
  }
  return expected
}

const d = memberKeyPair(14)

describe('adding a member', () => {
  test('a root add makes an effective member with its lease', async () => {
    const added = await add({ ...d, lease: 2_000_000_000 })
    const result = await folded([added])
    expect(result.rejected).toBe(0)
    expect(result.head.members.get(digest(added))).toEqual({
      did: d.did,
      key: d.key,
      add: digest(added),
      lease: 2_000_000_000,
      removed: false,
      effective: true,
    })
  })

  test('a long-form did:peer:4 carrying the pin is admitted', async () => {
    const added = await add({ did: peerDID(d.key), key: d.key })
    expect((await folded([added])).head.members.get(digest(added))?.effective).toBe(true)
  })

  test('a member cannot add a member', async () => {
    // The root add, with only `by` set and the member's signature in place of root's.
    const rootAdd = await add(d)
    const memberAdd = await signedBy({ ...rootAdd.event, by: memberA.add }, a.privateKey)
    expect((await reasonsFor([memberAdd])).get(digest(memberAdd))).toBe(ADD_NOT_ROOT)
    expect((await folded([memberAdd])).head.members.has(digest(memberAdd))).toBe(false)
    // Control: the same body without `by`, under root's signature, applies.
    expect((await reasonsFor([rootAdd])).size).toBe(0)
  })

  test('an add whose DID does not carry its pin is refused', async () => {
    const cases: Array<[string, { did: string; key: string }]> = [
      ['a did:key of another key', { did: a.did, key: d.key }],
      ['a short-form did:peer:4', { did: getPeer4ShortForm(peerDID(d.key)), key: d.key }],
      ['a network DID', { did: 'did:web:example.com', key: d.key }],
    ]
    for (const [label, member] of cases) {
      const refused = await add(member)
      expect((await reasonsFor([refused])).get(digest(refused)), label).toBe(ADD_DID_MISMATCH)
    }
  })

  test('an add pinning a non-Ed25519 key is refused', async () => {
    const publicKey = p256.getPublicKey(new Uint8Array(32).fill(7))
    const key = encodeMultibase(new Uint8Array([...CODECS.ES256, ...publicKey]))
    const refused = await add({ did: `did:key:${key}`, key })
    expect((await reasonsFor([refused])).get(digest(refused))).toBe(ADD_DID_MISMATCH)
  })

  test('an add pinning a root key, a committed next key or the recovery key is refused', async () => {
    const recovery = encodeKey({
      publicKey: deriveKeyPair({ seed, path: recoveryPath(profile), alg: 'EdDSA' }).publicKey,
      alg: 'EdDSA',
    })
    const cases: Array<[string, string]> = [
      ['the head key', rootKeyAt(0, 1)],
      ['a retired key of this generation', rootKeyAt(0, 0)],
      ['the committed next key', rootKeyAt(0, 2)],
      ['the recovery key', recovery],
    ]
    // The fixture is what the cases claim: the head publishes (0, 1) and commits (0, 2).
    expect(head.keys).toEqual([rootKeyAt(0, 1)])
    expect(head.next).toEqual([digestOf(rootKeyAt(0, 2))])
    expect(head.recovery).toBe(digestOf(recovery))
    for (const [label, key] of cases) {
      const refused = await add({ did: `did:key:${key}`, key })
      expect((await reasonsFor([refused])).get(digest(refused)), label).toBe(ADD_KEY_IS_ROOT)
    }
  })

  test('an add of a key or DID denied in its causal past is refused', async () => {
    for (const target of [keyTarget(d.key), d.did]) {
      const denial = await revoke(root, target)
      const refused = await add(d, [digest(denial)])
      expect((await reasonsFor([denial, refused])).get(digest(refused)), target).toBe(
        ADD_KEY_DENIED,
      )
    }
    // A long-form peer member is denied through its short form: canonical DID equivalence.
    const peer = peerDID(d.key)
    const denial = await revoke(root, getPeer4ShortForm(peer))
    const refused = await add({ did: peer, key: d.key }, [digest(denial)])
    expect((await reasonsFor([denial, refused])).get(digest(refused))).toBe(ADD_KEY_DENIED)
    // Control: the same add concurrent with the denial applies.
    const concurrent = await add(d)
    expect((await reasonsFor([await revoke(root, d.did), concurrent])).size).toBe(0)
  })

  test('an add of a key an effective member of its causal past already pins is refused', async () => {
    const first = await add(d)
    const again = await add({ did: peerDID(d.key), key: d.key }, [digest(first)])
    expect((await reasonsFor([first, again])).get(digest(again))).toBe(ADD_KEY_ALREADY_MEMBER)
    // A settled member counts too.
    const settledAgain = await add({ did: peerDID(a.key), key: a.key })
    expect((await reasonsFor([settledAgain])).get(digest(settledAgain))).toBe(
      ADD_KEY_ALREADY_MEMBER,
    )
    // Once that incarnation is removed in the causal past, the key may be added again.
    const removal = await remove(root, digest(first), [digest(first)])
    const readd = await add({ did: peerDID(d.key), key: d.key }, [digest(removal)])
    expect((await reasonsFor([first, removal, readd])).size).toBe(0)
  })

  test('an add with a lease that is not unix seconds is not an epoch event', async () => {
    for (const lease of [-1, 1.5, '1900000000']) {
      const event = { ...(await add(d)).event, lease } as unknown as EpochEvent
      const malformed = {
        event,
        sigs: await signEvent(event, [
          deriveKeyPair({
            seed,
            path: authorityPath({ profile, gen: 0, seq: 1 }),
            alg: 'EdDSA',
          }).privateKey,
        ]),
      }
      expect(await summary([malformed])).toMatchObject({ applied: [], rejected: 1 })
    }
  })
})

describe('renewing a member', () => {
  test('another member renews: the lease is the maximum', async () => {
    const higher = await renew({ signer: signerB, target: memberA.add, lease: 2_000_000_000 })
    const lower = await renew({ signer: signerC, target: memberA.add, lease: 1_500_000_000 })
    const expected = await expectEveryOrder([higher, lower])
    expect(expected.rejected).toBe(0)
    expect((await folded([higher, lower])).head.members.get(memberA.add)?.lease).toBe(2_000_000_000)
    // A lower renewal alone never shortens the lease the add set.
    expect((await folded([lower])).head.members.get(memberA.add)?.lease).toBe(LEASE)
  })

  test('a member cannot renew itself', async () => {
    const self = await renew({ signer: signerA, target: memberA.add, lease: 2_000_000_000 })
    expect((await reasonsFor([self])).get(digest(self))).toBe(SELF_RENEW)
    expect((await folded([self])).head.members.get(memberA.add)?.lease).toBe(LEASE)
  })

  test('a member cannot renew itself, even through a second add of the same key', async () => {
    // Root adds K twice, concurrently: once as a did:key, once as the long-form peer carrying K.
    const addA = await add(d)
    const addB = await add({ did: peerDID(d.key), key: d.key })
    const signerK: EpochSigner = { member: { privateKey: d.privateKey, add: digest(addA) } }
    const renewal = await renew({
      signer: signerK,
      target: digest(addB),
      lease: 2_000_000_000,
      parents: [digest(addA), digest(addB)],
    })
    const log = { chain, events: [addA, addB, renewal] }
    expect((await rejectionsOf(did, log)).get(digest(renewal))).toBe(SELF_RENEW)
    // Control: another member renewing the alias, from the same parents, applies.
    const other = await renew({
      signer: signerB,
      target: digest(addB),
      lease: 2_000_000_000,
      parents: [digest(addA), digest(addB)],
    })
    expect((await rejectionsOf(did, { chain, events: [addA, addB, other] })).size).toBe(0)
  })

  test('a renewal of an incarnation unknown to its causal past is refused', async () => {
    const added = await add(d)
    for (const signer of [root, signerB]) {
      const concurrent = await renew({
        signer,
        target: digest(added),
        lease: 2_000_000_000,
      })
      expect((await reasonsFor([added, concurrent])).get(digest(concurrent))).toBe(UNKNOWN_MEMBER)
      const later = await renew({
        signer,
        target: digest(added),
        lease: 2_000_000_000,
        parents: [digest(added)],
      })
      expect((await reasonsFor([added, later])).size).toBe(0)
    }
  })
})

describe('removing a member', () => {
  test('a member cannot remove itself', async () => {
    const self = await remove(signerA, memberA.add)
    expect((await reasonsFor([self])).get(digest(self))).toBe(SELF_REMOVE)
    expect((await folded([self])).head.members.get(memberA.add)?.removed).toBe(false)
  })

  test('a member cannot remove itself through a second add of the same key', async () => {
    const addA = await add(d)
    const addB = await add({ did: peerDID(d.key), key: d.key })
    const signerK: EpochSigner = { member: { privateKey: d.privateKey, add: digest(addA) } }
    const removal = await remove(signerK, digest(addB), [digest(addA), digest(addB)])
    expect((await reasonsFor([addA, addB, removal])).get(digest(removal))).toBe(SELF_REMOVE)
  })

  test('a removal of an incarnation unknown to its causal past is refused', async () => {
    for (const signer of [root, signerB]) {
      const stranger = await remove(signer, digestOf('no such add'))
      expect((await reasonsFor([stranger])).get(digest(stranger))).toBe(UNKNOWN_MEMBER)
    }
  })

  test('a removal beats a concurrent renewal', async () => {
    const removal = await remove(signerB, memberA.add)
    const renewal = await renew({ signer: signerC, target: memberA.add, lease: 2_000_000_000 })
    const expected = await expectEveryOrder([removal, renewal])
    expect(expected.rejected).toBe(0)
    expect((await folded([removal, renewal])).head.members.get(memberA.add)).toMatchObject({
      lease: 2_000_000_000,
      removed: true,
      effective: false,
    })
  })

  test('mutual removal removes both members', async () => {
    const aRemovesB = await remove(signerA, memberB.add)
    const bRemovesA = await remove(signerB, memberA.add)
    const expected = await expectEveryOrder([aRemovesB, bRemovesA])
    expect(expected.rejected).toBe(0)
    const members = (await folded([aRemovesB, bRemovesA])).head.members
    expect(members.get(memberA.add)?.removed).toBe(true)
    expect(members.get(memberB.add)?.removed).toBe(true)
    expect(members.get(memberC.add)?.effective).toBe(true)
  })

  test('a removal cycle of three removes all three', async () => {
    const cycle = [
      await remove(signerA, memberB.add),
      await remove(signerB, memberC.add),
      await remove(signerC, memberA.add),
    ]
    const expected = await expectEveryOrder(cycle)
    expect(expected.rejected).toBe(0)
    for (const [, member] of expected.members) {
      expect(member).toMatchObject({ removed: true, effective: false })
    }
  })

  test('a removed member signs nothing in its causal future', async () => {
    const removal = await remove(signerB, memberA.add)
    const late = await renew({
      signer: signerA,
      target: memberC.add,
      lease: 2_000_000_000,
      parents: [digest(removal)],
    })
    expect((await reasonsFor([removal, late])).get(digest(late))).toBe(
      'signer was removed in the causal state',
    )
  })

  test('copying an honest event onto a hostile branch changes nothing', async () => {
    // Honest: A renews C. Hostile: B removes A, then tries to make A's renewal its own descendant.
    const honest = await renew({ signer: signerA, target: memberC.add, lease: 2_000_000_000 })
    const hostile = await remove(signerB, memberA.add)
    const expected = await summary([honest, hostile])
    expect(expected.rejected).toBe(0)
    // The same body is the same event wherever and however often it is presented: deduplicated.
    const recopied = { event: { ...honest.event }, sigs: [...honest.sigs] }
    const resigned = await signedBy(honest.event, b.privateKey)
    for (const order of permutations([honest, hostile, recopied, resigned])) {
      expect(await summary(order)).toEqual(expected)
    }
    // Re-parented under the removal, the body is a different event A never signed: refused alone,
    // and the honest original still stands.
    const rebased = { event: { ...honest.event, p: [digest(hostile)] }, sigs: honest.sigs }
    expect(await summary([honest, hostile, rebased])).toEqual({ ...expected, rejected: 1 })
  })

  test('a delayed renew or remove of an old add does not touch a re-add of the same key', async () => {
    const first = await add(d)
    const removal = await remove(root, digest(first), [digest(first)])
    const readd = await add({ ...d, lease: LEASE + 1 }, [digest(removal)])
    const delayedRenew = await renew({
      signer: signerB,
      target: digest(first),
      lease: 2_000_000_000,
      parents: [digest(first)],
    })
    const delayedRemove = await remove(signerC, digest(first), [digest(first)])
    const events = [first, removal, readd, delayedRenew, delayedRemove]
    const expected = await expectEveryOrder(events)
    expect(expected.rejected).toBe(0)
    const members = (await folded(events)).head.members
    expect(members.get(digest(readd))).toMatchObject({
      lease: LEASE + 1,
      removed: false,
      effective: true,
    })
    expect(members.get(digest(first))).toMatchObject({ lease: 2_000_000_000, removed: true })
    // Five events: 120 presentation orders, each a full signature-checking fold. CI took over 20 s.
  }, 30_000)
})

describe('revoking', () => {
  test('a member revoke of another member is refused, a root revoke of a member disables it', async () => {
    const peer = peerDID(d.key)
    const peerAdd = await add({ did: peer, key: d.key })
    const targets: Array<[string, string, Array<SignedEvent<EpochEvent>>]> = [
      ['its DID', memberB.did, []],
      ['its pinned key', keyTarget(memberB.key), []],
      ['the short form of its long-form peer DID', getPeer4ShortForm(peer), [peerAdd]],
      ['itself', memberA.did, []],
    ]
    for (const [label, target, before] of targets) {
      const parents = before.length === 0 ? [epoch] : before.map(digest)
      const refused = await revoke(signerA, target, parents)
      expect((await reasonsFor([...before, refused])).get(digest(refused)), label).toBe(
        MEMBER_REVOKES_MEMBER,
      )
    }
    const byRoot = await revoke(root, memberB.did)
    const result = await folded([byRoot])
    expect(result.rejected).toBe(0)
    expect(result.head.members.get(memberB.add)).toMatchObject({ removed: false, effective: false })
  })

  test('a member may not revoke a member of its causal past, even one already removed or denied', async () => {
    // Otherwise C removes B, A denies B's key on top, and root's later re-add of that key under
    // another DID is refused as denied: a member would have done what only root may.
    const removal = await remove(signerC, memberB.add)
    const denial = await revoke(root, memberB.did)
    for (const [label, before] of [
      ['removed', removal],
      ['denied', denial],
    ] as const) {
      for (const target of [memberB.did, keyTarget(memberB.key)]) {
        const revocation = await revoke(signerA, target, [digest(before)])
        expect((await reasonsFor([before, revocation])).get(digest(revocation)), label).toBe(
          MEMBER_REVOKES_MEMBER,
        )
      }
    }
    // The re-add the attack would have blocked: root admits B's key again, as a peer DID.
    const readd = await add({ did: peerDID(memberB.key), key: memberB.key }, [digest(removal)])
    expect((await reasonsFor([removal, readd])).size).toBe(0)
  })

  test('no signer may revoke a key the chain head publishes', async () => {
    for (const signer of [root, signerA]) {
      for (const key of [...head.keys, ...head.agreement]) {
        const refused = await revoke(signer, keyTarget(key))
        expect((await reasonsFor([refused])).get(digest(refused))).toBe(REVOKE_NAMES_ROOT_KEY)
      }
    }
  })

  test('a root add merged with a concurrent revoke of the same key yields no effective member', async () => {
    for (const signer of [root, signerA]) {
      for (const target of [keyTarget(d.key), d.did]) {
        const added = await add(d)
        const revocation = await revoke(signer, target)
        const expected = await expectEveryOrder([added, revocation])
        // Both kept: neither is refused for arriving second.
        expect(expected.rejected).toBe(0)
        expect(expected.applied).toHaveLength(2)
        expect((await folded([added, revocation])).head.members.get(digest(added))).toMatchObject({
          removed: false,
          effective: false,
        })
      }
    }
  })

  test('a denied member issues no further authorised events in its causal future but its concurrent events stand', async () => {
    const denial = await revoke(root, keyTarget(memberA.key))
    const late = await renew({
      signer: signerA,
      target: memberB.add,
      lease: 2_000_000_000,
      parents: [digest(denial)],
    })
    const concurrent = await renew({ signer: signerA, target: memberC.add, lease: 2_000_000_000 })
    const reasons = await reasonsFor([denial, late, concurrent])
    expect(reasons.get(digest(late))).toBe('signer is denied in the causal state')
    expect(reasons.has(digest(concurrent))).toBe(false)
    const members = (await folded([denial, late, concurrent])).head.members
    expect(members.get(memberC.add)?.lease).toBe(2_000_000_000)
    expect(members.get(memberB.add)?.lease).toBe(LEASE)
    expect(members.get(memberA.add)?.effective).toBe(false)
  })
})

describe('the fold-scoped denial matcher', () => {
  test('agrees with denialTargetsMember on every entry, asked any number of times', () => {
    const peer = peerDID(d.key)
    const members: Array<MemberEntry> = [memberA, { ...memberB, did: peer, key: d.key }]
    const entries = [
      memberA.did,
      keyTarget(memberA.key),
      peer,
      getPeer4ShortForm(peer),
      keyTarget(d.key),
      d.did,
      'did:peer:4zQm:zNotADocument',
      'did:key:z',
      'not a did',
      '',
    ]
    const matches = createDenialMatcher()
    for (let round = 0; round < 2; round++) {
      for (const entry of entries) {
        for (const member of members) {
          expect(matches(entry, member), `${entry} / ${member.did}`).toBe(
            denialTargetsMember(entry, member),
          )
        }
      }
    }
    // And the cases that matter are true: a short form denies its long-form member.
    expect(matches(getPeer4ShortForm(peer), at(members, 1))).toBe(true)
  })
})
