import { readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { HDKeyStore } from '@kokuin/deterministic'
import { createSigningIdentity, type MemberQuery, verifyToken } from '@kokuin/token'
import { ed25519 } from '@noble/curves/ed25519.js'
import { expect, test } from 'vitest'

import { checkGolden, type GoldenCase } from '../../../scripts/golden.ts'
import { digestOf } from '../src/canonical.ts'
import { authorityPath, deriveKeyPair } from '../src/derivation.ts'
import { createDeviceRevoke, deviceRevokeIndices } from '../src/device-revoke.ts'
import { foldEpochDetailed } from '../src/epoch.ts'
import { createAdd, createRemove, createRenew, createRevoke } from '../src/epoch-events.ts'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
  signEvent,
} from '../src/events.ts'
import { type FoldResult, foldLog, type KeyState } from '../src/fold.ts'
import { authoritativeLogWithin, createMemoryLogStore } from '../src/history.ts'
import { encodeKey } from '../src/keys.ts'
import type { ControllerLog } from '../src/log.ts'
import { createControllerResolverWithin } from '../src/resolver.ts'

// Golden vectors for the Rust port (`crates/kokuin-controller`). Every log here is built by the
// real TS builders from fixed seeds: the root from `seed` through the controller's own derivation,
// management devices from a `@kokuin/deterministic` HD key store. Each case names its `kind`, the
// function the Rust runner calls with `input`.

const file = fileURLToPath(new URL('./golden/controller.json', import.meta.url))
const CONTEXT = 'Controller resolver'
const seed = new Uint8Array(32).fill(1)
const profile = 0
const LEASE = 1_800_000_000

type Json = unknown
type Device = { did: string; key: string; privateKey: Uint8Array }

const devices = HDKeyStore.fromSeed({ seed: new Uint8Array(32).fill(9) })

async function device(name: string): Promise<Device> {
  const privateKey = await devices.entry(name).provideAsync()
  const publicKey = ed25519.getPublicKey(privateKey)
  return {
    did: createSigningIdentity({ privateKey }).id,
    key: encodeKey({ publicKey, alg: 'EdDSA' }),
    privateKey,
  }
}

function rootKey(gen: number, seq: number) {
  return deriveKeyPair({ seed, path: authorityPath({ profile, gen, seq }), alg: 'EdDSA' })
}

function rootEncoded(gen: number, seq: number): string {
  return encodeKey({ publicKey: rootKey(gen, seq).publicKey, alg: 'EdDSA' })
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function json<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function errorOf(error: unknown): Json {
  if (!(error instanceof Error)) throw error
  return { error: error.name, message: error.message }
}

function stateOf(state: KeyState): Json {
  return {
    did: state.did,
    gen: state.gen,
    seq: state.seq,
    keyGen: state.keyGen,
    keySeq: state.keySeq,
    keys: state.keys,
    agreement: state.agreement,
    next: state.next,
    recovery: state.recovery,
    deny: [...state.deny],
    members: [...state.members.values()].map((member) => {
      return {
        did: member.did,
        key: member.key,
        add: member.add,
        lease: member.lease,
        removed: member.removed,
        effective: member.effective,
      }
    }),
    tombstones: [...(state.tombstones?.values() ?? [])],
    epoch: state.epoch,
    saturated: state.saturated,
    digest: state.digest,
  }
}

function foldOf(result: FoldResult): Json {
  if (!result.ok) return { ok: false, reason: result.reason, index: result.index }
  return {
    ok: true,
    states: result.states.map(stateOf),
    head: stateOf(result.head),
    applied: result.applied,
    pending: result.pending,
    rejected: result.rejected,
  }
}

async function foldCase(name: string, did: string, log: ControllerLog): Promise<GoldenCase> {
  const input = json({ did, log })
  return {
    name,
    input: { kind: 'fold', ...input },
    expected: foldOf(await foldLog({ did: input.did, input: input.log })),
  }
}

type EpochInput = {
  did: string
  chain: Array<SignedEvent>
  events: Array<unknown>
  trusted?: Array<unknown>
  limits?: { MAX_EPOCH_EVENTS: number }
}

async function epochCase(name: string, params: EpochInput): Promise<GoldenCase> {
  const input = json(params)
  const chain = await foldLog({ did: input.did, input: { chain: input.chain, events: [] } })
  if (!chain.ok) throw new Error(`${name}: chain does not fold`)
  const detail = await foldEpochDetailed({
    did: input.did,
    chainStates: chain.states,
    events: input.events,
    trusted: input.trusted,
    limits: input.limits,
  })
  const expected = detail.ok
    ? {
        ok: true,
        head: stateOf(detail.head),
        applied: detail.applied,
        pending: detail.pending,
        rejected: detail.rejected,
        reasons: [...detail.reasons.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        authentic: [...detail.authentic.entries()].map(([digest, copy]) => [digest, copy.sigs]),
      }
    : { ok: false, reason: detail.reason }
  return { name, input: { kind: 'epoch', ...input }, expected }
}

type AuthoritativeInput = {
  did: string
  loaded: unknown
  seen?: ControllerLog
  limits?: { MAX_EPOCH_EVENTS: number }
}

async function authoritativeCase(name: string, params: AuthoritativeInput): Promise<GoldenCase> {
  const input = json(params)
  let expected: Json
  try {
    const settled = await authoritativeLogWithin(
      {
        did: input.did,
        loaded: input.loaded as ControllerLog,
        seen: input.seen,
        context: CONTEXT,
      },
      input.limits,
    )
    expected = { log: json(settled.log), result: foldOf(settled.result) }
  } catch (error) {
    expected = errorOf(error)
  }
  return { name, input: { kind: 'authoritative', ...input }, expected }
}

type ResolveCall =
  | { method: 'resolve' | 'resolveHistoric'; header: { kid?: unknown } }
  | { method: 'resolveDenySet' | 'resolveAgreementKey' }
  | { method: 'resolveMember' | 'resolveMemberHistoric'; member: MemberQuery }

type ResolveInput = {
  did: string
  logs: Record<string, unknown>
  seen?: ControllerLog
  limits?: { MAX_EPOCH_EVENTS: number }
  call: ResolveCall
}

async function resolveCase(name: string, params: ResolveInput): Promise<GoldenCase> {
  const input = json(params)
  const history = createMemoryLogStore()
  if (input.seen !== undefined) {
    const seen = input.seen
    await history.merge({ did: input.did, update: async () => seen })
  }
  const resolver = createControllerResolverWithin(
    {
      loadLog: async (did) => input.logs[did] as ControllerLog | undefined,
      history,
    },
    input.limits,
  )
  const { did, call } = input
  let expected: Json
  try {
    switch (call.method) {
      case 'resolve':
      case 'resolveHistoric': {
        const header = call.header as { kid?: string }
        const key =
          call.method === 'resolve'
            ? await resolver.resolve({ did, header })
            : await resolver.resolveHistoric?.({ did, header })
        if (key === undefined) throw new Error('resolveHistoric missing')
        expected = { alg: key.alg, publicKey: hex(key.publicKey) }
        break
      }
      case 'resolveDenySet': {
        const deny = await resolver.resolveDenySet?.(did)
        if (deny === undefined) throw new Error('resolveDenySet missing')
        expected = { deny: [...deny].sort() }
        break
      }
      case 'resolveAgreementKey': {
        const keys = await resolver.resolveAgreementKey?.(did)
        if (keys === undefined) throw new Error('resolveAgreementKey missing')
        expected = { keys: keys.map((key) => ({ alg: key.alg, publicKey: hex(key.publicKey) })) }
        break
      }
      case 'resolveMember': {
        const member = await resolver.resolveMember?.({ subject: did, member: call.member })
        if (member === undefined) throw new Error('resolveMember missing')
        expected = {
          key: { alg: member.key.alg, publicKey: hex(member.key.publicKey) },
          lease: member.lease,
        }
        break
      }
      case 'resolveMemberHistoric': {
        const member = await resolver.resolveMemberHistoric?.({
          subject: did,
          member: call.member,
        })
        if (member === undefined) throw new Error('resolveMemberHistoric missing')
        expected = {
          key: { alg: member.key.alg, publicKey: hex(member.key.publicKey) },
          lease: member.lease,
          removed: member.removed,
        }
        break
      }
    }
  } catch (error) {
    expected = errorOf(error)
  }
  return { name, input: { kind: 'resolve', ...input }, expected }
}

const b64u = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')

/** A compact token over fixed JSON, signed with `privateKey`: no clock-dependent claims. */
function signRaw(header: Record<string, unknown>, payload: unknown, privateKey: Uint8Array) {
  const data = `${b64u({ typ: 'JWT', alg: 'EdDSA', ...header })}.${b64u(payload)}`
  const signature = ed25519.sign(Buffer.from(data), privateKey)
  return `${data}.${Buffer.from(signature).toString('base64url')}`
}

type TokenInput = { token: string; logs: Record<string, unknown>; historic: boolean }

async function tokenCase(name: string, params: TokenInput): Promise<GoldenCase> {
  const input = json(params)
  const resolver = createControllerResolverWithin({
    loadLog: async (did) => input.logs[did] as ControllerLog | undefined,
  })
  let expected: Json
  try {
    const verified = await verifyToken({
      token: input.token,
      methods: [resolver],
      historic: input.historic,
    })
    expected = {
      verified: true,
      publicKey: hex(verified.verifiedPublicKey),
      payload: verified.payload,
    }
  } catch (error) {
    expected = errorOf(error)
  }
  return { name, input: { kind: 'token', ...input }, expected }
}

/** Sign `event` with `keys`: for bodies no builder writes (a malformed or unauthorised event). */
async function signed(event: unknown, keys: Array<Uint8Array>): Promise<SignedEvent> {
  return { event, sigs: await signEvent(event as never, keys) } as SignedEvent
}

async function controllerCases(): Promise<Array<GoldenCase>> {
  const cases: Array<GoldenCase> = []
  const empty = { members: [], deny: [] }
  const icp = await createInception({ seed, profile })
  const did = didFromInception(icp.event)
  const rot1 = await createRotate({ seed, profile, did, prior: icp.event, snapshot: empty })
  // Retires the inception key: a key-target denial the rest of the generation must keep.
  const rot2 = await createRotate({
    seed,
    profile,
    did,
    prior: rot1.event,
    snapshot: { members: [], deny: [keyTarget(rootEncoded(0, 0))] },
  })
  const reset = await createReset({ seed, profile, gen: 1 })
  const d1 = await device('1')
  const d2 = await device('2')
  const d3 = await device('3')

  // --- Genesis, rotation, reset -----------------------------------------------------------------
  cases.push(await foldCase('genesis: inception only', did, { chain: [icp], events: [] }))
  cases.push(
    await foldCase('rotation: two rotates retiring the inception key', did, {
      chain: [icp, rot1, rot2],
      events: [],
    }),
  )
  cases.push(
    await foldCase('reset: blind reset after two rotates', did, {
      chain: [icp, rot1, rot2, reset],
      events: [],
    }),
  )
  const other = await createInception({ seed: new Uint8Array(32).fill(2), profile })
  cases.push(
    await foldCase('genesis: inception of another DID', did, { chain: [other], events: [] }),
  )

  // --- Malformed and badly signed chain events --------------------------------------------------
  cases.push(await foldCase('chain: empty log', did, { chain: [], events: [] }))
  const malformedLog = { chain: 'x', events: [] } as unknown as ControllerLog
  cases.push(await foldCase('chain: malformed log', did, malformedLog))
  cases.push(
    await foldCase('chain: inception without signatures', did, {
      chain: [{ event: icp.event } as unknown as SignedEvent],
      events: [],
    }),
  )
  const flipped = (sig: string) =>
    `${sig.slice(0, 10)}${sig[10] === 'A' ? 'B' : 'A'}${sig.slice(11)}`
  cases.push(
    await foldCase('chain: rotate with a forged signature', did, {
      chain: [icp, { ...rot1, sigs: rot1.sigs.map(flipped) }],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: rotate signature with base64 padding', did, {
      chain: [icp, { ...rot1, sigs: rot1.sigs.map((sig) => `${sig}==`) }],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: rotate out of sequence', did, { chain: [icp, rot2], events: [] }),
  )
  const k01 = rootKey(0, 1)
  const noSnapshot = { ...rot1.event, m: undefined, d: undefined }
  cases.push(
    await foldCase('chain: rotate without a snapshot', did, {
      chain: [icp, await signed(json(noSnapshot), [k01.privateKey])],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: rotate denying the key it establishes', did, {
      chain: [
        icp,
        await signed(json({ ...rot1.event, d: [keyTarget(rootEncoded(0, 1))] }), [k01.privateKey]),
      ],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: snapshot member pinning a root key', did, {
      chain: [
        icp,
        await signed(
          json({
            ...rot1.event,
            m: [
              {
                did: createSigningIdentity({ privateKey: rootKey(0, 0).privateKey }).id,
                key: rootEncoded(0, 0),
                add: 'zAdd',
                lease: LEASE,
              },
            ],
          }),
          [k01.privateKey],
        ),
      ],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: snapshot member DID not carrying its key', did, {
      chain: [
        icp,
        await signed(
          json({ ...rot1.event, m: [{ did: d1.did, key: d2.key, add: 'zAdd', lease: LEASE }] }),
          [k01.privateKey],
        ),
      ],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: snapshot dropping a retired key denial', did, {
      chain: [
        icp,
        rot1,
        rot2,
        await createRotate({ seed, profile, did, prior: rot2.event, snapshot: empty }),
      ],
      events: [],
    }),
  )
  const unknown = (crit: unknown) =>
    json({ v: 1, t: 'zzz', i: did, g: 0, s: 1, p: digestOf(icp.event), crit })
  cases.push(
    await foldCase('chain: unknown critical event', did, {
      chain: [icp, { event: unknown(true), sigs: [] } as unknown as SignedEvent],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: unknown event without a criticality flag', did, {
      chain: [icp, { event: unknown(undefined), sigs: [] } as unknown as SignedEvent],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: unknown non-critical event is skipped', did, {
      chain: [icp, { event: unknown(false), sigs: [] } as unknown as SignedEvent, rot1],
      events: [],
    }),
  )
  cases.push(
    await foldCase('chain: event naming a different controller', did, {
      chain: [icp, { ...rot1, event: { ...rot1.event, i: other.event.k[0] } }],
      events: [],
    }),
  )

  // --- Device add and revoke: the epoch ---------------------------------------------------------
  const head0 = await foldLog({ did, input: { chain: [icp], events: [] } })
  if (!head0.ok) throw new Error('inception does not fold')
  const base = { did, head: head0.head }
  const add = (member: Device, parents: Array<string>) =>
    createAdd({
      ...base,
      parents,
      seed,
      profile,
      member: { did: member.did, key: member.key, lease: LEASE },
    })
  const epoch0 = head0.head.epoch
  const add1 = await add(d1, [epoch0])
  const add2 = await add(d2, [epoch0])
  const add3 = await add(d3, [epoch0])
  const [a1, a2, a3] = [add1, add2, add3].map((event) => digestOf(event.event)) as [
    string,
    string,
    string,
  ]
  const root = { root: { seed, profile } }
  const asD1 = { member: { privateKey: d1.privateKey, add: a1 } }
  const rev2 = await createRevoke({ ...base, parents: [a1, a2], signer: root, target: d2.did })
  const renew2 = await createRenew({
    ...base,
    parents: [a1, a2],
    signer: asD1,
    add: a2,
    lease: LEASE + 10,
  })
  const remove3 = await createRemove({ ...base, parents: [a1, a3], signer: asD1, add: a3 })
  const revKey = await createRevoke({
    ...base,
    parents: [epoch0],
    signer: root,
    target: keyTarget('zSomeRetiredKey'),
  })
  const deviceEvents = [add1, add2, add3, rev2, renew2, remove3, revKey]
  cases.push(
    await epochCase('epoch: device adds, renew, remove and revoke', {
      did,
      chain: [icp],
      events: deviceEvents,
    }),
  )
  cases.push(
    await epochCase('epoch: presentation order and duplicates do not matter', {
      did,
      chain: [icp],
      events: [...deviceEvents].reverse().concat([add1, rev2]),
    }),
  )
  cases.push(
    await foldCase('fold: chain with the device epoch', did, {
      chain: [icp],
      events: deviceEvents,
    }),
  )

  // Refusals, one per rule, each with its reason.
  const selfRenew = await createRenew({
    ...base,
    parents: [a1],
    signer: asD1,
    add: a1,
    lease: LEASE + 1,
  })
  const selfRemove = await createRemove({ ...base, parents: [a1], signer: asD1, add: a1 })
  const memberRevokes = await createRevoke({
    ...base,
    parents: [a1, a2],
    signer: asD1,
    target: d2.did,
  })
  const unknownTarget = await createRenew({
    ...base,
    parents: [a1],
    signer: asD1,
    add: 'zNobody',
    lease: LEASE,
  })
  const memberAdd = await signed(
    json({
      v: 1,
      t: 'add',
      i: did,
      g: 0,
      e: epoch0,
      p: [a1],
      crit: true,
      by: a1,
      did: d3.did,
      key: d3.key,
      lease: LEASE,
    }),
    [d1.privateKey],
  )
  const rootKeyAdd = await add(
    {
      did: createSigningIdentity({ privateKey: rootKey(0, 0).privateKey }).id,
      key: rootEncoded(0, 0),
      privateKey: rootKey(0, 0).privateKey,
    },
    [epoch0],
  )
  const committedKeyAdd = await add(
    {
      did: createSigningIdentity({ privateKey: rootKey(0, 1).privateKey }).id,
      key: rootEncoded(0, 1),
      privateKey: rootKey(0, 1).privateKey,
    },
    [epoch0],
  )
  const mismatchAdd = await add({ ...d1, key: d2.key }, [epoch0])
  const duplicateAdd = await createAdd({
    ...base,
    parents: [a1],
    seed,
    profile,
    member: { did: d1.did, key: d1.key, lease: LEASE + 5 },
  })
  const deniedAdd = await createAdd({
    ...base,
    parents: [digestOf(rev2.event)],
    seed,
    profile,
    member: { did: d2.did, key: d2.key, lease: LEASE },
  })
  const revokeRootKey = await createRevoke({
    ...base,
    parents: [epoch0],
    signer: root,
    target: keyTarget(rootEncoded(0, 0)),
  })
  const forged = { ...add3, sigs: add3.sigs.map(flipped) }
  const strangerSigned = await createRenew({
    ...base,
    parents: [a1],
    signer: { member: { privateKey: d3.privateKey, add: a1 } },
    add: a2,
    lease: LEASE,
  })
  const notMember = await createRenew({
    ...base,
    parents: [epoch0],
    signer: { member: { privateKey: d1.privateKey, add: 'zNotAnAdd' } },
    add: a1,
    lease: LEASE,
  })
  const otherGeneration = json({ ...add1, event: { ...add1.event, g: 7 } })
  const otherController = json({ ...add1, event: { ...add1.event, i: 'did:kokuin:zElse' } })
  const missingParent = await createRevoke({
    ...base,
    parents: ['zMissingParent'],
    signer: root,
    target: 'did:key:zGone',
  })
  const pendingChild = await createRevoke({
    ...base,
    parents: [digestOf(missingParent.event)],
    signer: root,
    target: 'did:key:zGoneToo',
  })
  cases.push(
    await epochCase('epoch: refusals and their reasons', {
      did,
      chain: [icp],
      events: [
        add1,
        add2,
        rev2,
        selfRenew,
        selfRemove,
        memberRevokes,
        unknownTarget,
        memberAdd,
        rootKeyAdd,
        committedKeyAdd,
        mismatchAdd,
        duplicateAdd,
        deniedAdd,
        revokeRootKey,
        forged,
        strangerSigned,
        notMember,
        otherGeneration,
        otherController,
        missingParent,
        pendingChild,
        { event: { t: 'add' }, sigs: [] },
        'not an event',
        { ...add1, recoveryKey: 'zKey' },
      ],
    }),
  )

  // --- Epoch transitions ------------------------------------------------------------------------
  const epochHead = await foldLog({ did, input: { chain: [icp], events: [add1, add2, rev2] } })
  if (!epochHead.ok) throw new Error('device epoch does not fold')
  const settle = await createRotate({
    seed,
    profile,
    did,
    prior: icp.event,
    snapshot: {
      members: [...epochHead.head.members.values()].map(({ did, key, add, lease }) => {
        return { did, key, add, lease }
      }),
      deny: [...epochHead.head.deny],
    },
  })
  const head1 = await foldLog({ did, input: { chain: [icp, settle], events: [] } })
  if (!head1.ok) throw new Error('settlement does not fold')
  const nextEpochRevoke = await createRevoke({
    did,
    head: head1.head,
    parents: [head1.head.epoch],
    signer: { member: { privateKey: d1.privateKey, add: a1 } },
    target: 'did:key:zEdgeHolder',
  })
  const crossParent = await createRevoke({
    did,
    head: head1.head,
    parents: [epoch0],
    signer: root,
    target: 'did:key:zCross',
  })
  cases.push(
    await epochCase('epoch transition: settlement carries the epoch, old events are ignored', {
      did,
      chain: [icp, settle],
      events: [add3, rev2, nextEpochRevoke, crossParent],
    }),
  )
  cases.push(
    await foldCase('epoch transition: fold of the settled chain', did, {
      chain: [icp, settle],
      events: [nextEpochRevoke, add3],
    }),
  )
  const resetWithSnapshot = await createReset({
    seed,
    profile,
    gen: 1,
    snapshot: { members: [{ did: d1.did, key: d1.key, add: a1, lease: LEASE }], deny: [d2.did] },
  })
  cases.push(
    await foldCase('epoch transition: reset carrying a snapshot', did, {
      chain: [icp, settle, resetWithSnapshot],
      events: [nextEpochRevoke],
    }),
  )

  // --- Saturation and request limits ------------------------------------------------------------
  const limits = { MAX_EPOCH_EVENTS: 2 }
  cases.push(
    await epochCase('saturation: three applied events over a limit of two', {
      did,
      chain: [icp],
      events: [add1, add2, add3],
      limits,
    }),
  )
  cases.push(
    await epochCase('saturation: two applied events at a limit of two', {
      did,
      chain: [icp],
      events: [add1, add2],
      limits,
    }),
  )
  const bogus = Array.from({ length: 65 }, (_, index) => {
    const sig = new Uint8Array(64)
    sig[0] = index
    return { ...add1, sigs: [Buffer.from(sig).toString('base64url')] }
  })
  cases.push(
    await foldCase('request limit: too many failed signatures', did, {
      chain: [icp],
      events: bogus,
    }),
  )
  cases.push(
    await foldCase('request limit: sixty-four failed signatures still fold', did, {
      chain: [icp],
      events: bogus.slice(0, 64).concat([add1]),
    }),
  )
  const logs = (log: ControllerLog) => ({ [did]: log })
  const saturatedLog = { chain: [icp], events: [add1, add2, add3] }
  for (const method of ['resolve', 'resolveHistoric'] as const) {
    cases.push(
      await resolveCase(`saturation: ${method} refuses`, {
        did,
        logs: logs(saturatedLog),
        limits,
        call: { method, header: {} },
      }),
    )
  }
  cases.push(
    await resolveCase('saturation: resolveDenySet refuses', {
      did,
      logs: logs(saturatedLog),
      limits,
      call: { method: 'resolveDenySet' },
    }),
  )
  cases.push(
    await authoritativeCase('saturation: remembered log keeps limit plus one events', {
      did,
      loaded: { chain: [icp], events: [add1, add2, add3, rev2] },
      limits,
    }),
  )

  // --- History: truncation, forks, resets -------------------------------------------------------
  cases.push(
    await authoritativeCase('history: truncated chain is refused', {
      did,
      loaded: { chain: [icp, rot1], events: [] },
      seen: { chain: [icp, rot1, rot2], events: [] },
    }),
  )
  cases.push(
    await authoritativeCase('history: extending chain is accepted', {
      did,
      loaded: { chain: [icp, rot1, rot2], events: [] },
      seen: { chain: [icp, rot1], events: [] },
    }),
  )
  cases.push(
    await authoritativeCase('history: withheld epoch revoke is remembered', {
      did,
      loaded: { chain: [icp], events: [add1] },
      seen: { chain: [icp], events: [add1, add2, rev2] },
    }),
  )
  const rot1Fork = await createRotate({
    seed,
    profile,
    did,
    prior: icp.event,
    snapshot: { members: [], deny: ['did:key:zFork'] },
  })
  cases.push(
    await authoritativeCase('history: fork is refused', {
      did,
      loaded: { chain: [icp, rot1Fork], events: [] },
      seen: { chain: [icp, rot1], events: [] },
    }),
  )
  cases.push(
    await authoritativeCase('history: reset outranks a longer chain', {
      did,
      loaded: { chain: [icp, reset], events: [] },
      seen: { chain: [icp, rot1, rot2], events: [add1] },
    }),
  )
  cases.push(
    await authoritativeCase('history: stale chain under a reset is refused', {
      did,
      loaded: { chain: [icp, rot1, rot2], events: [] },
      seen: { chain: [icp, reset], events: [] },
    }),
  )
  cases.push(
    await authoritativeCase('history: first encounter', {
      did,
      loaded: { chain: [icp, rot1], events: [add1, 'junk'] },
    }),
  )
  cases.push(
    await authoritativeCase('history: malformed loaded log', {
      did,
      loaded: { chain: 'x', events: [] },
    }),
  )
  cases.push(
    await authoritativeCase('history: loaded chain that does not fold', {
      did,
      loaded: { chain: [icp, rot2], events: [] },
    }),
  )
  cases.push(
    await resolveCase('history: resolver refuses a truncated log', {
      did,
      logs: logs({ chain: [icp, rot1], events: [] }),
      seen: { chain: [icp, rot1, rot2], events: [] },
      call: { method: 'resolve', header: {} },
    }),
  )
  cases.push(
    await resolveCase('history: resolver answers a withheld revoke from memory', {
      did,
      logs: logs({ chain: [icp], events: [add1] }),
      seen: { chain: [icp], events: [add1, add2, rev2] },
      call: { method: 'resolveDenySet' },
    }),
  )

  // --- Resolver members -------------------------------------------------------------------------
  const rotated = { chain: [icp, rot1, rot2], events: [] }
  const kid = (key: string) => ({ kid: `#${key}` })
  const resolveCalls: Array<[string, ControllerLog, ResolveCall]> = [
    ['resolve: head key without kid', rotated, { method: 'resolve', header: {} }],
    ['resolve: head key by kid', rotated, { method: 'resolve', header: kid(rootEncoded(0, 2)) }],
    [
      'resolve: rotated-away key is not current',
      rotated,
      { method: 'resolve', header: kid(rootEncoded(0, 1)) },
    ],
    [
      'resolveHistoric: rotated-away key',
      rotated,
      { method: 'resolveHistoric', header: kid(rootEncoded(0, 1)) },
    ],
    [
      'resolveHistoric: revoked key',
      rotated,
      { method: 'resolveHistoric', header: kid(rootEncoded(0, 0)) },
    ],
    [
      'resolveHistoric: key of a superseded generation',
      { chain: [icp, rot1, reset], events: [] },
      { method: 'resolveHistoric', header: kid(rootEncoded(0, 1)) },
    ],
    [
      'resolve: kid without fragment',
      rotated,
      { method: 'resolve', header: { kid: rootEncoded(0, 2) } },
    ],
    ['resolve: non-string kid', rotated, { method: 'resolve', header: { kid: 7 } }],
    ['resolveDenySet: chain and epoch denials', rotated, { method: 'resolveDenySet' }],
    [
      'resolveDenySet: epoch denials',
      { chain: [icp], events: deviceEvents },
      { method: 'resolveDenySet' },
    ],
    ['resolveAgreementKey: head agreement key', rotated, { method: 'resolveAgreementKey' }],
  ]
  const deviceLog = { chain: [icp], events: deviceEvents }
  const member = (who: Device, addDigest: string, gen = 0): MemberQuery => {
    return { did: who.did, add: addDigest, gen }
  }
  resolveCalls.push(
    [
      'resolveMember: effective member',
      deviceLog,
      { method: 'resolveMember', member: member(d1, a1) },
    ],
    [
      'resolveMember: denied member',
      deviceLog,
      { method: 'resolveMember', member: member(d2, a2) },
    ],
    [
      'resolveMember: removed member',
      deviceLog,
      { method: 'resolveMember', member: member(d3, a3) },
    ],
    [
      'resolveMember: another generation',
      deviceLog,
      { method: 'resolveMember', member: member(d1, a1, 1) },
    ],
    [
      'resolveMember: incarnation of another DID',
      deviceLog,
      { method: 'resolveMember', member: member(d3, a1) },
    ],
    [
      'resolveMember: unknown incarnation',
      deviceLog,
      { method: 'resolveMember', member: member(d1, 'zNoSuchAdd') },
    ],
    [
      'resolveMemberHistoric: effective member',
      deviceLog,
      { method: 'resolveMemberHistoric', member: member(d1, a1) },
    ],
    [
      'resolveMemberHistoric: removed member',
      deviceLog,
      { method: 'resolveMemberHistoric', member: member(d3, a3) },
    ],
    [
      'resolveMemberHistoric: denied member',
      deviceLog,
      { method: 'resolveMemberHistoric', member: member(d2, a2) },
    ],
    [
      'resolveMemberHistoric: tombstoned member after a settlement',
      {
        chain: [
          icp,
          await createRotate({
            seed,
            profile,
            did,
            prior: icp.event,
            snapshot: {
              members: [{ did: d1.did, key: d1.key, add: a1, lease: LEASE }],
              removed: [{ did: d3.did, key: d3.key, add: a3, lease: LEASE }],
              deny: [],
            },
          }),
        ],
        events: [],
      },
      { method: 'resolveMemberHistoric', member: member(d3, a3) },
    ],
  )
  for (const [name, log, call] of resolveCalls) {
    cases.push(await resolveCase(name, { did, logs: logs(log), call }))
  }
  cases.push(
    await resolveCase('resolve: unknown DID', {
      did: 'did:kokuin:zUnknown',
      logs: logs(rotated),
      call: { method: 'resolve', header: {} },
    }),
  )
  cases.push(
    await resolveCase('resolve: empty chain is an unknown DID', {
      did,
      logs: logs({ chain: [], events: [] }),
      call: { method: 'resolve', header: {} },
    }),
  )
  cases.push(
    await resolveCase('resolve: log that does not fold', {
      did,
      logs: logs({ chain: [icp, rot2], events: [] }),
      call: { method: 'resolve', header: {} },
    }),
  )

  // --- Tokens issued by the did:kokuin controller -----------------------------------------------
  const payload = { iss: did, sub: did, hello: 'world' }
  const tokenAt = (
    gen: number,
    seq: number,
    header: Record<string, unknown> = kid(rootEncoded(gen, seq)),
  ) => signRaw(header, payload, rootKey(gen, seq).privateKey)
  const tokens: Array<[string, string, ControllerLog, boolean]> = [
    ['token: current key verifies', tokenAt(0, 2), rotated, false],
    ['token: current key without kid verifies', tokenAt(0, 2, {}), rotated, false],
    ['token: rotated-away key is refused live', tokenAt(0, 1), rotated, false],
    ['token: rotated-away key verifies historic', tokenAt(0, 1), rotated, true],
    ['token: revoked device key is refused historic', tokenAt(0, 0), rotated, true],
    [
      'token: key of a superseded generation is refused',
      tokenAt(0, 1),
      { chain: [icp, rot1, reset], events: [] },
      true,
    ],
    [
      'token: wrong signing key under a current kid',
      signRaw(kid(rootEncoded(0, 2)), payload, rootKey(0, 1).privateKey),
      rotated,
      false,
    ],
    [
      'token: inception key verifies at genesis',
      tokenAt(0, 0),
      { chain: [icp], events: [] },
      false,
    ],
  ]
  for (const [name, token, log, historic] of tokens) {
    cases.push(await tokenCase(name, { token, logs: logs(log), historic }))
  }

  // --- Root-chain device revocation -------------------------------------------------------------
  const deviceRevoke = await createDeviceRevoke({
    seed,
    profile,
    did,
    chain: [icp],
    subject: d1.did,
  })
  const afterRevoke = await createRotate({
    seed,
    profile,
    did,
    prior: deviceRevoke.event,
    snapshot: { members: [], deny: [d1.did] },
  })
  const cleared = await createRotate({
    seed,
    profile,
    did,
    prior: afterRevoke.event,
    snapshot: empty,
  })
  const again = await createDeviceRevoke({
    seed,
    profile,
    did,
    chain: [icp, deviceRevoke, afterRevoke, cleared],
    subject: d1.did,
  })
  for (const [name, chain] of [
    ['device revoke: first revoke', [icp, deviceRevoke, afterRevoke]],
    [
      'device revoke: revoked, cleared and revoked again',
      [icp, deviceRevoke, afterRevoke, cleared, again],
    ],
    ['device revoke: invalid chain', [icp, rot2]],
  ] as Array<[string, Array<SignedEvent>]>) {
    const input = json({ did, chain, subject: d1.did })
    cases.push({
      name,
      input: { kind: 'deviceRevoke', ...input },
      expected: await deviceRevokeIndices(input),
    })
  }
  expect(cases.length).toBeGreaterThan(60)
  return cases
}

test('golden: controller fold and did:kokuin resolution', async () => {
  checkGolden(file, await controllerCases())
})

test.skipIf(process.env.UPDATE_GOLDEN === '1')(
  'golden: verification does not write the vector file',
  async () => {
    const before = { content: readFileSync(file, 'utf8'), mtime: statSync(file).mtimeMs }
    checkGolden(file, await controllerCases())
    expect(readFileSync(file, 'utf8')).toBe(before.content)
    expect(statSync(file).mtimeMs).toBe(before.mtime)
  },
)
