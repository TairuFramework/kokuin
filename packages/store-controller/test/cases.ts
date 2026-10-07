import type { Adapter } from '@hozon/adapter'
import { HozonDB } from '@hozon/db'
import {
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  decodeKey,
  didFromInception,
  foldLog,
  keyTarget,
  LOG_FORKED,
  LOG_NOT_AUTHORITATIVE,
  type SignedEvent,
} from '@kokuin/controller'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'

import {
  type ControllerStoreAPI,
  controllerStoreDefinition,
  getControllerStore,
} from '../src/index.js'

export type StoreHarness = {
  name: string
  createAdapter(): Promise<Adapter>
  cleanup(): Promise<void>
}

const seed = new Uint8Array(32).fill(1)

// Inception then a rotate, so the head signing key is not the inception key --
// resolving to the head is then observably different from resolving to `keys[0]`
// of the first event.
function buildRotatedLog(logSeed: Uint8Array = seed) {
  const icp = createInception(logSeed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate({ seed: logSeed, profile: 0, did, prior: icp.event })
  const headKeyEncoded = rot.event.k[0]
  const inceptionKeyEncoded = icp.event.k[0]
  if (headKeyEncoded == null || inceptionKeyEncoded == null) {
    throw new Error('expected inception and rotate keys')
  }
  return {
    did,
    log: [icp, rot] as Array<SignedEvent>,
    headKey: decodeKey(headKeyEncoded).publicKey,
    inceptionKey: decodeKey(inceptionKeyEncoded).publicKey,
  }
}

// `resolveDenySet` is optional on the resolver interface; every controller resolver publishes one.
async function denySet(
  resolver: { resolveDenySet?: (did: string) => Promise<ReadonlySet<string>> },
  did: string,
): Promise<ReadonlySet<string>> {
  if (resolver.resolveDenySet == null) {
    throw new Error('resolver publishes no deny set')
  }
  return await resolver.resolveDenySet(did)
}

// `[icp, rot, rev]` where `rev` denies the inception key the rotate retired. A `rev` cannot deny a
// key the head still publishes, so the rotate must retire it first -- then the head deny set carries
// `#<retired key>`, the key-target spelling a reader matches rather than enumerates. The truncated
// prefix `[icp, rot]` folds cleanly and its deny set is missing exactly that entry.
function buildRevokedLog(revokedSeed: Uint8Array) {
  const icp = createInception(revokedSeed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate({ seed: revokedSeed, profile: 0, did, prior: icp.event })
  const retiredKey = icp.event.k[0]
  if (retiredKey == null) throw new Error('expected an inception key')
  const denyEntry = keyTarget(retiredKey)
  const rev = createRevoke({
    seed: revokedSeed,
    profile: 0,
    did,
    prior: rot.event,
    target: denyEntry,
    // The active authority key still sits where the rotate put it, gen 0 / seq 1.
    keyPosition: { gen: 0, seq: 1 },
  })
  return {
    did,
    icp,
    rot,
    rev,
    denyEntry,
    full: [icp, rot, rev] as Array<SignedEvent>,
    truncated: [icp, rot] as Array<SignedEvent>,
  }
}

function headDeny(did: string, log: Array<SignedEvent>): ReadonlySet<string> {
  const folded = foldLog(did, log)
  if (!folded.ok) {
    throw new Error(`log did not fold: ${folded.reason}`)
  }
  const head = folded.states[folded.states.length - 1]
  if (head == null) throw new Error('expected a folded head state')
  return head.deny
}

// Distinct seeds so each scenario resolves a distinct DID and the shared persistent store keeps
// their histories apart.
const TRUNCATION_SEED = new Uint8Array(32).fill(2)
const FORK_SEED = new Uint8Array(32).fill(3)
const OBSERVED_SEED = new Uint8Array(32).fill(4)
const OVERWRITE_SEED = new Uint8Array(32).fill(9)

/**
 * Registers the controller store conformance tests. Call inside a `describe`.
 * Every physical name is derived from `options.tablePrefix`, and the cases run
 * on any adapter.
 */
export function controllerStoreCases(
  harness: StoreHarness,
  options: { tablePrefix?: string } = {},
): void {
  const { tablePrefix } = options
  let db: HozonDB
  let store: ControllerStoreAPI

  beforeAll(async () => {
    db = new HozonDB({ adapter: await harness.createAdapter(), tablePrefix })
    db.register(controllerStoreDefinition)
    store = await getControllerStore(db)
  }, 60_000)

  afterAll(async () => {
    await db?.close()
    await harness.cleanup()
  })

  test('registers and round-trips a stored log', async () => {
    const { did, log } = buildRotatedLog()
    await store.set(did, log)
    expect(await store.get(did)).toEqual(log)
  })

  test('resolves the head signing key through the store', async () => {
    const { did, log, headKey, inceptionKey } = buildRotatedLog()
    await store.set(did, log)

    const resolver = createControllerResolver({
      loadLog: (loadDID) => store.get(loadDID),
      history: store,
    })
    const resolved = await resolver.resolve(did, {})

    expect(resolved.alg).toBe('EdDSA')
    expect(resolved.publicKey).toEqual(headKey)
    // Head, not inception: an implementation reading `keys[0]` of the first
    // event would answer with the retired key and fail here.
    expect(resolved.publicKey).not.toEqual(inceptionKey)
  })

  test('get returns undefined for an unknown DID', async () => {
    expect(await store.get('did:kokuin:unknown')).toBeUndefined()
  })

  test('set is plain last-writer-wins: a shorter later log overwrites a longer stored one', async () => {
    // Distinct seed so this DID does not collide with the other tests in the
    // shared store.
    const icp = createInception(OVERWRITE_SEED, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate({ seed: OVERWRITE_SEED, profile: 0, did, prior: icp.event })
    const long = [icp, rot] as Array<SignedEvent>
    const short = [icp] as Array<SignedEvent>

    await store.set(did, long)
    expect(await store.get(did)).toEqual(long)

    // The store never blocks a "backwards" write: supersession (e.g. a recovery
    // rotate at a low sequence) legitimately lowers length, so a high-water-mark
    // store would brick a rescue. Arbitration is the resolver's job, not the
    // store's -- this is the store's defining behavior.
    await store.set(did, short)
    expect(await store.get(did)).toEqual(short)
  })

  test('resolve rejects an unknown DID', async () => {
    const resolver = createControllerResolver({
      loadLog: (loadDID) => store.get(loadDID),
      history: store,
    })
    await expect(resolver.resolve('did:kokuin:unknown', {})).rejects.toThrow(/Unknown DID/)
  })

  test('getObservedAt returns a Date after insert and after update', async () => {
    const { did, log } = buildRotatedLog(OBSERVED_SEED)
    expect(await store.getObservedAt(did)).toBeUndefined()

    await store.set(did, log)
    const first = await store.getObservedAt(did)
    expect(first).toBeInstanceOf(Date)
    expect(Math.abs((first as Date).getTime() - Date.now())).toBeLessThan(5_000)

    await store.set(did, log.slice(0, 1))
    const second = await store.getObservedAt(did)
    expect(second).toBeInstanceOf(Date)
    expect((second as Date).getTime()).toBeGreaterThanOrEqual((first as Date).getTime())
  })

  describe('resolver anti-truncation guard', () => {
    test('the full log folds with K denied and the truncated prefix does not -- the setup is meaningful', () => {
      const { did, denyEntry, full, truncated } = buildRevokedLog(TRUNCATION_SEED)
      expect(headDeny(did, full).has(denyEntry)).toBe(true)
      // The dangerous shape the guard must catch: a clean fold that simply lacks the revoke.
      expect(headDeny(did, truncated).has(denyEntry)).toBe(false)
    })

    test('a truncated prefix is refused after the full log was accepted into the persistent store', async () => {
      const { did, denyEntry, full, truncated } = buildRevokedLog(TRUNCATION_SEED)

      let served: Array<SignedEvent> = full
      const resolver = createControllerResolver({
        loadLog: async () => served,
        history: store,
      })

      // Accept once: the resolver folds the full log and writes it to the store itself.
      expect([...(await denySet(resolver, did))]).toEqual([denyEntry])
      expect(await store.get(did)).toEqual(full)

      // Attack: the peer now serves the prefix stopping just before the revoke. It folds and verifies,
      // but loses to the log already seen, so it is refused rather than answered from.
      served = truncated
      await expect(denySet(resolver, did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
      // The refusal is the proof it never answered a deny set missing K; the store did not move back.
      expect(await store.get(did)).toEqual(full)
    })

    test('DANGEROUS BASELINE -- with no history the same prefix is answered, K missing from the deny set', async () => {
      const { did, denyEntry, truncated } = buildRevokedLog(TRUNCATION_SEED)

      // No `history`, so nothing to compare against: the prefix is taken at face value. This is the
      // silent revocation bypass the guard closes, isolating the history comparison as what bites.
      const resolver = createControllerResolver({ loadLog: async () => truncated })
      const set = await denySet(resolver, did)
      expect(set.has(denyEntry)).toBe(false)
      expect(set.size).toBe(0)
    })

    test('a genuine fork is refused after the full log was accepted', async () => {
      const { did, icp, rot, full } = buildRevokedLog(FORK_SEED)
      // A rival revoke at the same position as the accepted log's revoke: two current-key events, no
      // rotate to settle them, so branch resolution reports duplicity -- a fork, not a truncation.
      const rival = createRevoke({
        seed: FORK_SEED,
        profile: 0,
        did,
        prior: rot.event,
        target: 'did:key:z6MkForkRivalDeviceDidHere00000000000000000',
        keyPosition: { gen: 0, seq: 1 },
      })
      const fork = [icp, rot, rival] as Array<SignedEvent>

      let served: Array<SignedEvent> = full
      const resolver = createControllerResolver({
        loadLog: async () => served,
        history: store,
      })

      await denySet(resolver, did)
      expect(await store.get(did)).toEqual(full)

      served = fork
      await expect(denySet(resolver, did)).rejects.toThrow(LOG_FORKED)
      expect(await store.get(did)).toEqual(full)
    })
  })
}
