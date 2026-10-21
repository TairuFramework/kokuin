import type { Adapter } from '@hozon/adapter'
import { HozonDB, type Kysely } from '@hozon/db'
import {
  type ControllerLog,
  createAdd,
  createControllerResolver,
  createInception,
  createRotate,
  decodeKey,
  didFromInception,
  type EpochEvent,
  foldLog,
  keyTarget,
  LOG_FORKED,
  LOG_NOT_AUTHORITATIVE,
  type SignedEvent,
} from '@kokuin/controller'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'

import {
  type ControllerStoreAPI,
  type ControllerStoreTables,
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
  const rot = createRotate({
    seed: logSeed,
    profile: 0,
    did,
    prior: icp.event,
    options: { snapshot: { members: [], deny: [] } },
  })
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

// `[icp, rot, rev]` where `rev` is a second rotate whose snapshot denies the inception key the first
// rotate retired, so the head deny set carries `#<retired key>`, the key-target spelling a reader
// matches rather than enumerates. The truncated prefix `[icp, rot]` folds cleanly and its deny set is
// missing exactly that entry.
function buildRevokedLog(revokedSeed: Uint8Array) {
  const icp = createInception(revokedSeed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate({
    seed: revokedSeed,
    profile: 0,
    did,
    prior: icp.event,
    options: { snapshot: { members: [], deny: [] } },
  })
  const retiredKey = icp.event.k[0]
  if (retiredKey == null) throw new Error('expected an inception key')
  const denyEntry = keyTarget(retiredKey)
  const rev = createRotate({
    seed: revokedSeed,
    profile: 0,
    did,
    prior: rot.event,
    options: { snapshot: { members: [], deny: [denyEntry] } },
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

function chainOnly(chain: Array<SignedEvent>): ControllerLog {
  return { chain, events: [] }
}

function headDeny(did: string, log: Array<SignedEvent>): ReadonlySet<string> {
  const folded = foldLog(did, { chain: log, events: [] })
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
const RACE_SEED = new Uint8Array(32).fill(10)
const FIRST_RACE_SEED = new Uint8Array(32).fill(11)
const THROW_SEED = new Uint8Array(32).fill(13)
const LEGACY_SEED = new Uint8Array(32).fill(12)
const UNCHANGED_SEED = new Uint8Array(32).fill(14)
const RESOLVED_SEED = new Uint8Array(32).fill(15)

// An epoch event admitting a member named `name`, rooted at the log's head. The store never verifies
// events, so these only need to be distinct, well-formed entries.
function buildAdd(did: string, log: Array<SignedEvent>, logSeed: Uint8Array, name: string) {
  const folded = foldLog(did, { chain: log, events: [] })
  if (!folded.ok) throw new Error(`log did not fold: ${folded.reason}`)
  const head = folded.states[folded.states.length - 1]
  const key = head?.keys[0]
  if (head == null || key == null) throw new Error('expected a folded head state')
  return createAdd({
    did,
    head,
    parents: ['epoch'],
    seed: logSeed,
    profile: 0,
    member: { did: `did:key:${name}`, key, lease: 1_000 },
  })
}

function memberNames(log: ControllerLog | undefined): Array<string> {
  return (log?.events ?? [])
    .map((signed) => (signed.event as Extract<EpochEvent, { t: 'add' }>).did)
    .sort()
}

// Appends `event` to whatever the store holds, yielding to the event loop between the read and the
// result so a store that does not serialise `merge` lets a concurrent one read the same row.
function appendEvent(
  base: Array<SignedEvent>,
  event: SignedEvent<EpochEvent>,
): (current: ControllerLog | undefined) => Promise<ControllerLog> {
  return async (current) => {
    await new Promise((resolve) => setTimeout(resolve, 5))
    return { chain: current?.chain ?? base, events: [...(current?.events ?? []), event] }
  }
}

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
  let adapter: Adapter
  let rows: Kysely<ControllerStoreTables>

  // Write a chain as the whole stored log, bypassing arbitration: the store writes what `update` returns.
  async function put(did: string, chain: Array<SignedEvent>): Promise<void> {
    await store.merge(did, async () => chainOnly(chain))
  }

  beforeAll(async () => {
    adapter = await harness.createAdapter()
    db = new HozonDB({ adapter, tablePrefix })
    db.register(controllerStoreDefinition)
    // Direct row access, to store shapes `merge` never writes.
    db.register({
      name: 'controller-rows',
      migrations: {},
      createAPI: (rowsDB: Kysely<ControllerStoreTables>) => rowsDB,
    })
    store = await getControllerStore(db)
    rows = await db.getStore<Kysely<ControllerStoreTables>>('controller-rows')
  }, 60_000)

  afterAll(async () => {
    await db?.close()
    await harness.cleanup()
  })

  test('registers and round-trips a stored log', async () => {
    const { did, log } = buildRotatedLog()
    await put(did, log)
    expect(await store.get(did)).toEqual(chainOnly(log))
  })

  test('resolves the head signing key through the store', async () => {
    const { did, log, headKey, inceptionKey } = buildRotatedLog()
    await put(did, log)

    const resolver = createControllerResolver({
      loadLog: async (loadDID) => await store.get(loadDID),
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

  test('merge writes what the update returns: a shorter later log overwrites a longer stored one', async () => {
    // Distinct seed so this DID does not collide with the other tests in the
    // shared store.
    const icp = createInception(OVERWRITE_SEED, 0)
    const did = didFromInception(icp.event)
    const rot = createRotate({
      seed: OVERWRITE_SEED,
      profile: 0,
      did,
      prior: icp.event,
      options: { snapshot: { members: [], deny: [] } },
    })
    const long = [icp, rot] as Array<SignedEvent>
    const short = [icp] as Array<SignedEvent>

    await put(did, long)
    expect(await store.get(did)).toEqual(chainOnly(long))

    // The store never blocks a "backwards" write: supersession (e.g. a recovery
    // rotate at a low sequence) legitimately lowers length, so a high-water-mark
    // store would brick a rescue. Arbitration is the resolver's job, not the
    // store's -- this is the store's defining behavior.
    await put(did, short)
    expect(await store.get(did)).toEqual(chainOnly(short))
  })

  test('merge applies the update to the stored log and returns it', async () => {
    const { did, log } = buildRotatedLog(RACE_SEED)
    const added = buildAdd(did, log, RACE_SEED, 'one')
    let seen: ControllerLog | undefined = chainOnly([])

    const first = await store.merge(did, async (current) => {
      seen = current
      return chainOnly(log)
    })
    expect(seen).toBeUndefined()
    expect(first).toEqual(chainOnly(log))

    const second = await store.merge(did, async (current) => {
      seen = current
      return { chain: log, events: [added] }
    })
    expect(seen).toEqual(chainOnly(log))
    expect(second).toEqual({ chain: log, events: [added] })
    expect(await store.get(did)).toEqual({ chain: log, events: [added] })
  })

  test('a throwing update writes nothing', async () => {
    const { did, log } = buildRotatedLog(THROW_SEED)
    await put(did, log)
    const before = await store.get(did)
    await expect(
      store.merge(did, async () => {
        throw new Error('refused')
      }),
    ).rejects.toThrow('refused')
    expect(await store.get(did)).toEqual(before)
    expect(before).toEqual(chainOnly(log))
  })

  test('two concurrent merges for one stored DID both land', async () => {
    const { did, log } = buildRotatedLog(RACE_SEED)
    await put(did, log)
    const a = buildAdd(did, log, RACE_SEED, 'a')
    const b = buildAdd(did, log, RACE_SEED, 'b')
    // The first update waits until the second merge has been issued, so an unlocked store lets both
    // read the same row.
    let issued: () => void = () => {}
    const secondIssued = new Promise<void>((resolve) => {
      issued = resolve
    })
    const slow = appendEvent(log, a)
    const first = store.merge(did, async (current) => {
      await secondIssued
      return await slow(current)
    })
    const second = store.merge(did, appendEvent(log, b))
    issued()
    await Promise.all([first, second])
    expect(memberNames(await store.get(did))).toEqual(['did:key:a', 'did:key:b'])
  })

  test('two concurrent first merges for a new DID both land', async () => {
    const { did, log } = buildRotatedLog(FIRST_RACE_SEED)
    const a = buildAdd(did, log, FIRST_RACE_SEED, 'a')
    const b = buildAdd(did, log, FIRST_RACE_SEED, 'b')
    expect(await store.get(did)).toBeUndefined()
    await Promise.all([
      store.merge(did, appendEvent(log, a)),
      store.merge(did, appendEvent(log, b)),
    ])
    expect(memberNames(await store.get(did))).toEqual(['did:key:a', 'did:key:b'])
  })

  test('a legacy array row decodes as a chain with no epoch events', async () => {
    const { did, log } = buildRotatedLog(LEGACY_SEED)
    await rows
      .insertInto('controller_logs')
      .values({ did, log: adapter.encodeJSON(log) as ControllerLog })
      .execute()
    expect(await store.get(did)).toEqual(chainOnly(log))

    let seen: ControllerLog | undefined
    await store.merge(did, async (current) => {
      seen = current
      return current as ControllerLog
    })
    expect(seen).toEqual(chainOnly(log))
    // Handing back `current` is "nothing changed": the row is not rewritten, and still decodes.
    expect(await store.get(did)).toEqual(chainOnly(log))
    await store.merge(did, async (current) => ({ ...(current as ControllerLog) }))
    // A new log, even an equal one, is written, in the current shape.
    expect(await store.get(did)).toEqual(chainOnly(log))
  })

  // Rows inserted with no `updated_at`, so a write of any kind would show as one.
  async function insertUnstamped(did: string, log: unknown): Promise<void> {
    await rows
      .insertInto('controller_logs')
      .values({ did, log: adapter.encodeJSON(log) as ControllerLog })
      .execute()
  }

  async function stampOf(did: string): Promise<unknown> {
    const row = await rows
      .selectFrom('controller_logs')
      .select('updated_at')
      .where('did', '=', did)
      .executeTakeFirst()
    return row?.updated_at
  }

  test('an update returning the current log writes nothing', async () => {
    const { did, log } = buildRotatedLog(UNCHANGED_SEED)
    await insertUnstamped(did, chainOnly(log))
    const returned = await store.merge(did, async (current) => current as ControllerLog)
    expect(returned).toEqual(chainOnly(log))
    expect(await stampOf(did)).toBeNull()
    expect(await store.getObservedAt(did)).toBeInstanceOf(Date)
  })

  test('a resolution that learns nothing new writes nothing', async () => {
    const { did, log } = buildRotatedLog(RESOLVED_SEED)
    await insertUnstamped(did, chainOnly(log))
    const resolver = createControllerResolver({
      loadLog: async () => chainOnly(log),
      history: store,
    })
    await resolver.resolve(did, {})
    await resolver.resolve(did, {})
    expect(await stampOf(did)).toBeNull()
  })

  test('a row that is not JSON at all is no memory, and the next merge replaces it', async () => {
    // Postgres refuses such a row on insert; a text column (SQLite) keeps whatever was written.
    if (adapter.kind === 'postgres') return
    const { did, log } = buildRotatedLog(new Uint8Array(32).fill(16))
    await rows
      .insertInto('controller_logs')
      .values({ did, log: '{"chain": [' as unknown as ControllerLog })
      .execute()
    expect(await store.get(did)).toBeUndefined()
    let seen: ControllerLog | undefined = chainOnly(log)
    await store.merge(did, async (current) => {
      seen = current
      return chainOnly(log)
    })
    expect(seen).toBeUndefined()
    expect(await store.get(did)).toEqual(chainOnly(log))
  })

  test('a stored value that is neither a log nor a legacy array is no memory', async () => {
    const did = 'did:kokuin:malformed'
    await rows
      .insertInto('controller_logs')
      .values({ did, log: adapter.encodeJSON({ nope: true }) as ControllerLog })
      .execute()
    expect(await store.get(did)).toBeUndefined()
  })

  test('resolve rejects an unknown DID', async () => {
    const resolver = createControllerResolver({
      loadLog: async (loadDID) => await store.get(loadDID),
      history: store,
    })
    await expect(resolver.resolve('did:kokuin:unknown', {})).rejects.toThrow(/Unknown DID/)
  })

  test('getObservedAt returns a Date after insert and after update', async () => {
    const { did, log } = buildRotatedLog(OBSERVED_SEED)
    expect(await store.getObservedAt(did)).toBeUndefined()

    await put(did, log)
    const first = await store.getObservedAt(did)
    expect(first).toBeInstanceOf(Date)
    expect(Math.abs((first as Date).getTime() - Date.now())).toBeLessThan(5_000)

    await put(did, log.slice(0, 1))
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
        loadLog: async () => ({ chain: served, events: [] }),
        history: store,
      })

      // Accept once: the resolver folds the full log and writes it to the store itself.
      expect([...(await denySet(resolver, did))]).toEqual([denyEntry])
      expect(await store.get(did)).toEqual(chainOnly(full))

      // Attack: the peer now serves the prefix stopping just before the revoke. It folds and verifies,
      // but loses to the log already seen, so it is refused rather than answered from.
      served = truncated
      await expect(denySet(resolver, did)).rejects.toThrow(LOG_NOT_AUTHORITATIVE)
      // The refusal is the proof it never answered a deny set missing K; the store did not move back.
      expect(await store.get(did)).toEqual(chainOnly(full))
    })

    test('DANGEROUS BASELINE -- with no history the same prefix is answered, K missing from the deny set', async () => {
      const { did, denyEntry, truncated } = buildRevokedLog(TRUNCATION_SEED)

      // No `history`, so nothing to compare against: the prefix is taken at face value. This is the
      // silent revocation bypass the guard closes, isolating the history comparison as what bites.
      const resolver = createControllerResolver({
        loadLog: async () => ({ chain: truncated, events: [] }),
      })
      const set = await denySet(resolver, did)
      expect(set.has(denyEntry)).toBe(false)
      expect(set.size).toBe(0)
    })

    test('a genuine fork is refused after the full log was accepted', async () => {
      const { did, icp, rot, full } = buildRevokedLog(FORK_SEED)
      // A rival rotate at the same position as the accepted log's denying one: both reveal the
      // pre-committed key, neither supersedes the other, so branch resolution reports duplicity --
      // a fork, not a truncation.
      const rival = createRotate({
        seed: FORK_SEED,
        profile: 0,
        did,
        prior: rot.event,
        options: {
          snapshot: { members: [], deny: ['did:key:z6MkForkRivalDeviceDidHere00000000000000000'] },
        },
      })
      const fork = [icp, rot, rival] as Array<SignedEvent>

      let served: Array<SignedEvent> = full
      const resolver = createControllerResolver({
        loadLog: async () => ({ chain: served, events: [] }),
        history: store,
      })

      await denySet(resolver, did)
      expect(await store.get(did)).toEqual(chainOnly(full))

      served = fork
      await expect(denySet(resolver, did)).rejects.toThrow(LOG_FORKED)
      expect(await store.get(did)).toEqual(chainOnly(full))
    })
  })
}
