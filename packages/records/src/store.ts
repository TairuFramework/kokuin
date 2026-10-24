import type { RecordDecision } from './decision.js'
import type { RecordKey, SignedRecord } from './record.js'

export type RecordLockKey = { type: string; key: string }

/** Decisions keyed by {@link recordKeyText}; a key with no stored decision is absent. */
export type RecordDecisionMap = Map<string, RecordDecision>

/**
 * Where a receiver keeps each owner's current decision, addressed by `(type, owner, id)`.
 *
 * One store holds ops of exactly one `opKind`. All records enter through apply, which
 * verifies them under that kind. Never share a store, or reconcile two stores, across kinds.
 * `rangeLeaf` and decision digests assume records already verified under the store's kind;
 * these comparison values do not isolate replay domains themselves.
 *
 * `get`, `getMany` and `list` include tombstones. `getMany` answers what `get` would for each
 * key, in fewer reads, and throws whatever `get` would throw for any one of them. `putCopy`
 * retains a copy of the winning decision; a new decision replaces the old one. `pruneCopy`
 * removes copies by signer only after a replacement is held. The store keeps one authorized
 * signed copy per signing key.
 *
 * `transaction` runs `fn` against an adapter bound to one transaction, committing when `fn`
 * resolves and rolling back when it throws.
 */
export type RecordStoreAdapter = {
  /** True when already bound to a caller-owned transaction; required for inline transaction adapters. */
  isTransaction?: boolean
  transaction<R>(fn: (tx: RecordStoreAdapter) => Promise<R>): Promise<R>
  /**
   * Must accept concurrent calls on one adapter, including one bound to a transaction:
   * `getRecordDecisions` and apply issue several at once when `getMany` is absent.
   */
  get(key: RecordKey): Promise<RecordDecision | null>
  getMany?(keys: ReadonlyArray<RecordKey>): Promise<RecordDecisionMap>
  list(types: ReadonlyArray<string>): Promise<Array<RecordDecision>>
  /** Indexed lookup of records whose signed metadata names one transport group. */
  listByGroup?(type: string, groupID: string): Promise<Array<RecordDecision>>
  putCopy(record: SignedRecord): Promise<void>
  pruneCopy(key: RecordKey, signerDID: string): Promise<void>
  /** Acquire all transaction-scoped key locks together, before authoritative reads. */
  lock?(keys: ReadonlyArray<RecordLockKey>): Promise<void>
  adapterForType?(type: string): RecordStoreAdapter | null
}

/** The address of a record key in a {@link RecordDecisionMap}. */
export function recordKeyText(key: RecordKey): string {
  return JSON.stringify([key.type, key.owner, key.id])
}

/**
 * The stored decisions of `keys`, through `getMany` when the store has it, else concurrent `get`s.
 * The fallback waits for every `get`, so none is left running in the caller's transaction, then
 * throws the first failure in key order.
 */
export async function getRecordDecisions(
  store: RecordStoreAdapter,
  keys: ReadonlyArray<RecordKey>,
): Promise<RecordDecisionMap> {
  const unique = new Map<string, RecordKey>()
  for (const key of keys) {
    const text = recordKeyText(key)
    if (!unique.has(text)) unique.set(text, key)
  }
  if (unique.size === 0) return new Map()
  if (store.getMany !== undefined) return await store.getMany([...unique.values()])
  const entries = [...unique]
  const found = await Promise.allSettled(entries.map(([, key]) => store.get(key)))
  const decisions: RecordDecisionMap = new Map()
  for (const [index, [text]] of entries.entries()) {
    const result = found[index]
    if (result === undefined) continue
    if (result.status === 'rejected') throw result.reason
    if (result.value != null) decisions.set(text, result.value)
  }
  return decisions
}
