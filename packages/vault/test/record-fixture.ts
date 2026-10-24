import type { RecordDecision, RecordStoreAdapter, SignedRecord } from '@kokuin/records'
import {
  applyRecordChunk,
  recordClaimDigest,
  recordKeyText,
  recordPayloadDigest,
  recordSignerKey,
  signRecordOp,
  verifySignedRecord,
} from '@kokuin/records'
import type { SigningIdentity } from '@kokuin/token'
import { toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'

import type { VaultRecordHooks, VaultRecordType } from '../src/index.js'
import {
  createVaultKeyID,
  descriptorDigest,
  encodeVaultRecordPayload,
  vaultRecordTypes,
} from '../src/index.js'

export const OP_KIND = 'kokuin/vault-op/v1'
export const NOW = Date.parse('2026-10-24T12:00:00.000Z')
export const UNIQUE = new Uint8Array(16).fill(7)
export const stamp = (counter: number, nodeID = 'node') =>
  HLC.serialize({ wallTime: NOW - 3600_000, counter, nodeID })

export async function signed(
  signer: SigningIdentity,
  params: {
    type: VaultRecordType
    id: string
    owner: string
    hlc: string
    payload: Uint8Array | null
    meta: Record<string, unknown>
  },
  opKind = OP_KIND,
): Promise<SignedRecord> {
  const { payload, ...claim } = params
  return {
    ...params,
    ...(await signRecordOp(
      signer,
      {
        ...claim,
        payloadDigest: recordPayloadDigest(payload),
        deleted: payload === null,
      },
      opKind,
    )),
  }
}

export async function verified(record: SignedRecord) {
  const op = await verifySignedRecord(record, OP_KIND)
  if (op === null) throw new Error('Fixture signature did not verify')
  return op
}

export async function resign(
  signer: SigningIdentity,
  record: SignedRecord,
  changes: Partial<Parameters<typeof signed>[1]> = {},
  opKind = OP_KIND,
) {
  const op = await verified(record)
  return await signed(
    signer,
    { ...op.claim, type: record.type as VaultRecordType, payload: record.payload, ...changes },
    opKind,
  )
}

export async function chain(
  signer: SigningIdentity,
  params: {
    version?: number
    counter?: number
    owner?: string
    state?: 'active' | 'retired'
    consumer?: unknown
  } = {},
) {
  const owner = params.owner ?? signer.id
  const keyID = createVaultKeyID(owner, UNIQUE)
  const version = params.version ?? 1
  const state = params.state ?? 'active'
  const consumer = params.consumer ?? {}
  const key = await signed(signer, {
    type: 'vault.key',
    id: keyID,
    owner,
    hlc: stamp(params.counter ?? version * 10),
    payload: encodeVaultRecordPayload('vault.key', { suite: 1, state }),
    meta: { keyID, keyUnique: toB64U(UNIQUE), version, state, consumer },
  })
  const branchID = `${key.hlc}:${key.opHash}`
  const payload = encodeVaultRecordPayload('vault.key-branch', {
    authorDID: signer.id,
    hlc: key.hlc,
    opJWT: key.opJWT,
    opHash: key.opHash,
    suite: 1,
  })
  const id = recordPayloadDigest(payload)
  if (id === null) throw new Error('Branch payload digest missing')
  const branch = await signed(signer, {
    type: 'vault.key-branch',
    id,
    owner,
    hlc: key.hlc,
    payload,
    meta: { keyID, keyVersion: version, branchID, consumer },
  })
  return { key, branch, branchID, keyID, version, owner }
}
export type Chain = Awaited<ReturnType<typeof chain>>

export async function dependent(
  signer: SigningIdentity,
  source: Chain,
  type: 'vault.entry' | 'vault.wrapping',
  options: {
    id?: string
    counter?: number
    contentCounter?: number
    nodeID?: string
    recipient?: string | null
    factorRecipient?: string
    deleted?: boolean
    consumer?: unknown
  } = {},
) {
  const payload = options.deleted
    ? null
    : type === 'vault.entry'
      ? encodeVaultRecordPayload(type, {
          iv: new Uint8Array([0, 255]),
          ciphertext: new Uint8Array([128, 255, 0]),
        })
      : encodeVaultRecordPayload(type, {
          descriptors: [
            { kind: 'did', params: { recipient: options.factorRecipient ?? signer.id } },
          ],
          descriptorDigest: descriptorDigest([
            { kind: 'did', params: { recipient: options.factorRecipient ?? signer.id } },
          ]),
          iv: new Uint8Array([0, 255]),
          wrappedKey: new Uint8Array([128, 255, 0]),
        })
  return await signed(signer, {
    type,
    id: options.id ?? type,
    owner: source.owner,
    hlc: stamp(options.counter ?? 100, options.nodeID),
    payload,
    meta: {
      keyID: source.keyID,
      keyVersion: source.version,
      branchID: source.branchID,
      branchRecordID: source.branch.id,
      consumer: options.consumer ?? {},
      ...(type === 'vault.entry'
        ? {
            kind: 'blob',
            label: 'State',
            attributes: { format: 'binary' },
            contentHLC: stamp(options.contentCounter ?? 90, options.nodeID),
          }
        : { recipient: options.recipient === undefined ? signer.id : options.recipient }),
    },
  })
}

// Engine persistence only: no merge selection or projection policy lives in this adapter.
export function memoryStore() {
  let rows = new Map<string, RecordDecision>()
  let candidates: Array<SignedRecord> = []
  let effects: Array<{ ownerDID: string; keyID: string }> = []
  const transactions = new WeakMap<
    RecordStoreAdapter,
    { candidates: Array<SignedRecord>; effects: typeof effects }
  >()
  function adapter(view: Map<string, RecordDecision>): RecordStoreAdapter {
    const tx: RecordStoreAdapter = {
      isTransaction: true,
      transaction: async (fn) => await fn(tx),
      get: async (key) => view.get(recordKeyText(key)) ?? null,
      list: async (types) => [...view.values()].filter((d) => types.includes(d.key.type)),
      async putCopy(record) {
        const op = await verified(record)
        const text = recordKeyText(record)
        const previous = view.get(text)
        const digest = recordClaimDigest(op.claim)
        const copies = previous?.contentDigest === digest ? [...previous.copies] : []
        const signer = recordSignerKey(op.issuer, record.opJWT)
        for (let index = copies.length - 1; index >= 0; index--) {
          const copy = copies[index]
          if (copy === undefined) throw new Error('Missing stored copy')
          const old = await verified(copy)
          if (recordSignerKey(old.issuer, copy.opJWT) === signer) {
            if (copy.opHash <= record.opHash) return
            copies.splice(index, 1)
          }
        }
        copies.push(record)
        copies.sort((a, b) => (a.opHash < b.opHash ? -1 : 1))
        view.set(text, {
          key: { type: record.type, owner: record.owner, id: record.id },
          contentDigest: digest,
          decisionHLC: op.claim.hlc,
          copies,
        })
      },
      async pruneCopy(key, issuer) {
        const row = view.get(recordKeyText(key))
        if (row)
          row.copies = (
            await Promise.all(row.copies.map(async (copy) => ({ copy, op: await verified(copy) })))
          )
            .filter(({ op }) => op.issuer !== issuer)
            .map(({ copy }) => copy)
      },
      lock: async () => {},
    }
    return tx
  }
  const store: RecordStoreAdapter = {
    ...adapter(rows),
    get: async (key) => rows.get(recordKeyText(key)) ?? null,
    list: async (types) => [...rows.values()].filter((d) => types.includes(d.key.type)),
    async transaction(fn) {
      const draft = structuredClone(rows)
      const tx = adapter(draft)
      const state = { candidates: [...candidates], effects: [...effects] }
      transactions.set(tx, state)
      const result = await fn(tx)
      rows = draft
      candidates = state.candidates
      effects = state.effects
      return result
    },
  }
  store.isTransaction = false
  function portsFor(tx: RecordStoreAdapter) {
    const state = transactions.get(tx)
    if (!state) throw new Error('Effects must use the apply transaction')
    return {
      async retainEntryCandidate(record: SignedRecord) {
        state.candidates.push(record)
      },
      async listRevocations(address: { ownerDID: string; keyID: string }) {
        const result: Array<string> = []
        for (const row of await tx.list(['vault.revocation'])) {
          const copy = row.copies[0]
          if (copy === undefined) throw new Error('Empty decision')
          const op = await verified(copy)
          if (op.claim.owner === address.ownerDID && op.claim.meta.keyID === address.keyID)
            result.push(op.claim.meta.revokedDID as string)
        }
        return result
      },
      async dropRevokedWrappings(address: { ownerDID: string; keyID: string }) {
        state.effects.push(address)
      },
    }
  }
  const hooks: VaultRecordHooks = {
    authority: { authorize: async () => true },
    validateConsumerMetadata: async () => true,
    portsFor,
  }
  async function apply(
    records: Array<SignedRecord>,
    overrides: Partial<VaultRecordHooks> = {},
    transportContext?: unknown,
  ) {
    return await applyRecordChunk({
      records,
      store,
      types: vaultRecordTypes({ ...hooks, ...overrides, opKind: OP_KIND }),
      opKind: OP_KIND,
      transportContext,
      nowMS: NOW,
      maxDriftMS: 60_000,
      receiveClock: () => {},
      resolveController: async () => null,
      verifyCapability: async () => {
        throw new Error('Unexpected capability policy')
      },
    })
  }
  return { store, hooks, apply, candidates: () => candidates, effects: () => effects }
}
