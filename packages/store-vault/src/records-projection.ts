import type { SignedRecord, VerifiedRecordOp } from '@kokuin/records'
import { decodeVaultRecord } from '@kokuin/vault'

import { VaultModeConflict } from './record-context.js'
import type { Bound } from './records-rows.js'

export async function projection(
  record: SignedRecord,
  op: VerifiedRecordOp,
  bound: Bound,
): Promise<void> {
  const { db, adapter } = bound
  const type = record.type
  const table =
    type === 'vault.key'
      ? 'vault_keys'
      : type === 'vault.entry'
        ? 'vault_entries'
        : type === 'vault.wrapping'
          ? 'vault_wrappings'
          : null

  if (table !== null) {
    const column =
      type === 'vault.key' ? 'key_id' : type === 'vault.entry' ? 'entry_id' : 'wrapping_id'
    const existing = await db
      .selectFrom(table)
      .select('mode')
      .where('owner_did', '=', record.owner)
      .where(column, '=', record.id)
      .executeTakeFirst()

    if (existing?.mode === 'local') throw new VaultModeConflict()

    // The caller, `putCopy`, claims the decision for replicated mode in the same transaction.
    if (record.payload === null) {
      await db
        .deleteFrom(table)
        .where('owner_did', '=', record.owner)
        .where(column, '=', record.id)
        .execute()

      return
    }
  }

  const decoded = decodeVaultRecord(record, op.claim.meta)

  switch (decoded.type) {
    case 'vault.key': {
      const row = {
        owner_did: decoded.owner,
        key_id: decoded.id,
        suite: decoded.payload.suite,
        version: decoded.meta.version,
        state: decoded.payload.state,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_keys')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'key_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.wrapping': {
      const row = {
        owner_did: decoded.owner,
        wrapping_id: decoded.id,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        descriptors: adapter.encodeJSON(
          decoded.payload.descriptors,
        ) as typeof decoded.payload.descriptors,
        descriptor_digest: decoded.payload.descriptorDigest,
        iv: adapter.encodeBinary(decoded.payload.iv) as Uint8Array,
        wrapped_key: adapter.encodeBinary(decoded.payload.wrappedKey) as Uint8Array,
        recipient_did: decoded.meta.recipient,
        provenance: decoded.meta.branchID as string,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_wrappings')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'wrapping_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.entry': {
      const row = {
        owner_did: decoded.owner,
        entry_id: decoded.id,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        kind: decoded.meta.kind as string,
        label: decoded.meta.label as string,
        attributes: adapter.encodeJSON(decoded.meta.attributes) as Record<string, string>,
        iv: adapter.encodeBinary(decoded.payload.iv) as Uint8Array,
        ciphertext: adapter.encodeBinary(decoded.payload.ciphertext) as Uint8Array,
        hlc: decoded.hlc,
        provenance: decoded.meta.branchID as string,
        mode: 'replicated' as const,
      }

      await db
        .insertInto('vault_entries')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'entry_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.key-branch': {
      const row = {
        owner_did: decoded.owner,
        key_id: decoded.meta.keyID,
        key_version: decoded.meta.keyVersion,
        record_id: decoded.id,
        branch_id: decoded.meta.branchID,
        op_jwt: decoded.payload.opJWT,
      }

      await db
        .insertInto('vault_key_branches')
        .values(row)
        .onConflict((oc) => oc.columns(['owner_did', 'record_id']).doUpdateSet(row))
        .execute()

      break
    }
    case 'vault.revocation':
      await db
        .insertInto('vault_revocations')
        .values({
          owner_did: decoded.owner,
          key_id: decoded.meta.keyID,
          recipient_did: decoded.meta.revokedDID,
        })
        .onConflict((oc) => oc.columns(['owner_did', 'key_id', 'recipient_did']).doNothing())
        .execute()
  }
}
