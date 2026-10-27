import { withStoreTransaction } from '@hozon/db'
import type { RecordStoreAdapter } from '@kokuin/records'
import { recordPayloadMatches, verifySignedRecord } from '@kokuin/records'
import type { VaultRecordPorts } from '@kokuin/vault'
import { vaultRecordMeta, vaultRevocationRecordID } from '@kokuin/vault'

import { selectWrappings, statementChunks } from './batch.js'
import { VaultModeConflict } from './record-context.js'
import { assertDomain, boundAdapters, values } from './records-rows.js'
import { settleAll } from './settle.js'

/** Resolve effects only through an adapter bound to the apply transaction. */
export function vaultRecordPortsFor(store: RecordStoreAdapter): VaultRecordPorts {
  const bound =
    boundAdapters.get(store) ??
    boundAdapters.get(store.adapterForType?.('vault.entry') as RecordStoreAdapter)

  if (bound === undefined) throw new Error('Vault adapter is unavailable for effect ports')

  const { db } = bound

  return {
    async retainEntryCandidate(record) {
      if (!db.isTransaction) throw new Error('Candidate retention requires the apply transaction')

      const op = await verifySignedRecord(record, bound.opKind, bound.params.methods)

      if (
        op === null ||
        !recordPayloadMatches(record, op.claim) ||
        vaultRecordMeta('vault.entry', op.claim) === null
      )
        throw new Error('Invalid entry candidate')

      await db
        .insertInto('vault_entry_candidates')
        .values({
          ...values(record, op, bound),
          key_id: op.claim.meta.keyID as string,
          key_version: op.claim.meta.keyVersion as number,
          branch_id: (op.claim.meta.branchID as string) ?? '',
        })
        .onConflict((oc) => oc.columns(['type', 'owner', 'id', 'op_hash']).doNothing())
        .execute()
    },
    async listRevocations(address) {
      await assertDomain(bound)

      const rows = await withStoreTransaction(db, async (tx) => {
        return tx
          .selectFrom('vault_revocations')
          .select('recipient_did')
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .orderBy('recipient_did')
          .execute()
      })

      return rows.map((row) => row.recipient_did)
    },
    async dropRevokedWrappings(address) {
      if (!db.isTransaction) throw new Error('Wrapping suppression requires the apply transaction')

      const [revocations, wrappings] = await settleAll([
        this.listRevocations(address),
        bound.store.listWrappings(address),
      ])
      const denied = new Set(revocations.map((did) => vaultRevocationRecordID(address.keyID, did)))
      const revoked = wrappings
        .filter((row) => {
          const recipients = [
            row.recipientDID,
            ...row.descriptors.filter((d) => d.kind === 'did').map((d) => d.params.recipient),
          ]

          return recipients.some((recipient) => {
            return (
              typeof recipient === 'string' &&
              denied.has(vaultRevocationRecordID(address.keyID, recipient))
            )
          })
        })
        .map((row) => ({ owner_did: row.ownerDID, wrapping_id: row.wrappingID }))

      if (revoked.length === 0) return

      const parts = statementChunks(revoked, 2)
      const held = await settleAll(parts.map((part) => selectWrappings(db, part).execute()))

      // Denial never deletes an unrelated local record.
      if (held.flat().some((row) => row.mode === 'local')) throw new VaultModeConflict()

      await settleAll(
        parts.map((part) => {
          return db
            .deleteFrom('vault_wrappings')
            .where((eb) => {
              return eb.or(
                part.map((row) => {
                  return eb.and([
                    eb('owner_did', '=', row.owner_did),
                    eb('wrapping_id', '=', row.wrapping_id),
                  ])
                }),
              )
            })
            .execute()
        }),
      )
    },
  }
}
