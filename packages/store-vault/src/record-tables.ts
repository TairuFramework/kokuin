import type { VaultStoreTables } from './tables.js'

export type VaultRecordTable = {
  type: string
  owner: string
  id: string
  hlc: string
  op_jwt: string
  op_hash: string
  payload: Uint8Array | null
  payload_digest: string | null
  deleted: number
  meta: Record<string, unknown>
}

export type VaultKeyBranchTable = {
  owner_did: string
  key_id: string
  key_version: number
  record_id: string
  branch_id: string
  op_jwt: string
}

export type VaultRecordsTables = VaultStoreTables & {
  vault_records: VaultRecordTable
  vault_decisions: {
    type: string
    owner: string
    id: string
    mode: 'local' | 'replicated'
    content_digest: string | null
    decision_hlc: string | null
  }
  vault_record_domain: { singleton: number; op_kind: string }
  vault_entry_candidates: VaultRecordTable & {
    key_id: string
    key_version: number
    branch_id: string
  }
  vault_key_branches: VaultKeyBranchTable
  vault_revocations: { owner_did: string; key_id: string; recipient_did: string }
}
