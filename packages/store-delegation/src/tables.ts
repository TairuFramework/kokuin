import type { CreatedAtColumn, UpdatedAtColumn } from '@hozon/adapter'
import type { Insertable, Selectable } from 'kysely'

// --- Delegation tokens ---

export type DelegationTokenTable = {
  jti: string
  grantor: string
  audience: string
  token: string
  resource: string
  act: string
  exp: number
  /**
   * Last-writer-wins stamp, supplied by every caller and never generated here.
   * Byte-wise lexicographic order must match causal order: SQL compares it with
   * `>` and JS with `<=`, so a fixed-width serialization is required. It must be
   * ASCII: SQL compares bytes and JS compares UTF-16 code units, and the two
   * orders are only guaranteed to agree on ASCII.
   *
   * - Local-only consumers may pass any strictly increasing string of the shape
   *   `<ISO wall time>:<zero-padded counter>:<nodeID>`.
   * - Syncing consumers need a real hybrid logical clock serialized in this
   *   format, so stamps from different peers arbitrate correctly.
   *
   * Mixing locally invented stamps with real HLC stamps in a synced store is
   * unsupported: the local stamps would win or lose on wall clock alone.
   */
  hlc: string
  created_at: CreatedAtColumn
  updated_at: UpdatedAtColumn
}

export type DelegationToken = Selectable<DelegationTokenTable>
export type InsertDelegationToken = Insertable<DelegationTokenTable>

// --- Revoked capabilities ---

export type RevokedCapabilityTable = {
  jti: string
  revoker_did: string
  revoked_iat: number
  revocation_token: string
  verified_at: number | null
  cap_exp: number | null
  /**
   * Last-writer-wins stamp, supplied by every caller and never generated here.
   * Byte-wise lexicographic order must match causal order: SQL compares it with
   * `>` and JS with `<=`, so a fixed-width serialization is required. It must be
   * ASCII: SQL compares bytes and JS compares UTF-16 code units, and the two
   * orders are only guaranteed to agree on ASCII.
   *
   * - Local-only consumers may pass any strictly increasing string of the shape
   *   `<ISO wall time>:<zero-padded counter>:<nodeID>`.
   * - Syncing consumers need a real hybrid logical clock serialized in this
   *   format, so stamps from different peers arbitrate correctly.
   *
   * Mixing locally invented stamps with real HLC stamps in a synced store is
   * unsupported: the local stamps would win or lose on wall clock alone.
   */
  hlc: string
  created_at: CreatedAtColumn
  updated_at: UpdatedAtColumn
}

export type RevokedCapability = Selectable<RevokedCapabilityTable>
export type InsertRevokedCapability = Insertable<RevokedCapabilityTable>

// Row shape produced by joining `revoked_capabilities` to `delegation_tokens` on
// `jti`. `audience` and `grantor` come from the cap row; the join is INNER, so a
// verified revocation with no matching local cap is excluded. `verified_at` is
// non-null by the query's WHERE.
export type HeldRevocation = {
  jti: string
  grantor: string
  audience: string
  revoker_did: string
  revoked_iat: number
  verified_at: number
  cap_exp: number | null
}

export type DelegationStoreTables = {
  delegation_tokens: DelegationTokenTable
  revoked_capabilities: RevokedCapabilityTable
}
