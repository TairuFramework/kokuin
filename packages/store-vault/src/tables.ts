import type { Generated } from '@hozon/db'
import type { FactorDescriptor } from '@kokuin/vault'

export type VaultKeyTable = {
  owner_did: string
  key_id: string
  suite: number
  version: number
  state: 'active' | 'retired'
  mode: Generated<'local' | 'replicated'>
}

export type VaultWrappingTable = {
  owner_did: string
  wrapping_id: string
  key_id: string
  key_version: number
  descriptors: Array<FactorDescriptor>
  descriptor_digest: string
  iv: Uint8Array
  wrapped_key: Uint8Array
  recipient_did: string | null
  provenance: string
  mode: Generated<'local' | 'replicated'>
}

export type VaultEntryTable = {
  owner_did: string
  entry_id: string
  key_id: string
  key_version: number
  kind: string
  label: string
  attributes: Record<string, string>
  iv: Uint8Array
  ciphertext: Uint8Array
  hlc: string
  provenance: string
  mode: Generated<'local' | 'replicated'>
}

export type VaultStoreTables = {
  vault_keys: VaultKeyTable
  vault_wrappings: VaultWrappingTable
  vault_entries: VaultEntryTable
}
