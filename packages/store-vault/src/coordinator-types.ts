import type { SignedRecord } from '@kokuin/records'
import type { SigningIdentity } from '@kokuin/token'
import type {
  FactorInput,
  FactorInputs,
  KeyCacheParams,
  PinThrottleParams,
  CredentialAuthorityRequest as RecordAuthorityRequest,
  SecretFactorKind,
  UnwrapParams,
  WrapParams,
} from '@kokuin/vault'

import type { VaultRecords, VaultRecordsParams } from './records.js'
import type {
  EntryAddress,
  EntryFilter,
  EntryRow,
  KeyAddress,
  KeyRow,
  UpdateEntryResult,
  VaultStoreAPI,
} from './types.js'

/** Unsigned operation requests never fabricate record signatures, including replicated reads. */
export type CredentialAuthorityRequest =
  | RecordAuthorityRequest
  | {
      source: 'local'
      mode: 'local' | 'replicated'
      operation: string
      owner: string
      issuer: string
      verb: 'read' | 'administer'
      keyID?: string
      entryID?: string
      transportContext: unknown
      request: unknown
      store: Pick<
        VaultStoreAPI,
        'getKey' | 'getEntry' | 'listKeys' | 'listWrappings' | 'listEntries'
      >
    }

export type CredentialAuthority = {
  authorize(request: CredentialAuthorityRequest): Promise<boolean>
}

export type CoordinatorCall = { transportContext?: unknown }

export type OpenKeyParams = KeyAddress &
  CoordinatorCall & { inputs?: FactorInputs; atVersion?: number }

export type OpenedKey = { contentKey: Uint8Array; version: number; branchID: string; suite: number }

export type CreateKeyParams = CoordinatorCall & {
  ownerDID: string
  wrappings?: Array<Array<FactorInput>>
  suite?: number
  consumer?: unknown
}

export type EntryWriteParams = KeyAddress &
  EntryAddress &
  CoordinatorCall &
  Pick<EntryRow, 'kind' | 'label' | 'attributes'> & {
    plaintext: Uint8Array
    inputs?: FactorInputs
    consumer?: unknown
  }

export type EntryUpdateParams = EntryAddress &
  CoordinatorCall & { plaintext: Uint8Array; inputs?: FactorInputs; consumer?: unknown }

export type EntryReissue = { entryID: string; contentHLC?: string; consumer?: unknown } & (
  | { action: 'preserve' | 'skip' | 'delete' }
  | { action: 'replace'; plaintext: Uint8Array }
)

export type RotateKeyParams = OpenKeyParams & {
  excludedRecipients: ReadonlyArray<string>
  reissue: ReadonlyArray<EntryReissue>
  consumer?: unknown
  suite?: number
}

export type ForkRepairResult =
  | { status: 'rotated'; version: number }
  | { status: 'not-needed' | 'pending' }

export type KeyStatus =
  | { state: 'unlocked' | 'available' | 'unopenable' }
  | { state: 'locked'; unlockOptions: Array<Array<SecretFactorKind>> }

type CommonParams = {
  store: VaultStoreAPI
  principal: string
  identity: UnwrapParams['identity']
  runtime: WrapParams['runtime']
  authority: CredentialAuthority
  nextHLC(): Promise<string>
  methods?: WrapParams['methods']
  cache?: KeyCacheParams
  pinThrottle?: PinThrottleParams
}

export type VaultCoordinatorParams = CommonParams &
  (
    | { mode: 'local' }
    | {
        mode: 'replicated'
        signer: SigningIdentity
        records: Omit<VaultRecordsParams, 'store' | 'authority'>
      }
  )

export type VaultCoordinator = {
  /** Replicated mode only. Receipt remains subject to the records authority callback. */
  get records(): VaultRecords
  createKey(params: CreateKeyParams): Promise<KeyAddress>
  openKey(params: OpenKeyParams): Promise<OpenedKey>
  unlock(params: OpenKeyParams): Promise<void>
  lock(address: KeyAddress & CoordinatorCall): Promise<void>
  lockAll(ownerDID: string, call?: CoordinatorCall): Promise<void>
  status(params: OpenKeyParams): Promise<KeyStatus>
  listKeys(ownerDID: string, call?: CoordinatorCall): Promise<Array<KeyRow>>
  setKeyState(
    params: KeyAddress & CoordinatorCall & Pick<KeyRow, 'state'> & { consumer?: unknown },
  ): Promise<void>
  deleteKey(params: KeyAddress & CoordinatorCall & { consumer?: unknown }): Promise<void>
  grant(params: OpenKeyParams & { recipientDID: string; consumer?: unknown }): Promise<void>
  addFactor(params: OpenKeyParams & { factor: FactorInput; consumer?: unknown }): Promise<void>
  removeFactor(params: OpenKeyParams & { kind: string; consumer?: unknown }): Promise<void>
  rotate(params: RotateKeyParams): Promise<number>
  repairFork(params: RotateKeyParams): Promise<ForkRepairResult>
  putEntry(params: EntryWriteParams): Promise<EntryAddress>
  updateEntry(params: EntryUpdateParams): Promise<void>
  updateEntryIfPresent(params: EntryUpdateParams): Promise<'updated' | 'absent'>
  updateEntryIfUnchanged(
    params: EntryUpdateParams & { expectedHLC: string },
  ): Promise<UpdateEntryResult>
  readEntry(params: EntryAddress & CoordinatorCall & { inputs?: FactorInputs }): Promise<Uint8Array>
  getEntry(params: EntryAddress & CoordinatorCall): Promise<EntryRow | undefined>
  listEntries(params: EntryFilter & CoordinatorCall): Promise<Array<EntryRow>>
  deleteEntry(params: EntryAddress & CoordinatorCall & { consumer?: unknown }): Promise<void>
  reKeyEntry(
    params: EntryAddress &
      CoordinatorCall & { toKeyID: string; inputs?: FactorInputs; consumer?: unknown },
  ): Promise<void>
  reendorse(
    params: KeyAddress & CoordinatorCall & { records: ReadonlyArray<SignedRecord> },
  ): Promise<void>
}
