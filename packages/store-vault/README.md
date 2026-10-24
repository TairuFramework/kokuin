# @kokuin/store-vault

Local vault persistence for hozon. Register `vaultStoreDefinition`, then call `getVaultStore(provider)`.
All addresses require an explicit owner DID. Owners and recipients round-trip verbatim.

Keys contain public suite, version and state metadata. Wrappings and entries contain opaque encrypted bytes.
Entry `kind`, `label` and string attributes remain public. Filters combine exact kind/label equality with conjunctive attribute-subset matching.

Ordinary key puts accept equal or greater versions. Entry puts replace bytes without comparing HLC and refuse key reassociation.
`moveEntry` stores caller-encrypted destination bytes while preserving the owner-qualified entry ID.
It does nothing when the observed source disappears or changes key before locking.
Conditional updates never insert or move rows. HLC CAS returns `updated`, `absent` or `superseded`.
The caller supplies all encryption, authorisation and HLC values.

`transaction` joins an enclosing host transaction. Obtain the store from the host's transaction provider for journal/outbox atomicity.
Explicit key locks require a transaction. Declare the complete key set before authoritative reads when touching multiple keys.
Writes use hozon key locks, including absent keys. Multi-key locking orders actual advisory IDs through hozon.
Generic reads never acquire write locks or change rows.

The shared lock namespace uses table `vault_keys` and tuple `[JSON.stringify([ownerDID, keyID])]`.
This maps the database-free vault record lock `{ type: 'vault.key', key: JSON.stringify([ownerDID, keyID]) }`.
Replicated adapters must reuse this mapping.

The base schema contains only keys, wrappings and entries. Each row has a `local` or `replicated` mode.
Coordinators and transport are supplied separately.

## Optional records

Register `vaultRecordsStoreDefinition` alongside the base definition, then initialise it with
`await getVaultRecordsStore(provider, opKind)` before opening caller transactions. It depends on `vault`.
The base registration alone never creates records, decisions, candidates, branch proofs or revocations.

`createVaultRecords({ store, opKind, authority, validateConsumerMetadata, nowMS, maxDriftMS })`
creates a facade over the initialised store. The operation kind has no default.
Initialisation binds the database permanently to that kind without taking vault key locks.
Supplying a kind inside a caller transaction throws. Omit it only when retrieving already initialised storage.
Apply only reads and compares the binding. Reads and writes refuse an absent or different durable kind.

Use `apply(records, transportContext)` for receipt. Use `write({ records, preconditions })` for signed local output.
Both run `@kokuin/records` apply. There is no direct signed put method.
`preconditions.key` compares the expected version, including `null` for absence, and an optional complete branch set.
`preconditions.entry` compares an entry's exact HLC, including `null` for absence.
Every output must be covered by the named key or entry. Preconditions and apply share the transaction and key locks.
Obtain the base store from the caller's transaction provider to join journal/outbox writes.
An error requires the caller to roll back that transaction.

The `adapter` implements `RecordStoreAdapter` for transport reconciliation and routed apply.
Its `putCopy` and `pruneCopy` are trusted engine persistence ports, requiring an adapter transaction.
Never submit untrusted signed records directly to those ports.
`vaultRecordPortsFor(adapter)` resolves transaction-bound definition effects, including through `adapterForType` routing.
Authority and signed consumer metadata validation always come from the caller.
Transport and membership policy remain consumer-owned.

Local mutation methods refuse replicated addresses with `VaultModeConflict`.
Projections refuse local addresses, and their entire apply transaction rolls back.
Mode reservations survive signed tombstones, suppressed wrappings and local physical deletion after optional registration.
Entry mode is independent of the parent key. There is no adoption or unrevocation API.

Branch reads return verified introducing operations. Wrappings and entries carry their signed branch as `provenance`.
Candidate reads retain received authorised entry losers and prior tombstones.
Exchange lists selected decisions and their signed copies, rather than all candidate history.
Revocations permanently suppress recipient and DID-factor wrappings across versions.
A survivor's same-decision endorsement can replace a removed signer's copy without losing content.

`get` and `getMany` fail closed on unreadable decisions. `list` omits corrupt decisions and reports them through `onCorruptRow`.
Generic reads never repair data or write history. Range leaves and fingerprints use the records package's functions.

## Coordinators

`createVaultCoordinator(params)` adds authority, opening, key lifecycle, rotation, repair and encrypted entry operations.
Select `mode: 'local'` or `mode: 'replicated'` explicitly. Both require `CredentialAuthority`, a principal, runtime and `nextHLC`.
Supply an agreement identity, or `null` for secret-only opening. Replicated mode additionally requires a signer and records configuration.
Initialise the optional records store before constructing a replicated coordinator. Local coordinators need only the base store.

The store-vault `CredentialAuthority` accepts unsigned operations and the vault's existing verified record requests.
Unsigned requests use `source: 'local'` and include the selected mode, operation, verb, address and unchanged transport context.
This includes replicated reads. No fabricated signed operation represents a local request.
Record admission uses `source: 'record'`, verified fields and the transaction-bound records read port.
Every public operation calls authority, including cached opens, missing entries, listings, repair and explicit re-endorsement.
Reads use `read`. Persistent mutations use `administer`. Authority refusal stops the operation before database writes.
Consumer metadata and effective membership remain consumer decisions. There is no default authority.

`openKey` returns a private content-key buffer. The caller must erase that buffer after use.
`unlock`, `lock`, `lockAll` and `status` manage the optional memory cache.
Input-free opens share in-flight work. Input-bearing opens verify independently, even when a key is cached.
All PIN-bearing opening paths share one throttle. Locks invalidate pending cache warming.
Replicated opening selects authenticated branches by claim digest, then operation hash.
It passes the signed wrapping's descriptor digest to unwrap. Local rows provide no independent trusted descriptor digest.

`createKey` takes an explicit canonical owner DID and optional ordered wrapping factor sets.
The default wrapping addresses the agreement identity in its resolvable form.
`grant`, `addFactor` and `removeFactor` require administration and operate on the current version.
A historical `atVersion` on those mutations refuses. `setKeyState` and `deleteKey` change lifecycle metadata.
Replicated arbitration can refuse same-version reactivation after retirement. The coordinator reports that refusal as `VaultWriteConflict`.

Entry operations accept explicit owner-qualified addresses, byte plaintext and public kind, label and string attributes.
`putEntry` creates an absent address. Updates require an existing entry. HLC CAS returns updated, absent or superseded.
`reKeyEntry` authorises both keys, preserves the entry address, and re-encrypts under the destination key.
`getEntry`, `listEntries`, `listKeys`, `readEntry` and `openKey` never write or initiate recovery.
Returned entry rows include stored provenance. No entry ID has application-specific meaning.

`rotate` and `repairFork` require `excludedRecipients` and `reissue` arrays, including explicit empty arrays.
Rotation carries generic plaintext and public metadata forward. It preserves content intent unless an instruction supplies another `contentHLC`.
A reissue instruction names one entry and selects `preserve`, `replace`, `delete` or `skip`.
`replace` supplies new plaintext. `consumer` optionally replaces signed opaque metadata.
`skip` leaves the old entry untouched. Duplicate or unknown entry instructions refuse the whole operation.
Replacement instructions target live entries. Tombstone preservation and explicit deletion require no plaintext.

Exclusions match explicit recipients and DID factors. Replicated exclusions also publish permanent recipient denials through apply.
Local exclusions delete existing matching wrappings. Local mode has no permanent revocation table.
Repair uses received authenticated candidates, prior tombstones and vault branch proofs. It never discovers removed members.
Repair returns rotated, not-needed or pending. Missing preservation factors leave the fork pending for an explicit retry.
Received candidate history has no all-peers completeness guarantee.

Replicated coordinators submit every signed output through `write` and apply, with key version, branch-set and entry HLC preconditions.
They refuse parked, rejected or losing output and roll back the operation. There is no direct signed put.
Retained wrapping factors and reissued entry projections are checked against signed evidence before they become new signed output.
`reendorse({ ownerDID, keyID, records })` re-signs only named stored decisions, including key tombstones, without changing their claims or payloads.
The configured signer represents the effective consumer member. The consumer decides which records require re-endorsement.

Mutations hold hozon's complete key-lock set through their joined transaction, including cryptographic work.
Create the coordinator from the host transaction's store when journal/outbox changes must commit together.
Propagate errors out of the host transaction so it rolls back. Temporary keys and decrypted plaintext are erased on success and failure.
`nextHLC` belongs to the host. It must provide canonical, increasing stamps and any required restart floor.
Crypto-only hosts continue to use `@kokuin/vault` directly.
