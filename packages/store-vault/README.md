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
