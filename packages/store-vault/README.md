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

The base schema contains only keys, wrappings and entries. Each row reserves a `mode` column for future projection guards.
This package currently exposes local storage only. It has no records adapter, history, transport, recipient revocations or coordinators.
