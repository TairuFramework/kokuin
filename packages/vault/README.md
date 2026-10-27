# @kokuin/vault

Database-free content keys, ordered factor wrapping, and authenticated encryption of opaque bytes.

```ts
import { getSuite, SUITE_VAULT_1, wrappableDID } from '@kokuin/vault'
import { createRuntime } from '@sozai/runtime'

const runtime = createRuntime()
const suite = getSuite(SUITE_VAULT_1)
const keyID = 'host-content-key'
const keyVersion = 1
const wrappingID = 'device-wrapping'
const contentKey = suite.generateContentKey(runtime)
const wrapped = await suite.wrap({
  runtime,
  keyID,
  keyVersion,
  wrappingID,
  contentKey,
  factors: [{ kind: 'did', recipientDID: wrappableDID(deviceIdentity) }],
})

// Keep this digest in trusted local state or independently authenticated metadata.
const trustedDigest = wrapped.descriptorDigest
const openedKey = await suite.unwrap({
  ...wrapped,
  keyID,
  keyVersion,
  wrappingID,
  identity: deviceIdentity,
  expectedDescriptorDigest: trustedDigest,
})
const entryID = 'current-state'
const encrypted = suite.encryptEntry({
  runtime,
  keyID,
  keyVersion,
  entryID,
  contentKey: openedKey,
  plaintext: hostBytes,
})
const recovered = suite.decryptEntry({
  ...encrypted,
  keyID,
  keyVersion,
  entryID,
  contentKey: openedKey,
})
```

`deviceIdentity` supplies an already available agreement key. The host must ensure `agreeKey` never prompts on its message path.
The host owns persistence and atomically replaces the current ciphertext with its journal or outbox transaction.
The host also owns device binding, rollback protection, and refusal to sync, export, or retain historical MLS state.

`VAULT_1` uses X25519 agreement, HKDF-SHA256, Argon2id, and AES-256-GCM.
Descriptors preserve factor order. A PIN requires a DID factor in the same wrapping.
The default Argon2id cost is `{ m: 19456, t: 2, p: 1 }`, with memory measured in KiB.
IVs are 12 bytes. Encrypted values contain ciphertext followed by the 16-byte authentication tag.
Entry AAD binds the suite, key ID, version, and entry ID.

`expectedDescriptorDigest` is optional. A trusted mismatch throws `VaultTampered` before agreement, KDF work, or decryption.
The `descriptorDigest` carried beside a presented wrapping is informational and cannot establish trust by itself.
GCM unwrap failures throw `VaultSecretRejected` with the original failure as `cause`, including for DID-only wrappings.
Missing factors and malformed descriptors retain their distinct validation errors.
Entry authentication failures throw `VaultTampered` with the original cause.

`createVaultKeyID(owner, unique)` hashes the exact owner bytes concatenated with unique bytes using BLAKE3.
Its base36 multibase encoding frames unsigned varints for namespace `0xb6`, key type `31`, and digest length `32`.
Callers normalise owner DIDs before minting IDs used as equality keys.
Recipient DIDs retain their resolvable long form. `wrappableDID` selects that form when available.

The package also exports the public key, wrapping, entry-set and descriptor digest helpers,
pure factor reconstruction and eligibility checks, a cloning TTL key cache, and an optional in-memory PIN throttle.
