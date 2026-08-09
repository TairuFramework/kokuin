# Authentication & Keys

Kokuin is the **identity layer** for your application: it provides DID-based JWT-like identities for generating and verifying signed tokens, and per-environment keystores that persist private keys using OS-level secure storage (macOS Keychain, Windows Credential Manager, IndexedDB + Web Crypto, iOS Keychain, Android Keystore, Electron `safeStorage`, or a hardware Ledger device). Every identity is a [DID](https://www.w3.org/TR/did-core/) (`did:key:…` or `did:peer:4:…`) that encodes its own public key — token signatures can therefore be verified without prior key distribution or a central directory.

---

## Token system (`@kokuin/token`)

### Identities

```typescript
import {
  randomIdentity,
  createIdentity,
  createSigningIdentity,
  createKeyAgreementIdentity,
  createFullIdentity,
  isSigningIdentity,
  isKeyAgreementIdentity,
  isFullIdentity,
  isOwnIdentity,
} from '@kokuin/token'
import type {
  Identity,
  OwnIdentity,
  SigningIdentity,
  KeyAgreementIdentity,
  FullIdentity,
  MultiKeyIdentity,
  IdentityKeySpec,
  KeyAlg,
  KeyPurpose,
} from '@kokuin/token'
```

| Function | Returns | Notes |
|---|---|---|
| `randomIdentity()` | `OwnIdentity` | Fresh Ed25519 key pair in memory (`did:key:…`) |
| `createIdentity(input)` | `Promise<MultiKeyIdentity>` | Multi-key `did:peer:4` identity with signing + encryption keys |
| `createSigningIdentity(privateKey)` | `SigningIdentity` | Sign-only identity from an Ed25519 private key |
| `createKeyAgreementIdentity(privateKey)` | `KeyAgreementIdentity` | Key-agreement-only identity (JWE recipient, via `@kokuin/jwe`) |
| `createFullIdentity(privateKey)` | `FullIdentity` | Sign + key agreement from one Ed25519 private key |

**Identity hierarchy**: `OwnIdentity ⊇ FullIdentity ⊇ SigningIdentity | KeyAgreementIdentity`.

Type guards: `isSigningIdentity`, `isKeyAgreementIdentity`, `isFullIdentity`, `isOwnIdentity`.

The `id` field on every identity is its DID (e.g. `did:key:z6Mk…`). Because the public key is encoded in the DID, any token can be verified by extracting the key from the `iss` claim — no external key lookup required.

**Type system overview:**

```typescript
type Identity = { readonly id: string }

type SigningIdentity = Identity & {
  signToken<Payload, Header>(
    payload: Payload,
    header?: Header,
  ): Promise<SignedToken<Payload, Header>>
}

type KeyAgreementIdentity = Identity & {
  agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array>
}

type FullIdentity = SigningIdentity & KeyAgreementIdentity

type OwnIdentity = FullIdentity & { privateKey: Uint8Array }
```

### Tokens

```typescript
import {
  createUnsignedToken,
  signToken,
  verifyToken,
  isSignedToken,
  isUnsignedToken,
  isVerifiedToken,
  stringifyToken,
} from '@kokuin/token'
```

**Basic sign-and-verify flow:**

```typescript
import {
  randomIdentity,
  createUnsignedToken,
  signToken,
  verifyToken,
  stringifyToken,
} from '@kokuin/token'

const identity = randomIdentity()

// 1. Create an unsigned token with a custom payload
const unsigned = createUnsignedToken({
  sub: 'resource:42',
  aud: 'did:key:z6MkRecipient…',
  exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
})

// 2. Sign it with the identity's private key
const signed = await signToken(identity, unsigned)

// 3. Serialize to a compact dot-separated string (header.payload.signature)
const tokenString = stringifyToken(signed)

// 4. Verify later — no private key required
const verified = await verifyToken(tokenString)
console.log(verified.payload.iss) // identity.id (the issuer DID)
console.log(verified.payload.sub) // 'resource:42'
```

Token type guards: `isSignedToken`, `isUnsignedToken`, `isVerifiedToken`.

**Offline token batch** (create offline, verify on reconnect):

```typescript
import {
  randomIdentity,
  createUnsignedToken,
  signToken,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'

const identity = randomIdentity()
const serialized: string[] = []

for (let i = 0; i < 100; i++) {
  const token = await signToken(identity, createUnsignedToken({ sub: `task-${i}` }))
  serialized.push(stringifyToken(token))
}

// Verify any time, anywhere — public key is embedded in the DID
for (const s of serialized) {
  const verified = await verifyToken(s)
  if (verified.payload.iss === identity.id) {
    console.log('Valid:', verified.payload.sub)
  }
}
```

**Signed payload shape:**

```typescript
type SignedPayload = {
  iss: string         // issuer DID (set automatically from signing identity)
  sub?: string        // subject
  aud?: string        // audience
  cap?: string | Array<string>  // capability token(s) embedded in the request
  exp?: number        // expiry (Unix seconds)
  nbf?: number        // not-before (Unix seconds)
  iat?: number        // issued-at (Unix seconds)
}
```

### Encryption (JWE envelope modes)

JWE support lives in the separate `@kokuin/jwe` package, so verify-only consumers of
`@kokuin/token` do not pay for `@noble/ciphers`.

```typescript
import {
  createTokenEncrypter,
  encryptToken,
  decryptToken,
  wrapEnvelope,
  unwrapEnvelope,
} from '@kokuin/jwe'
import type { EnvelopeMode, TokenEncrypter } from '@kokuin/jwe'
```

| `EnvelopeMode` | Description |
|---|---|
| `'plain'` | Unsigned, unencrypted bare JWT |
| `'jws'` | Signed only (standard JWS) |
| `'jws-in-jwe'` | Signed first, then encrypted |
| `'jwe-in-jws'` | Encrypted first, then signed |

**JWE encrypt / decrypt** (ECDH-ES + A256GCM):

```typescript
import { randomIdentity } from '@kokuin/token'
import {
  createTokenEncrypter,
  encryptToken,
  decryptToken,
} from '@kokuin/jwe'

const recipient = randomIdentity()

// Encrypt for a recipient identified by DID
const encrypter = createTokenEncrypter(recipient.id)
const jwe = await encryptToken(encrypter, new TextEncoder().encode('secret payload'))

// Recipient decrypts with their private identity — decryptToken reads only
// recipient.agreeKey(), so any KeyAgreementIdentity (including a FullIdentity) works
const plaintext = await decryptToken(recipient, jwe)
console.log(new TextDecoder().decode(plaintext)) // 'secret payload'
```

### Raw key agreement — when you need a shared secret, not an envelope

`deriveSharedSecret(did)` performs the same X25519 key agreement as the JWE path, but returns the
raw output instead of building an envelope around it — for callers who want a shared secret as an
input to their own protocol (e.g. one factor among several combined via HKDF), not a JWE.

```typescript
import { randomIdentity } from '@kokuin/token'
import { deriveSharedSecret } from '@kokuin/jwe'

const recipient = randomIdentity()

const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipient.id)
// ship ephemeralPublicKey alongside whatever the secret protects

// Recipient recovers the identical bytes with agreeKey (see `KeyAgreementIdentity` above):
const recovered = await recipient.agreeKey(ephemeralPublicKey)
```

`deriveSharedSecret` resolves the recipient's agreement key by the same rule
`createTokenEncrypter` uses internally, and generates the ephemeral key pair inside the function —
the ephemeral private key never leaves it. Two caveats before you use the result:

- **It is raw ECDH output, not a key.** Run it through a KDF, and bind `ephemeralPublicKey` and
  the recipient DID into that KDF's info/context yourself. The JWE path does not do this either —
  it derives its content key with a fixed `algorithmID` and empty `partyUInfo`/`partyVInfo`, so no
  party identity reaches the KDF; its only per-message binding is `ephemeralPublicKey`, carried in
  the protected header that serves as the AES-GCM AAD. NIST SP 800-56A calls for party identities
  in OtherInfo, and it matters most when this secret is combined with *other* factor secrets via
  HKDF — precisely where cross-factor confusion becomes possible.
- **The agreement is anonymous.** This is ephemeral-static ECDH: anyone holding the recipient's
  DID can mint a valid `{ sharedSecret, ephemeralPublicKey }` pair, so possession of the secret is
  not evidence about who sent it. If you need sender authentication, use the `jws-in-jwe` envelope
  mode instead — the raw API has no equivalent.

**Envelope wrapping** (`jws-in-jwe` — signed, then encrypted):

```typescript
import { randomIdentity } from '@kokuin/token'
import {
  createTokenEncrypter,
  wrapEnvelope,
  unwrapEnvelope,
} from '@kokuin/jwe'
import type { EnvelopeMode } from '@kokuin/jwe'

const signer = randomIdentity()
const recipient = randomIdentity()
const mode: EnvelopeMode = 'jws-in-jwe'

const encrypter = createTokenEncrypter(recipient.id)
const envelope = await wrapEnvelope(mode, { hello: 'world' }, {
  signer,
  encrypter,
})

const unwrapped = await unwrapEnvelope(envelope, { decrypter: recipient })
console.log(unwrapped.payload) // { hello: 'world' }
console.log(unwrapped.mode)    // 'jws-in-jwe'
```

### Key rotation

```typescript
import { createRotationAssertion } from '@kokuin/token'
import type { RotationPayload } from '@kokuin/token'
```

`createRotationAssertion` signs a rotation claim with the **old** identity, declaring the new DID. Verifiers walking a rotation chain follow these assertions to reach the current key.

```typescript
import { createIdentity, createRotationAssertion } from '@kokuin/token'

// Both old and new must be MultiKeyIdentity (use createIdentity)
const oldIdentity = await createIdentity({
  keys: [
    { purpose: 'sig', alg: 'EdDSA' },
    { purpose: 'kem', alg: 'X25519' },
  ],
})
const newIdentity = await createIdentity({
  keys: [
    { purpose: 'sig', alg: 'EdDSA' },
    { purpose: 'kem', alg: 'X25519' },
  ],
})

// Old identity signs the assertion linking it to the new one
const assertion = await createRotationAssertion(oldIdentity, newIdentity)
// assertion.payload.type === 'did-rotation'
// assertion.payload.to   === newIdentity.id
```

---

## Keystores

Keystores persist private keys using each platform's secure storage mechanism. They implement the `KeyStore` / `KeyEntry` contract defined in `@kokuin/token`, and each store exposes `provideIdentity(keyID)`, which gets or creates a key and returns a ready-to-use identity. `@kokuin/ledger-device` is the exception: its key never leaves the device, so it implements `IdentityProvider` alone — no storage contract and no keystore class.

### `@kokuin/node` — Node.js

Uses `@napi-rs/keyring`: macOS Keychain, Windows Credential Manager, Linux Secret Service.

```typescript
import { NodeKeyStore } from '@kokuin/node'

const store = NodeKeyStore.open({ service: 'my-app' })

// Get or create a key; return a FullIdentity
const identity = await store.provideIdentity('main-key')
console.log('DID:', identity.id)

// The same, synchronously
const identitySync = store.provideIdentitySync('main-key')

// Manual entry operations
const entry = store.entry('main-key')
const key = await entry.getAsync()     // Uint8Array | null
const newKey = new Uint8Array(32)      // e.g. a freshly generated key
await entry.setAsync(newKey)
await entry.removeAsync()

// List all stored entries
const entries = await store.listAsync()
```

> `provideIdentitySync` is beyond the `IdentityProvider` contract and is **not** cross-process
> safe: a file lock cannot be acquired synchronously, so it throws when the store was opened
> with a `lockPath`.

Storage locations:
- macOS: `~/Library/Keychains/login.keychain-db`
- Windows: Credential Manager (DPAPI-encrypted)
- Linux: Secret Service (libsecret)

### `@kokuin/browser` — Browser (IndexedDB + Web Crypto)

Uses IndexedDB for persistence and Web Crypto for key generation. Holds a non-extractable
Ed25519 signing key plus the X25519 agreement key derived from it, so a current record both
signs and decrypts — `provideIdentity` returns a `FullIdentity`.

Requires `SubtleCrypto` support for both algorithms: Chrome 137+, Firefox 130+, or Safari 17+.
On an older browser it hard-errors rather than falling back to ES256 — a fallback would mint a
different DID for the same keyID.

Records minted before this requirement (ES256) keep working, but only for signing: WebCrypto
will not let an ECDSA key do `deriveBits`, so a legacy record cannot decrypt. Use
`store.provideSigningIdentity(keyID)` for one — `store.provideIdentity(keyID)` throws on it,
since it promises decryption. Legacy records are never silently re-keyed, since that would
change the identity's DID.

```typescript
import { BrowserKeyStore } from '@kokuin/browser'
import { createUnsignedToken, signToken, stringifyToken } from '@kokuin/token'

// `open()` is memoized per database name — repeated calls resolve the same store
const store = await BrowserKeyStore.open({ name: 'my-app-keys' })

// A FullIdentity — signing and decryption. Throws on a legacy ES256 record.
const identity = await store.provideIdentity('user-session')
console.log('DID:', identity.id)

// Signing-only, accepting both the current and legacy suites
const signingIdentity = await store.provideSigningIdentity('user-session')

// Sign a token
const token = await signToken(identity, createUnsignedToken({
  sub: 'resource:7',
  exp: Math.floor(Date.now() / 1000) + 3600,
}))
const tokenString = stringifyToken(token)
```

Storage: per-origin IndexedDB; survives page reload and browser restart; not synced across devices.

### `@kokuin/expo` — React Native (Expo SecureStore)

Uses Expo SecureStore: iOS Keychain (`kSecAttrAccessibleAfterFirstUnlock`) / Android Keystore.

```typescript
import { ExpoKeyStore } from '@kokuin/expo'

const store = ExpoKeyStore.open()

// Get or create a device identity
const identity = await store.provideIdentity('device-identity')
console.log('DID:', identity.id)

// Manual entry operations
const entry = store.entry('device-identity')
const key = await entry.getAsync()     // Uint8Array | null
await entry.removeAsync()
```

Keys survive app restarts. On logout, call `entry.removeAsync()` to delete the stored key.

### `@kokuin/electron` — Electron (safeStorage)

Uses Electron `safeStorage` for encryption and `electron-store` for persistence. **Main process only** — `safeStorage` is not available in renderer processes.

```typescript
import { ElectronKeyStore } from '@kokuin/electron'
import { createUnsignedToken, signToken } from '@kokuin/token'

const store = ElectronKeyStore.open({ name: 'my-app-keystore' })

// Get or create identity
const identity = await store.provideIdentity('main-process-key')
console.log('DID:', identity.id)

// Sign a token (e.g. for IPC verification)
const token = await signToken(identity, createUnsignedToken({
  sub: 'renderer-process',
  aud: 'main-process',
}))
```

Storage: `electron-store` default location (`~/Library/Application Support/<app>/config.json` on macOS).

### `@kokuin/deterministic` — HD keystore (SLIP-0010 Ed25519)

Derives Ed25519 private keys from a root seed using [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) hierarchical deterministic (HD) derivation. The same seed + path always yields the same key pair — identities are reproducible without persistent storage.

`HDKeyStore` implements `IdentityProvider<FullIdentity>` — call `store.provideIdentity(keyID)`.
Derivation is async-only; there is no sync twin. `derivePrivateKey` remains available for
standalone derivation without a store.

```typescript
import { HDKeyStore, derivePrivateKey, resolveDerivationPath } from '@kokuin/deterministic'
import { createFullIdentity } from '@kokuin/token'

// Managed entries — the store derives on demand
const store = HDKeyStore.fromMnemonic('abandon abandon … art')
// or: HDKeyStore.fromSeed(masterSeed)

const identity = await store.provideIdentity('0')
console.log('DID:', identity.id)

// Standalone derivation (no store required)
const path = resolveDerivationPath('0')                // numeric keyID → "m/44'/876'/0'"
const privateKey = derivePrivateKey(masterSeed, path)  // Uint8Array
const identity2 = createFullIdentity(privateKey)
```

The HD name map: `resolveDerivationPath('0')` → `"m/44'/876'/0'"` (default base path `44'/876'`). Pass a full `m/…` path directly to skip resolution.

### `@kokuin/ledger-device` — Ledger hardware wallet

Provides an `IdentityProvider` backed by a Ledger hardware device over USB/WebHID. Private keys never leave the device — there is no keystore class.

```typescript
import { createLedgerIdentityProvider } from '@kokuin/ledger-device'

// `transport` is a WebHID or Node-HID Ledger transport instance
const provider = createLedgerIdentityProvider(transport)

// Call provideIdentity with a keyID string to obtain a FullIdentity from the device
const identity = await provider.provideIdentity('0')
console.log('Hardware DID:', identity.id)
```

Error types exported from `@kokuin/ledger-device`:
- `LedgerError` — base class
- `LedgerDisconnectedError` — device not connected
- `LedgerAppNotOpenError` — required app not open on device
- `LedgerUserRejectedError` — user rejected on device

---

## Keystore contract

`KeyEntry` and `KeyStore` are the generic types that all keystores implement. They live in `@kokuin/token` (`src/keystore.ts`) — not in any individual keystore package.

```typescript
import type { KeyEntry, KeyStore, MutableKeyEntry } from '@kokuin/token'

type KeyEntry<PrivateKeyType> = {
  readonly keyID: string
  getAsync(): Promise<PrivateKeyType | null>
  provideAsync(): Promise<PrivateKeyType>   // get-or-create
}

type MutableKeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType> & {
  setAsync(privateKey: PrivateKeyType): Promise<void>
  removeAsync(): Promise<void>
}

type KeyStore<
  PrivateKeyType,
  EntryType extends KeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType>,
> = {
  entry(keyID: string): EntryType
}
```

`KeyEntry` is the **read/provide** facet — the floor every backend can honor, including ones
that derive keys rather than store them (HD) or never expose key material at all (ledger).
`MutableKeyEntry` adds writing and deletion.

HD and ledger deliberately do **not** implement `MutableKeyEntry`: an HD key is derived (there
is nothing to set, and removing it does not stop it being derivable), and a ledger key never
leaves the device. The type says what the substrate can do, so there is nothing to throw from.

`provideAsync` is idempotent under concurrency — racing callers on one keyID converge on a
single key. Backends sharing storage across processes need a cross-process lock to hold this
(see `lockPath` on `NodeKeyStore` / `ElectronKeyStore`); an in-process promise chain is not
enough. `entry()` must be cached: `store.entry(x) === store.entry(x)`, since entries carry the
per-entry `provideAsync` lock.

Platform key types:
- `@kokuin/node`, `@kokuin/expo`, `@kokuin/electron`: `Uint8Array` (raw Ed25519 private key)
- `@kokuin/browser`: `StoredKeyRecord` (a non-extractable Web Crypto key record)
- `@kokuin/deterministic`: keys derived on demand; `HDKeyStore.entry(keyID)` returns an `HDKeyEntry` whose `provideAsync()` calls `derivePrivateKey` internally.

`IdentityProvider` (from `@kokuin/token`) decouples identity creation from its backing store:

```typescript
import type { IdentityProvider } from '@kokuin/token'

type IdentityProvider<T extends SigningIdentity = SigningIdentity> = {
  provideIdentity(keyID: string): Promise<T>
}
```

Hardware providers (e.g. `createLedgerIdentityProvider`) return an `IdentityProvider` directly — private keys never leave the device. `HDKeyStore` implements `IdentityProvider<FullIdentity>` directly; call `store.provideIdentity('0')` to get an identity.
