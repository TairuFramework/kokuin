---
name: kokuin:auth
description: Identity & key patterns — token generation, verification, encryption, and per-environment keystores
---

# Kokuin Authentication & Identity

## Packages in This Domain

**Token System**: `@kokuin/token`

**Platform Keystores**: `@kokuin/node`, `@kokuin/browser`, `@kokuin/expo`, `@kokuin/electron`, `@kokuin/deterministic`, `@kokuin/ledger-device`

## Key Patterns

### Pattern 1: Generating and Verifying Tokens

```typescript
import {
  randomIdentity,
  createUnsignedToken,
  signToken,
  verifyToken,
  stringifyToken,
} from '@kokuin/token'

// Generate an identity with a random private key
const identity = randomIdentity()
console.log('Identity DID:', identity.id) // did:key:z...

// Create an unsigned token with custom claims
const unsigned = createUnsignedToken({
  sub: 'user-123',
  aud: 'did:key:z6MkRecipient…',
  exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
})

// Sign it with the identity's private key
const signed = await signToken(identity, unsigned)

// Serialize to compact format (header.payload.signature)
const tokenString = stringifyToken(signed)

// Verify — public key is embedded in the DID, no key distribution required
const verified = await verifyToken(tokenString)
console.log(verified.payload.iss) // identity.id (the issuer DID)
console.log(verified.payload.sub) // 'user-123'
```

**Use case**: JWT-like authentication tokens with DID-based identity

**Key points**:
- Tokens use EdDSA or ES256 signature algorithms
- Issuer (`iss`) is automatically set to the identity's DID (decentralized identifier)
- DIDs encode both algorithm and public key: `did:key:z<base58-encoded>`
- Token verification extracts the public key from the DID and validates the signature — no external key lookup required
- Supports standard JWT claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `cap`
- Tokens can be serialized to JWT format or used as objects

### Pattern 2: Using Node.js Keystore for Secure Storage

```typescript
import { NodeKeyStore } from '@kokuin/node'
import { createUnsignedToken, signToken, stringifyToken } from '@kokuin/token'

// Open a keystore (uses OS-level credential storage)
const store = NodeKeyStore.open({ service: 'my-app' })

// Get or create a FullIdentity from a named key
const identity = await store.provideIdentity('user-auth-key')
console.log('DID:', identity.id)

// Sign a token
const token = await signToken(identity, createUnsignedToken({
  sub: 'user-456',
  aud: 'my-service',
  exp: Math.floor(Date.now() / 1000) + 86400, // 24 hours
}))
const tokenString = stringifyToken(token)

// Manual entry operations
const entry = store.entry('user-auth-key')
const key = await entry.getAsync()    // Uint8Array | null
await entry.removeAsync()

// List all keys in store
const allEntries = await store.listAsync()
for (const e of allEntries) {
  console.log('Key ID:', e.keyID)
}
```

**Use case**: Server-side key management with OS-level security (macOS Keychain, Windows Credential Manager, Linux Secret Service)

**Key points**:
- Keys stored in OS credential manager (not in files)
- Automatic key generation on first use via `provideAsync()`
- Both sync and async APIs available (prefer async in production)
- Each service can have multiple keys identified by keyID
- `store.provideIdentity(keyID)` returns a `FullIdentity`; `store.provideIdentitySync(keyID)` is the sync twin, which throws when the store was opened with a `lockPath` (a file lock cannot be acquired synchronously)

### Pattern 3: Browser Keystore with IndexedDB

```typescript
import { BrowserKeyStore } from '@kokuin/browser'
import { createUnsignedToken, signToken, stringifyToken } from '@kokuin/token'

// `open()` is memoized per database name — repeated calls resolve the same store
const store = await BrowserKeyStore.open({ name: 'my-app-keys' })

// A FullIdentity — signing and decryption. Throws on a legacy ES256 record.
const identity = await store.provideIdentity('session-key')

// Signing-only, accepting both the current and legacy suites
const signingIdentity = await store.provideSigningIdentity('session-key')

// Sign a token with the browser identity
const token = await signToken(identity, createUnsignedToken({
  sub: 'resource:7',
  exp: Math.floor(Date.now() / 1000) + 3600,
}))
const tokenString = stringifyToken(token)

// Clean up when the user logs out
const entry = store.entry('session-key')
await entry.removeAsync()
```

**Use case**: Browser-based authentication with persistent keys

**Key points**:
- Uses IndexedDB for persistent storage across page reloads
- Holds a non-extractable Ed25519 signing key plus the X25519 agreement key derived from it — a current record both signs and decrypts
- Requires `SubtleCrypto` support for both algorithms: Chrome 137+, Firefox 130+, Safari 17+. Older browsers hard-error rather than falling back to ES256, since a fallback would mint a different DID for the same keyID
- Legacy ES256 records sign but cannot decrypt (WebCrypto will not let an ECDSA key do `deriveBits`). `store.provideIdentity(keyID)` throws on one; use `store.provideSigningIdentity(keyID)`. They are never silently re-keyed — that would change the DID
- All operations are async (IndexedDB requirement)
- Keys survive browser restart but are per-origin

### Pattern 4: Multi-Platform Mobile with Expo Keystore

```typescript
import { ExpoKeyStore } from '@kokuin/expo'
import { createUnsignedToken, signToken, stringifyToken } from '@kokuin/token'

// The process-wide store (uses Expo SecureStore)
const store = ExpoKeyStore.open()

// Get or create a device identity
const identity = await store.provideIdentity('device-identity')
console.log('DID:', identity.id)

// Sign a token
const token = await signToken(identity, createUnsignedToken({
  sub: 'sync-request',
  exp: Math.floor(Date.now() / 1000) + 300,
}))
const tokenString = stringifyToken(token)

// Remove key when needed (e.g. app uninstall or logout)
const entry = store.entry('device-identity')
await entry.removeAsync()
```

**Use case**: React Native mobile apps with platform-native secure storage

**Key points**:
- Uses Expo SecureStore for encrypted key storage
- iOS: stored in Keychain (`kSecAttrAccessibleAfterFirstUnlock`)
- Android: stored in EncryptedSharedPreferences backed by Android Keystore
- Keys persist across app restarts; EdDSA algorithm (Ed25519)
- Both sync and async APIs available

### Pattern 5: Electron App with Encrypted Storage

```typescript
import { ElectronKeyStore } from '@kokuin/electron'
import { createUnsignedToken, signToken } from '@kokuin/token'

// Open keystore (uses electron-store with safeStorage)
const store = ElectronKeyStore.open({ name: 'app-keystore' })

// Get or create identity
const identity = await store.provideIdentity('main-process-key')
console.log('DID:', identity.id)

// Sign a token (e.g. for IPC verification in the renderer)
const ipcToken = await signToken(identity, createUnsignedToken({
  sub: 'renderer-process',
  aud: 'main-process',
  exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
}))

// Clean up
const entry = store.entry('main-process-key')
await entry.removeAsync()
```

**Use case**: Electron desktop apps with OS-native encryption

**Key points**:
- Uses Electron `safeStorage` for platform-native encryption (DPAPI / Keychain / libsecret)
- Stores encrypted keys in `electron-store` (persistent JSON)
- **Main process only** — `safeStorage` is not available in renderer processes
- Keys survive app restart and system reboot

### Pattern 6: Deterministic HD Keystore (SLIP-0010 Ed25519)

```typescript
import { HDKeyStore, derivePrivateKey, resolveDerivationPath } from '@kokuin/deterministic'
import { createFullIdentity } from '@kokuin/token'

// Managed entries — the store derives on demand
const store = HDKeyStore.fromMnemonic('abandon abandon … art')
// or: HDKeyStore.fromSeed(masterSeed)

const identity = await store.provideIdentity('0')
console.log('DID:', identity.id)

// Standalone derivation — same seed + path always yields the same key pair
const path = resolveDerivationPath('0')               // numeric keyID → "m/44'/876'/0'"
const privateKey = derivePrivateKey(masterSeed, path) // Uint8Array
const identity2 = createFullIdentity(privateKey)
```

**Use case**: Reproducible identities from a seed phrase — no persistent storage required

**Key points**:
- SLIP-0010 hierarchical deterministic (HD) derivation; Ed25519 curve
- Same seed + path → same identity; identities are fully reproducible
- `HDKeyStore` implements `IdentityProvider<FullIdentity>` — call `store.provideIdentity(keyID)`. Async-only; there is no sync twin
- `resolveDerivationPath` maps a numeric keyID to the default base path (`m/44'/876'/<n>'`)

### Pattern 7: Ledger Hardware Wallet

```typescript
import { createLedgerIdentityProvider } from '@kokuin/ledger-device'
import type { IdentityProvider } from '@kokuin/token'
import { createUnsignedToken, signToken } from '@kokuin/token'

// `transport` is a WebHID or Node-HID Ledger transport instance
const provider = createLedgerIdentityProvider(transport)

// Call provideIdentity with a keyID string to get a FullIdentity from the device
const identity = await provider.provideIdentity('0')
console.log('Hardware DID:', identity.id)

// Sign a token — private key never leaves the device
const token = await signToken(identity, createUnsignedToken({
  sub: 'secure-action',
  exp: Math.floor(Date.now() / 1000) + 300,
}))
```

**Use case**: High-security environments where private keys must never leave hardware

**Key points**:
- `createLedgerIdentityProvider` returns an `IdentityProvider<FullIdentity>` (not a keystore class); it implements neither `KeyStore` nor `MutableKeyEntry`, since the key never leaves the device
- Private keys never leave the Ledger device
- Error types: `LedgerError`, `LedgerDisconnectedError`, `LedgerAppNotOpenError`, `LedgerUserRejectedError`

### Pattern 8: Message-Level Encryption with JWE

```typescript
import {
  randomIdentity,
  createTokenEncrypter,
  encryptToken,
  decryptToken,
  wrapEnvelope,
  unwrapEnvelope,
} from '@kokuin/token'
import type { EnvelopeMode } from '@kokuin/token'

// Sender and recipient identities
const sender = randomIdentity()
const recipient = randomIdentity()

// Create encrypter targeting the recipient's DID
const encrypter = createTokenEncrypter(recipient.id)

// Low-level: encrypt raw bytes
const plaintext = new TextEncoder().encode('secret message')
const jwe = await encryptToken(encrypter, plaintext)
// jwe is a JWE compact serialization string (5 dot-separated parts)

const decrypted = await decryptToken(recipient, jwe)
new TextDecoder().decode(decrypted) // 'secret message'

// High-level: envelope wrapping (sign, then encrypt — hides sender identity)
const mode: EnvelopeMode = 'jws-in-jwe'
const wrapped = await wrapEnvelope(mode, { hello: 'world' }, {
  signer: sender,
  encrypter,
})

const { payload, mode: unwrappedMode } = await unwrapEnvelope(wrapped, { decrypter: recipient })
console.log(unwrappedMode) // 'jws-in-jwe'
console.log(payload)       // { hello: 'world' }
```

**Use case**: End-to-end encryption where intermediaries (proxies, logs) cannot read payloads

**Key points**:
- Uses ECDH-ES (X25519) key agreement with A256GCM content encryption
- `createTokenEncrypter` accepts a DID string or raw X25519 public key
- JWE compact serialization: `header.encryptedKey.iv.ciphertext.tag`
- Fresh ephemeral key pair per encryption (forward secrecy)
- Four envelope modes: `plain`, `jws`, `jws-in-jwe`, `jwe-in-jws`
- `jws-in-jwe` hides sender identity; `jwe-in-jws` allows routing by sender
- Ed25519 keys are auto-converted to X25519 for ECDH

## When to Use What

**Use `@kokuin/token`** when:
- Need to generate or verify authentication tokens
- Implementing custom token signing logic
- Working with DIDs and decentralized identity
- Need low-level token operations
- Need to encrypt payloads with JWE
- Working with envelope modes (`plain`, `jws`, `jws-in-jwe`, `jwe-in-jws`)

**Use `@kokuin/node`** when:
- Building Node.js servers or CLI tools
- Need OS-level key security
- Running on macOS, Windows, or Linux
- Want keys accessible across processes

**Use `@kokuin/browser`** when:
- Building web applications (SPA, PWA)
- Need persistent browser-based authentication
- Want Web Crypto security (non-extractable Ed25519 + derived X25519 keys)
- Client-side signing and decryption required (Chrome 137+, Firefox 130+, Safari 17+)

**Use `@kokuin/expo`** when:
- Building React Native apps with Expo
- Need iOS Keychain or Android Keystore
- Want platform-native security for mobile
- Need encrypted key backup support

**Use `@kokuin/electron`** when:
- Building Electron desktop applications
- Need encrypted key storage in the main process
- Want OS-native encryption (DPAPI, Keychain, libsecret)

**Use `@kokuin/deterministic`** when:
- Need reproducible identities from a seed phrase or master key
- Prefer derivation over persistent storage (e.g. key recovery scenarios)
- Building HD wallet or multi-account patterns

**Use `@kokuin/ledger-device`** when:
- Require hardware-backed keys that never leave the device
- Building high-security signing flows (WebHID browser or Node-HID desktop)

→ Reference: docs/reference/auth.md
