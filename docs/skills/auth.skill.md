---
name: kokuin:auth
description: Identity & key patterns — token generation, verification, encryption, and per-environment keystores
---

# Kokuin Authentication & Identity

## Packages in This Domain

**Token System**: `@kokuin/token`

**Message Encryption**: `@kokuin/jwe`

**Controller / DID Method**: `@kokuin/controller`

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
import { randomIdentity } from '@kokuin/token'
import {
  createTokenEncrypter,
  encryptToken,
  decryptToken,
  wrapEnvelope,
  unwrapEnvelope,
} from '@kokuin/jwe'
import type { EnvelopeMode } from '@kokuin/jwe'

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
- Need the shared secret itself, not a JWE (e.g. as one HKDF input among several)?
  `@kokuin/jwe`'s `deriveSharedSecret(did)` returns `{ sharedSecret, ephemeralPublicKey }` raw —
  see `docs/reference/auth.md`'s "Raw key agreement" section for the KDF-context and
  sender-anonymity caveats before using it

### Pattern 9: Encrypting to a `did:kokuin:` Controller

`did:kokuin:` is a self-certifying DID whose key set lives in a folded key event log rather than
in the identifier itself, so resolving it needs a registered `DIDMethodResolver` — the sync JWE
entry points (`createTokenEncrypter`, `deriveSharedSecret`) cannot reach it; use the async
siblings with `createControllerResolver` registered.

```typescript
import { createTokenEncrypterAsync, decryptToken, encryptToken } from '@kokuin/jwe'
import { x25519 } from '@noble/curves/ed25519.js'
import {
  agreementPath,
  createControllerResolver,
  createInception,
  deriveKeyPair,
  didFromInception,
} from '@kokuin/controller'

const seed = new Uint8Array(32).fill(3)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)

// Any log loader works — this one is a fixed in-memory log.
const resolver = createControllerResolver({ loadLog: async () => [inception] })

const encrypter = await createTokenEncrypterAsync(did, { methods: [resolver] })
const jwe = await encryptToken(encrypter, new TextEncoder().encode('hello'))

// The profile holder derives the same agreement key from the seed to decrypt.
const agreement = deriveKeyPair(seed, agreementPath(0, 0, 0), 'X25519')
const recipient = {
  id: did,
  agreeKey: async (ephemeralPublicKey: Uint8Array) =>
    x25519.getSharedSecret(agreement.privateKey, ephemeralPublicKey),
}

const decrypted = await decryptToken(recipient, jwe)
new TextDecoder().decode(decrypted) // 'hello'
```

**Use case**: encrypting to a `did:kokuin:` recipient whose keys may have rotated since the
message was addressed

**Key points**:
- `createInception(seed, profile)` derives a deterministic inception event; `didFromInception`
  hashes it into the DID — same seed and profile index always produce the same DID
- `createControllerResolver({ loadLog })` adapts a folded event log into a `DIDMethodResolver`;
  `loadLog(did)` returns the DID's signed-event log, or `undefined` for an unknown DID. The whole
  log is correct **only when no `verifyCapability` is configured** — with one, answer with the log
  up to the event being verified, since verifying a capability resolves its issuer, which is the
  same profile, which folds the log and reaches the same event again. That deadlocks the DID's
  resolution on that resolver instance, quietly and unrecoverably; see Pattern 10 and
  `ControllerResolverOptions.loadLog`
- Reuse one resolver instance rather than building one per resolution: concurrent resolutions of
  one DID share a single fold, and a fresh instance per hop shares nothing
- Resolution happens once, inside `createTokenEncrypterAsync` — the resolved agreement key is
  closed over by the returned encrypter, and `encryptToken` itself resolves nothing (it just
  calls `encrypter.encrypt`). So an encrypter snapshots whatever `ka` was current in the folded
  log *at construction time*: build it after a rotation and it targets the rotated key; keep an
  encrypter around across a later rotation and it keeps encrypting to the now-superseded key. See
  `packages/controller/test/encrypt-to-profile.test.ts` for the round trip through a rotate
- The recipient side never touches the resolver: it re-derives the same agreement key pair from
  the seed and the profile's `agreementPath`, and implements `KeyAgreementIdentity` (`{ id, agreeKey }`)

### Pattern 10: Issuing and Verifying Tokens as a `did:kokuin:` Controller

A `did:kokuin:` profile can be the `iss` of a token in both directions: `createControllerIdentity`
produces a `SigningIdentity` whose `id` is the profile DID, and `verifyToken` resolves that `iss`
when the same `DIDMethodResolver` is passed as `methods`.

```typescript
import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRotate,
  didFromInception,
} from '@kokuin/controller'
import { createUnsignedToken, signToken, verifyToken } from '@kokuin/token'

const seed = new Uint8Array(32).fill(7)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const log = [inception, createRotate(seed, 0, did, inception.event)]

// Folds the log and derives the authority key the *current* state establishes.
const identity = createControllerIdentity(seed, 0, log)
identity.id // the did:kokuin: DID, not a did:key:

const token = await signToken(identity, createUnsignedToken({ hello: 'world' }))

const resolver = createControllerResolver({ loadLog: async () => log })
const verified = await verifyToken(token, { methods: [resolver] })
verified.payload.iss // === did
```

**Use case**: a profile acting as a token issuer — self-issued capabilities, service tokens, or
any claim whose subject is the profile rather than a device

**Key points**:
- `createControllerIdentity(seed, profile, log)` takes the **log**, not a `{ gen, seq }` position.
  What that buys is narrow but real: the caller cannot name a position, so the signing key always
  matches the log it was handed. **The log is still the caller's freshness contract** — build an
  identity from a stale or truncated log and it signs with whatever key that log's head
  established. That is survivable across a `rotate` (a verifier accepts any key that was
  authoritative within the current generation) and fatal across a `reset`, which discards the prior
  generation: those tokens fail with `kid names a key outside the current generation`. Re-read the
  log and rebuild the identity after a reset; caching one across a rotate is merely stale
- It throws when the log does not fold, and when the derived key is not one of the current
  authority keys — a wrong `seed` or a wrong `profile` for that log
- The key it derives sits at the fold's `keyGen`/`keySeq` — where the current keys were
  *established* — not at `gen`/`seq`, which is the position of the last event. A revoke advances
  the sequence without establishing a key, so the two diverge
- A revoke carrying a capability (`cap`) authorises a non-authority signer, and verifying that
  capability is async. `createControllerIdentity` stays synchronous and throws on such a log; use
  `createControllerIdentityAsync(seed, profile, log, { verifyCapability })` for one, and give
  `createControllerResolver` a `verifyCapability` too so the verifier side folds it.
  Without a verifier both still fail closed rather than trusting the capability.
  `createControllerCapabilityVerifier` (`@kokuin/capability`) is the real implementation of that
  callback. **It takes two resolvers, not one.** The verifier's own `methods` registry must contain
  a *separate* resolver whose `loadLog` answers with the **prefix** — the log up to the event
  carrying the capability — never the resolver being configured and never one over the full log:

  ```typescript
  import { createControllerCapabilityVerifier } from '@kokuin/capability'

  // `prefix` is the log up to the event carrying the capability.
  const issuers = [createControllerResolver({ loadLog: async () => prefix })]
  const resolver = createControllerResolver({
    loadLog: async () => log,
    verifyCapability: createControllerCapabilityVerifier({ methods: issuers }),
  })
  ```

  Reaching for a single shared resolver — the same instance in both places, or a second one over
  the full log — is the natural-looking shape and it **never settles**: the capability is issued by
  the very profile whose log carries the revoke, so resolving its issuer folds that log, reaches the
  same revoke, and verifies the capability again. `verifyToken` then stays pending forever, and
  because the unsettleable fold stays in flight, every later resolution of that DID on that instance
  joins it. There is no error and no diagnosis — build a new resolver and fix the wiring. Reuse each
  of the two instances rather than minting them per resolution: one resolver per role, not one per
  process and not one per hop

  A capability authorising a revoke must also pin its audience's key in `cnf.kid`
  (`audienceConfirmation(key)`); one without it is rejected rather than resolved, so that the
  audience rotating its own key can never make this profile unresolvable
- Without `methods`, `verifyToken` fails with `Unknown DID` — the identifier carries no key.
  `did:key` and `did:peer:4` need no entry
- `checkCapability` / `checkDelegationChain` (`@kokuin/capability`) take the same `methods` option
  and forward it to every `verifyToken` in the chain, as do `createCapability` (for its
  parent-capability check) and `createRevocationChecker` / `createMemoryRevocationBackend` (for the
  record's issuer). A `did:kokuin:` issuer needs `methods` at each of those call sites: without it
  delegation fails, and a revocation record whose issuer cannot be resolved *at all* fails the
  verification closed. A record the registry can resolve but whose signature or `kid` does not check
  out is ignored instead — it is evidence about the record, not about revocation
- **The deny set is enforced through the same `methods` registry.** A `rev` event adds a DID to the
  profile's deny set, and `checkCapability` / `checkDelegationChain` reject any capability whose
  `aud` is in the deny set of its `sub` — every link in the chain, not just the leaf. That check
  reads `DIDMethodResolver.resolveDenySet`, which `createControllerResolver` implements, so a
  registry wired for resolution is wired for enforcement; there is no second option to forget. It is
  evaluated against the log's **current** head, never against a position the capability names —
  `iat` is author-supplied and backdatable. A profile clears a denial with a deny-set snapshot
  (`createRotate(…, { deny: [] })`) or with a `reset`
- **Key selection**: a controller's `k` is a *set*. Every token `createControllerIdentity` signs
  carries `kid: "#<the multibase key exactly as it appears in `k`>"`, and the resolver matches that
  against the folded key sets by membership. A header with no `kid` still resolves to the head's
  `k[0]`, so single-key profiles are unaffected
- **A `kid` resolves against the whole current generation**, not only the head's `k`. A `rotate` is
  routine hygiene, so it must not invalidate the tokens, capabilities and revocation records the
  profile has already issued — including ones held by third parties who cannot know a rotation
  happened. A `reset` is what invalidates: it bumps the generation, and every key from the prior one
  stops resolving. A `kid` naming a key this profile never published, or one from a superseded
  generation, is an error — never a fall back to `k[0]`
- That error is an `IssuerKeyNotFoundError` (`@kokuin/token`, guard `isIssuerKeyNotFoundError`),
  **not** an `UnresolvableIssuerError`: the DID resolved and its log folded; only the key the token
  named was missing. The classification matters because fail-closed callers key on the second type —
  and `kid` is an unauthenticated header field, so a fabricated record naming a real `did:kokuin:`
  DID and an invented key would otherwise deny every capability that issuer holds. `did:peer:4`
  answers the same condition with a plain `KidNotFound`; the two methods agree
- The identity takes no `kid`: it derives exactly one key pair, so the `kid` is a fact about the
  signature. Passing a `kid` naming another key to `signToken` is rejected rather than ignored

## When to Use What

**Use `@kokuin/token`** when:
- Need to generate or verify authentication tokens
- Implementing custom token signing logic
- Working with DIDs and decentralized identity
- Need low-level token operations

**Use `@kokuin/jwe`** when:
- Need to encrypt payloads with JWE (ECDH-ES + A256GCM)
- Working with envelope modes (`plain`, `jws`, `jws-in-jwe`, `jwe-in-jws`)
- Need a raw ECDH shared secret rather than a full envelope

**Use `@kokuin/controller`** when:
- Need a self-certifying DID (`did:kokuin:`) whose key set can rotate without changing the
  identifier
- Building or resolving a folded key event log (inception, rotation, reset, revocation)
- Encrypting to a `did:kokuin:` recipient through a registered `DIDMethodResolver`
- Issuing tokens whose `iss` is a `did:kokuin:` profile (`createControllerIdentity`), or verifying
  them (`verifyToken`/`checkCapability` with `methods`)

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
