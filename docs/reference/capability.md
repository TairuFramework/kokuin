# Capabilities & Delegation

`@kokuin/capability` implements a capability-based authorization layer on top of the identity primitives in `@kokuin/token`. A root identity (a DID that controls a resource) issues a signed capability token granting scoped `act`/`res` permissions. That token may then be re-delegated — each step narrowing the permission set — forming a verifiable chain that terminates at the root. Revocation plugs into the chain check via a `VerifyTokenHook` so any token in the chain can be rejected without invalidating the issuer's key.

For the underlying identity creation, token signing, and keystore machinery see [./auth.md](./auth.md).

---

## Capability tokens

### Types

```typescript
import type {
  Permission,
  CapabilityPayload,
  CapabilityToken,
  SignCapabilityPayload,
  CreateCapabilityOptions,
} from '@kokuin/capability'
```

**`Permission`** — the authorization claim carried by every capability token:

```typescript
type Permission = {
  act: string | Array<string>
  res: string | Array<string>
}
```

`act` is the action (or list of actions) being authorized; `res` is the resource (or list of resources) targeted. Both fields follow the pattern syntax described in [Permission matching](#permission-matching).

**`CapabilityPayload`** — extends `Permission` with standard JWT-style claims:

```typescript
type CapabilityPayload = Permission & {
  iss: string   // Issuer DID (set by the signer)
  sub: string   // Subject DID (who the capability is for)
  aud: string   // Audience DID (who may present this capability)
  exp?: number  // Expiry (seconds since epoch)
  iat?: number  // Issued-at (seconds since epoch)
  jti?: string  // Unique token ID (used for revocation)
}
```

**`CapabilityToken<Payload, Header>`** — a verified signed token whose payload satisfies `CapabilityPayload`. It is the runtime value returned by `createCapability` and `verifyToken`.

### Creating capabilities

```typescript
import { createCapability } from '@kokuin/capability'
import type { CreateCapabilityOptions, SignCapabilityPayload } from '@kokuin/capability'
```

```typescript
async function createCapability<Payload extends SignCapabilityPayload>(
  signer: SigningIdentity,
  payload: Payload,
  header?: Record<string, unknown>,
  options?: CreateCapabilityOptions,
): Promise<CapabilityToken<Payload & { iss: string }, SignedHeader>>
```

`createCapability` validates the `act`/`res` patterns, signs the payload with `signer`, and returns the resulting `CapabilityToken`.

**Root capability** (signer DID === `sub` DID): no parent required. The signer is the subject — they are asserting a permission they already own.

**Delegated capability** (signer DID !== `sub` DID): `options.parentCapability` (a stringified `CapabilityToken`) is required. The signer must be the `aud` of the parent, and the delegated permission must not exceed the parent's `act`/`res`.

```typescript
type CreateCapabilityOptions = {
  /**
   * Stringified parent capability token authorizing this delegation.
   * Required when signer !== sub.
   */
  parentCapability?: string
}
```

### Guards

```typescript
import { isCapabilityToken, assertCapabilityToken } from '@kokuin/capability'
```

- `isCapabilityToken(token)` — type-guard; returns `true` when `token` is a `CapabilityToken` (verified signed token with valid `iss`, `sub`, `aud`, `act`, `res` fields).
- `assertCapabilityToken(token)` — assertion form; throws `Error('Invalid token: not a capability')` on failure.

---

## Permission matching

Permissions use `/`-separated path patterns with a trailing `*` wildcard.

Pattern rules enforced by `assertValidPattern`:
- `'*'` alone matches everything.
- Components are alphanumeric plus `_`, `-`, `.`, `:`.
- A `*` wildcard is only valid as the **last** component (`docs/*` is valid; `docs/*/edit` is not).
- No leading/trailing slashes, no double slashes, no path traversal (`../`, `./`).

```typescript
import {
  assertValidPattern,
  isMatch,
  hasPartsMatch,
  hasPermission,
} from '@kokuin/capability'
```

| Function | Signature | Purpose |
|---|---|---|
| `assertValidPattern` | `(value: string \| Array<string>) => void` | Throw if pattern is invalid |
| `isMatch` | `(expected: string, actual: string) => boolean` | Exact match or `actual === '*'` |
| `hasPartsMatch` | `(expected: string, actual: string) => boolean` | Path prefix/wildcard match |
| `hasPermission` | `(expected: Permission, granted: Permission) => boolean` | Full permission subsumption check |

`hasPermission(expected, granted)` returns `true` when `granted` covers `expected`: it handles arrays on either side and delegates to `isMatch`/`hasPartsMatch` for the leaf comparison.

```typescript
import { hasPermission } from '@kokuin/capability'

// Exact match
hasPermission({ act: 'read', res: 'docs/report' }, { act: 'read', res: 'docs/report' }) // true

// Wildcard match
hasPermission({ act: 'read', res: 'docs/report' }, { act: '*', res: 'docs/*' }) // true

// Permission not covered
hasPermission({ act: 'write', res: 'docs/report' }, { act: 'read', res: 'docs/*' }) // false
```

---

## Delegation chains

A delegation chain is an ordered list of stringified `CapabilityToken`s linking a request back to a root capability. Each link must narrow (or equal) the permissions of its parent and must have the parent's `aud` as its `iss`.

```typescript
import {
  DEFAULT_MAX_DELEGATION_DEPTH,
  assertValidDelegation,
  checkDelegationChain,
  checkCapability,
  assertNonExpired,
  assertValidIssuedAt,
} from '@kokuin/capability'
import type { DelegationChainOptions } from '@kokuin/capability'
```

**`DEFAULT_MAX_DELEGATION_DEPTH`** — `4`. The maximum number of links accepted by `checkDelegationChain`/`checkCapability` before rejecting the chain.

**`DelegationChainOptions`**:

```typescript
type DelegationChainOptions = {
  /** Reference time for expiry checks (seconds since epoch). Defaults to now(). */
  atTime?: number
  /** Maximum chain depth. Defaults to DEFAULT_MAX_DELEGATION_DEPTH (4). */
  maxDepth?: number
  /** Hook called for each token after signature verification. Throw to reject. */
  verifyToken?: VerifyTokenHook
  /** Optional DID cache for did:peer:4 short-form resolution. */
  cache?: DIDCache
  /** Optional resolver for did:peer:4 short forms not in cache. */
  resolver?: DIDResolver
}
```

**`assertNonExpired(payload, atTime?)`** — throws if `payload.exp` is in the past relative to `atTime` (defaults to `now()`).

**`assertValidIssuedAt(payload, atTime?)`** — throws if `payload.iat` is in the future relative to `atTime`.

**`assertValidDelegation(from, to, atTime?)`** — validates a single delegation step: `to.iss` must equal `from.aud`, `to.sub` must equal `from.sub`, `from` must be non-expired and have a valid issued-at, and `to`'s permission must be a subset of `from`'s.

**`checkDelegationChain(payload, capabilities, options?)`** — recursively validates a full chain. `capabilities` is the ordered list of stringified parent tokens (head = immediate parent, tail = grandparents toward root). The root token is valid when `iss === sub` (self-issued).

**`checkCapability(permission, payload, options?)`** — the top-level entry point. Given a `permission` being requested and a signed `payload` (from the incoming token), it checks that the payload grants the permission either directly (self-issued) or via its `cap` delegation chain.

```typescript
async function checkCapability(
  permission: Permission,
  payload: SignedPayload,     // from @kokuin/token
  options?: DelegationChainOptions,
): Promise<void>
```

---

## Revocation

Revocation is implemented as a `VerifyTokenHook` injected into `DelegationChainOptions.verifyToken`. The hook is called for every token in a chain after signature verification; throwing rejects the chain.

```typescript
import {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
} from '@kokuin/capability'
import type {
  RevocationBackend,
  RevocationRecord,
  VerifyTokenHook,
} from '@kokuin/capability'
```

**`VerifyTokenHook`**:

```typescript
type VerifyTokenHook = (token: CapabilityToken, raw: string) => void | Promise<void>
```

**`RevocationRecord`** — a **signed token**, not a plain object. The claims below are its *payload*:

```typescript
type RevocationRecord = SignedToken<RevocationClaims>

type RevocationClaims = {
  jti: string   // Token ID being revoked
  rev: true
  iat: number   // Revocation timestamp (seconds since epoch)
}
```

`iss` is stamped by `signToken` from the signer's own DID, so a caller cannot mint a record for another issuer. The signature is what the "only a token's own issuer may revoke it" guarantee rests on: the checker compares the record's `iss` to the token's, and an unsigned record would let anyone revoke anyone.

**`RevocationBackend`** — interface for the revocation store:

```typescript
type RevocationBackend = {
  add(record: RevocationRecord): Promise<void>
  get(jti: string): Promise<RevocationRecord | undefined>
}
```

It answers with the *record*, not with a boolean: the checker re-verifies the signature at the point of use, because a backend is an extension point and may return something it never verified.

**`createMemoryRevocationBackend(options?)`** — returns an in-memory `RevocationBackend` backed by a `Map`. `add` verifies the record's signature and throws `Invalid revocation record` on one that does not check out. Suitable for single-process use; does not survive restarts.

**`createRevocationRecord(signer, jti)`** — **signs** `{ jti, rev: true, iat }` with `signer`, producing the record. The caller is responsible for persisting it via `backend.add(record)`.

**`createRevocationChecker(backend)`** — wraps a `RevocationBackend` as a `VerifyTokenHook`. Wire it via `DelegationChainOptions.verifyToken`:

```typescript
import { createMemoryRevocationBackend, createRevocationChecker, checkCapability } from '@kokuin/capability'

const backend = createMemoryRevocationBackend()
const checker = createRevocationChecker(backend)

// Later, to revoke a token:
const record = await createRevocationRecord(revokerIdentity, jtiToRevoke)
await backend.add(record)

// Check with revocation enabled:
await checkCapability(permission, signedPayload, { verifyToken: checker })
```

---

## Identity providers

`IdentityProvider<T>` (from `@kokuin/token`) is the abstraction that decouples identity creation from the backing key store. Its shape is `{ provideIdentity(keyID: string): Promise<T> }`. Two provider backends are relevant to the capability domain:

**Software HD keys — `@kokuin/deterministic`**

`HDKeyStore` derives Ed25519 keys from a BIP39 mnemonic via SLIP-0010 and implements `IdentityProvider<FullIdentity>` directly. Call `store.provideIdentity('0')` to get a `FullIdentity` (no separate wrapper needed). Suitable for non-interactive delegation signing (servers, automated agents).

```typescript
import { HDKeyStore, derivePrivateKey, resolveDerivationPath } from '@kokuin/deterministic'
import { createSigningIdentity } from '@kokuin/token'
```

**Hardware Ledger — `@kokuin/ledger-device`**

`createLedgerIdentityProvider` returns an `IdentityProvider<FullIdentity>` backed by a Ledger hardware wallet via the BOLOS APDU app. Private keys never leave the device; signing happens on-chip. Appropriate for high-value root capabilities.

```typescript
import { createLedgerIdentityProvider } from '@kokuin/ledger-device'

const provider = createLedgerIdentityProvider(transport)   // positional LedgerTransport
const identity = await provider.provideIdentity('0')        // keyID string → FullIdentity
```

---

## Worked example

```typescript
import { createCapability, checkCapability, hasPermission } from '@kokuin/capability'
import type { Permission } from '@kokuin/capability'
import { randomIdentity, stringifyToken, signToken, createUnsignedToken } from '@kokuin/token'
import type { SigningIdentity } from '@kokuin/token'

// --- Step 1: root identity creates a root capability ---
const rootIdentity: SigningIdentity = randomIdentity()
const delegateIdentity: SigningIdentity = randomIdentity()
const consumerIdentity: SigningIdentity = randomIdentity()

const rootCap = await createCapability(rootIdentity, {
  sub: rootIdentity.id,   // signer === subject → root capability
  aud: delegateIdentity.id,
  act: 'read',
  res: 'docs/*',
  exp: Math.floor(Date.now() / 1000) + 3600,
})
// rootCap is a CapabilityToken; stringify it before passing as parentCapability
const rootCapStr = stringifyToken(rootCap)

// --- Step 2: delegate narrows the capability and re-delegates ---
const delegatedCap = await createCapability(
  delegateIdentity,
  {
    sub: rootIdentity.id,          // same subject as root
    aud: consumerIdentity.id,
    act: 'read',
    res: 'docs/report',            // narrower than 'docs/*'
  },
  undefined,
  { parentCapability: rootCapStr }, // links back to the root
)
// stringify before embedding in the consumer token's `cap` claim (a string)
const delegatedCapStr = stringifyToken(delegatedCap)

// --- Step 3: verify the chain ---
// The consumer presents a payload claiming the permission they were granted.
// checkCapability resolves the cap chain and verifies every link.
const requestedPermission: Permission = { act: 'read', res: 'docs/report' }

const consumerToken = await signToken(consumerIdentity, createUnsignedToken({
  sub: rootIdentity.id,
  act: 'read',
  res: 'docs/report',
  cap: delegatedCapStr,
}))
const consumerPayload = consumerToken.payload

await checkCapability(requestedPermission, consumerPayload, {
  // optionally inject revocation:
  // verifyToken: createRevocationChecker(backend),
})
// Resolves → permission granted; throws → denied
```
