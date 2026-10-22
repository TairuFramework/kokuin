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
  cnf?: ConfirmationClaim  // Proof-of-possession key the audience must hold (RFC 7800)
  mbr?: MemberClaim        // Present on a root issued by a management member of `sub`
}

type MemberClaim = { add: string; g: number }  // the issuer's add digest and the subject's generation
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

**Member-issued capability** (signer is a management member of a `did:kokuin:` `sub`): `options.member` names the signer's membership, and the capability is a chain root with no parent. See [Grants issued by management members](#grants-issued-by-management-members).

**Delegated capability** (signer DID !== `sub` DID, no `member`): `options.parentCapability` (a stringified `CapabilityToken`) is required. The signer must be the `aud` of the parent, and the delegated permission must not exceed the parent's `act`/`res`.

```typescript
type CreateCapabilityOptions = {
  /** Stringified parent capability authorizing this delegation. Required when signer !== sub, unless `member` is given. */
  parentCapability?: string
  /** Mint as a management member of `sub`: written as the `mbr` claim. Requires `exp` and `iat`, with `exp >= iat`. */
  member?: MemberClaim
  /** Resolution inputs forwarded to `verifyToken` when verifying the parent. */
  cache?: DIDCache
  resolver?: DIDResolver
  methods?: MethodRegistry
  verifiers?: Verifiers
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
  /** DID method registry: required for `did:kokuin:` links and subjects. Pass one `resolver.frozen()` view per verification. */
  methods?: MethodRegistry
  /** Signature verifiers, forwarded to every `verifyToken`. */
  verifiers?: Verifiers
  /** Longest `exp - iat` of a member-issued grant, in seconds. Defaults to DEFAULT_MEMBER_GRANT_LIFETIME (43200, 12 hours). */
  maxMemberGrantLifetime?: number
}
```

**`assertNonExpired(payload, atTime?)`** — throws if `payload.exp` is in the past relative to `atTime` (defaults to `now()`).

**`assertValidIssuedAt(payload, atTime?)`** — throws if `payload.iat` is in the future relative to `atTime`.

**`assertValidDelegation(from, to, atTime?)`** — validates a single delegation step: `to.iss` must equal `from.aud`, `to.sub` must equal `from.sub`, `from` must be non-expired and have a valid issued-at, and `to`'s permission must be a subset of `from`'s.

**`checkDelegationChain(payload, capabilities, options?)`** — recursively validates a full chain. `capabilities` is the ordered list of stringified parent tokens (head = immediate parent, tail = grandparents toward root). The root token is valid when `iss === sub` (self-issued), or when it carries `mbr` and its issuer is an effective management member of `sub` (see below).

**`checkCapability(permission, payload, options?)`** — the top-level entry point. Given a `permission` being requested and a signed `payload` (from the incoming token), it checks that the payload grants the permission directly (self-issued, or a member-issued grant presented on its own) or via its `cap` delegation chain. On both direct arms the caller must already have verified the payload's signature: `checkCapability` does not verify the token it is handed, only the chain behind it.

```typescript
async function checkCapability(
  permission: Permission,
  payload: SignedPayload,     // from @kokuin/token
  options?: DelegationChainOptions,
): Promise<void>
```

---

## Grants issued by management members

A `did:kokuin:` subject keeps a management tier in its own log (see [./controller.md](./controller.md#management-members)): a few devices, each admitted by a root add that pins one Ed25519 key, with a lease end. Any of them can mint **edge grants** for the subject — capabilities with `sub` = the profile DID and `iss` = the member's DID — without the root key. Such a grant is a chain root with the same power as one the profile signs itself. It confers no management power: membership comes only from a root add in the log, never from a capability, so a holder copying `mbr` onto a root of its own is simply not a member.

### Minting

```typescript
import { createCapability } from '@kokuin/capability'

const now = Math.floor(Date.now() / 1000)
const grant = await createCapability(
  memberIdentity,                          // iss: the member's did:key, or its long-form did:peer:4
  { sub: profileDID, aud: agentDID, act: 'read', res: 'docs/*', iat: now, exp: now + 12 * 3600 },
  undefined,
  { member: { add: memberAddDigest, g: head.gen } },   // the incarnation, and the log's generation
)
```

`member` writes the `mbr: { add, g }` claim: `add` is the digest of the add event that admitted the issuer (its incarnation), `g` the generation of the subject's log it was minted under. Both are needed — a reset carrying a snapshot keeps add digests, so only `g` tells a grant minted before it from one minted after. `createCapability` refuses a malformed claim (exactly the keys `add` and `g`; a non-empty `add`, a non-negative integer `g`), and a payload without numeric `exp` and `iat`, or with `exp < iat`. It does **not** ask the log: membership, the lease and the lifetime bound are the verifier's, since the maximum lifetime is the verifier's setting and a mint-side default would refuse grants a verifier configured wider accepts.

**The issuer must be a `did:key`, or the long form of a `did:peer:4`.** The verifier checks that `iss` carries exactly the pinned key, which only an identifier that embeds its key can show. A short-form `did:peer:4` is always refused, even for a real member.

### Verification

`checkCapability` and `checkDelegationChain` accept a root that carries `mbr` and whose `iss` is not `sub` through `assertMemberRoot(payload, options, time)`, which checks, in order:

1. `mbr` is well formed — else `MEMBER_GRANT_NOT_MEMBER` (`: malformed mbr claim`);
2. the subject's method can answer `resolveMember` — else `MEMBER_GRANT_NO_RESOLVER`;
3. `resolveMember(sub, { did: iss, add, gen: g })` answers: the incarnation is an effective member (present, not removed, its DID and pinned key not denied) in the head's generation, under the issuer's DID — any refusal, including an unresolvable or saturated log, is `MEMBER_GRANT_NOT_MEMBER`, with the original error as `cause`;
4. `iss` carries exactly the pinned key — one Ed25519 key, byte-equal — else `MEMBER_GRANT_KEY_MISMATCH`;
5. `exp` is present and `exp <= lease` — else `MEMBER_GRANT_PAST_LEASE`;
6. `iat` is present — else `MEMBER_GRANT_NO_IAT`;
7. `exp - iat <= maxMemberGrantLifetime` (default `DEFAULT_MEMBER_GRANT_LIFETIME`, 43200 s) — else `MEMBER_GRANT_TOO_LONG`;
8. the time claims (`exp`, `nbf`, `iat` not in the future), then the audience against the subject's deny set (`AUDIENCE_REVOKED`).

Each reason is thrown with a `: detail` suffix, so match with `startsWith`.

**Bounded at mint.** The lease and the lifetime are judged against the grant's own claims, so a grant that would outlive either is refused outright, never trimmed. The two bounds answer different questions. The **lifetime** (12 hours by default, configurable per verification) bounds how late an offline verifier learns that an *edge holder* was revoked: a revoke reaches it only with a newer log, expiry reaches it unconditionally. The **lease** (months) bounds a *stolen member*: a removed member keeps its pre-removal log and can mint fresh grants that a verifier which never sees the removal accepts, until its lease end. A removal kills a member's grants for any verifier whose state contains it.

**Signature before membership.** On the chain path the walk verifies each link's signature against `iss` before asking about membership. That order matters: the log compares DIDs canonically, which for a `did:peer:4` reads only the short prefix, so a forged long form sharing a member's prefix gets the real member's pin back. Its document does not hash to the prefix, so `verifyToken` refuses it first, and the exact-key check (step 4) refuses it on any path that skipped the signature. On the **direct** `checkCapability` path a member grant is the payload itself, and — exactly as on the `iss === sub` arm — **the caller must have verified its signature**; `checkCapability` only checks the request is within the grant and runs the steps above.

**One frozen view per verification.** Membership, pin, lease and every audience denial on the chain must come from one state of the subject's log, or a revoke landing between two of the questions gives a verdict no single state supports. With `@kokuin/controller`, put a fresh `resolver.frozen()` view in `methods` for each verification and drop it after:

```typescript
await checkCapability(requested, payload, { methods: [resolver.frozen()] })
```

The view folds each DID at most once, so a whole chain — membership, lease, each link's audience — costs one `loadLog`.

**Offline.** A grant travels with the subject's log — the root chain up to the current settlement and the current epoch's events, at least those establishing the issuer's membership and lease (`pruneLog` gives the least of a log that folds to the same head; no narrower proof format is defined). A verifier merges it with the log it holds (`mergeLogs`), folds it, and checks the grant against that view with no network; with a `history` store it never forgets an event it was shown. What it cannot see — a removal or revoke it was never shown — is the gap the lifetime and lease bounds close.

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
  get(jti: string, issuer: string): Promise<RevocationRecord | undefined>
}
```

It answers with the *record*, not with a boolean: the checker re-verifies the signature at the point of use, because a backend is an extension point and may return something it never verified.

`get` is asked for the token's own issuer, already normalized (`normalizeDID`), and a backend **must** scope its records by issuer as well as `jti`. Anyone can sign a valid record for any `jti` — a capability's holder knows it — so a store keyed by `jti` alone lets a foreign record displace the issuer's: overwrite it (last write wins) or pre-empt it (first write wins). The checker ignores a record from any other issuer, so either way the revoked token passes.

**`createMemoryRevocationBackend(options?)`** — returns an in-memory `RevocationBackend` backed by a `Map` keyed by `(normalized issuer, jti)`. `add` verifies the record's signature and throws `Invalid revocation record` on one that does not check out. Suitable for single-process use; does not survive restarts.

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
