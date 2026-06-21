---
name: kokuin:capability
description: Capability & delegation patterns — scoped permissions, delegation chains, and revocation
---

# Kokuin Capabilities & Delegation

## Packages in This Domain

**Capability System**: `@kokuin/capability` (built on `@kokuin/token`)

## Key Patterns

### Pattern 1: Create a Root Capability

A root capability is self-issued — the signer DID equals the subject DID. No parent is required.

```typescript
import { createCapability } from '@kokuin/capability'
import { randomIdentity, stringifyToken } from '@kokuin/token'

// Root identity that controls a resource
const rootIdentity = randomIdentity()

// Delegate identity that will receive the capability
const delegateIdentity = randomIdentity()

// Issue a root capability — signer === sub, so no parentCapability needed
const rootCap = await createCapability(rootIdentity, {
  sub: rootIdentity.id,      // self-issued: signer is the subject
  aud: delegateIdentity.id,  // who may use this capability
  act: 'read',               // allowed action (or Array<string>)
  res: 'docs/*',             // allowed resource pattern
  exp: Math.floor(Date.now() / 1000) + 3600, // expires in 1 hour
})

// Stringify before passing to another party or as parentCapability
const rootCapStr = stringifyToken(rootCap)
```

**Key points**:
- `act` and `res` follow `/`-separated path patterns; a trailing `*` is the only wildcard form (`docs/*` is valid; `docs/*/edit` is not)
- `sub` is the resource owner (root DID); `aud` is who may present or re-delegate this capability
- `exp` is recommended — capabilities without expiry must be revoked explicitly

### Pattern 2: Delegate a Capability

A delegated capability narrows (or equals) the `act`/`res` of the parent. The signer must be the `aud` of the parent; `parentCapability` is required.

```typescript
import { createCapability } from '@kokuin/capability'
import type { CreateCapabilityOptions } from '@kokuin/capability'
import { stringifyToken } from '@kokuin/token'

// `delegateIdentity` is the aud of rootCap, so it can re-delegate
const consumerIdentity = randomIdentity()

const delegatedCap = await createCapability(
  delegateIdentity,
  {
    sub: rootIdentity.id,        // same subject as root (resource owner)
    aud: consumerIdentity.id,    // narrowed audience
    act: 'read',                 // must be a subset of rootCap's act
    res: 'docs/report',          // narrowed from 'docs/*'
    exp: Math.floor(Date.now() / 1000) + 1800,
  },
  undefined, // no custom JWT header needed
  { parentCapability: rootCapStr } satisfies CreateCapabilityOptions,
)

const delegatedCapStr = stringifyToken(delegatedCap)
```

**Key points**:
- `parentCapability` must be a **stringified** `CapabilityToken` (use `stringifyToken` from `@kokuin/token`)
- The delegated `act`/`res` must not exceed the parent's — `createCapability` throws if it does
- `sub` must match the parent's `sub` across the entire chain
- The third argument (`header`) is `undefined` when no custom JWT header fields are needed

### Pattern 3: Check a Capability

Use `checkCapability` as the top-level entry point. It verifies that a signed payload grants a requested permission, following the `cap` delegation chain back to a self-issued root.

```typescript
import { checkCapability, checkDelegationChain } from '@kokuin/capability'
import type { Permission, DelegationChainOptions } from '@kokuin/capability'

// The permission the consumer is requesting
const requested: Permission = { act: 'read', res: 'docs/report' }

// `consumerPayload` is the SignedPayload from the consumer's token;
// it must include `cap` pointing to the delegation chain.
await checkCapability(requested, consumerPayload)
// Resolves → permission granted
// Throws   → denied (expired, chain broken, permission exceeded, etc.)

// Lower-level: validate a chain array directly
await checkDelegationChain(consumerPayload, [delegatedCapStr, rootCapStr], {
  maxDepth: 5,
} satisfies DelegationChainOptions)
```

**Key points**:
- `checkCapability` handles both self-issued tokens (no chain) and delegated tokens (reads `payload.cap`)
- `checkDelegationChain` takes the `capabilities` array explicitly — head is the immediate parent, tail leads toward the root
- `DEFAULT_MAX_DELEGATION_DEPTH` is 20; override via `options.maxDepth`
- `assertNonExpired` and `assertValidIssuedAt` are called automatically on every link

### Pattern 4: Revocation

Wire a `RevocationBackend` into `DelegationChainOptions.verifyToken` using `createRevocationChecker`. The hook is called for every token in the chain after signature verification; throwing rejects the chain.

```typescript
import {
  createMemoryRevocationBackend,
  createRevocationChecker,
  createRevocationRecord,
  checkCapability,
} from '@kokuin/capability'
import type {
  RevocationBackend,
  RevocationRecord,
  VerifyTokenHook,
} from '@kokuin/capability'

// In-memory backend — suitable for single-process use; does not survive restarts
const backend: RevocationBackend = createMemoryRevocationBackend()

// Wrap it as a VerifyTokenHook
const revocationHook: VerifyTokenHook = createRevocationChecker(backend)

// To revoke a token by its jti:
// `jtiToRevoke` is the `jti` claim of the token being revoked (from its payload)
const record: RevocationRecord = await createRevocationRecord(revokerIdentity, jtiToRevoke)
await backend.add(record)

// Check with revocation enabled — any revoked token in the chain causes rejection
const requested: Permission = { act: 'read', res: 'docs/report' }
await checkCapability(requested, consumerPayload, {
  verifyToken: revocationHook,
})
```

**Key points**:
- `createRevocationRecord(signer, jti)` is `async` and returns `Promise<RevocationRecord>` — always `await` it before calling `backend.add`
- `VerifyTokenHook` signature: `(token: CapabilityToken, raw: string) => void | Promise<void>` — throw to reject
- `createMemoryRevocationBackend` is backed by an in-memory `Set`; for persistence, implement `RevocationBackend` (`add` + `isRevoked`)
- Revocation plugs in via `DelegationChainOptions.verifyToken` and applies to every link in the chain

## When to Use What

**Use `checkCapability`** when:
- Verifying an incoming request that presents a capability token
- You have a `SignedPayload` and want to confirm it grants a specific `Permission`

**Use `checkDelegationChain`** when:
- You already have the chain array decomposed
- Implementing custom chain validation logic

**Use `createCapability` with `parentCapability`** when:
- A service or agent needs to re-delegate a narrowed subset of its own permissions
- Building multi-hop delegation flows (agent → sub-agent → resource)

**Use `createRevocationChecker`** when:
- Long-lived capabilities need early invalidation without key rotation
- Building audit logs of revoked tokens

→ Reference: docs/capabilities/capability.md
