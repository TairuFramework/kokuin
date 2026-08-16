# did:kokuin FullIdentity from a keystore — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a high-level `@kokuin/controller` utility that turns a keystore `KeyEntry` holding a seed into a ready `did:kokuin:` `FullIdentity` (signing + decryption), generating on first use and restoring afterwards.

**Architecture:** Three layers, bottom-up. `@kokuin/token` gains a DID-bound X25519 key-agreement constructor. `@kokuin/controller` extends its seed-based identity path to derive the agreement key and return a `FullIdentity`. A new `provideControllerIdentity` utility reads the seed from a `KeyEntry`, loads-or-bootstraps the log from a `LogStore`, and folds it into the identity.

**Tech Stack:** TypeScript (ES2025, strict), pnpm workspaces, biome, swc, vitest. Crypto via `@noble/curves` (ed25519 / x25519). JWE round-trip via `@kokuin/jwe` (already a controller devDependency).

**Spec:** `docs/superpowers/specs/2026-08-16-controller-keystore-identity-design.md` — read it alongside this plan.

## Global Constraints

- Conventions are the `kigu:conventions` skill: `type` not `interface`; `Array<T>` not `T[]`; ES `#private`; single params-object arguments with a `NameParams` type; capital `ID`/`DID`; `import type` for type-only imports; terse comments (why, not what); British spelling in prose and comments.
- pnpm only. Run a package's unit tests with `rtk proxy pnpm --filter <pkg> run test:unit`; type-check with `rtk proxy pnpm --filter <pkg> run test:types`. Format with `pnpm exec biome check --write <paths>` before every commit.
- The controller's root seed is a raw `Uint8Array`; a `KeyEntry<Uint8Array>`'s `provideAsync()` bytes ARE that seed. `keyID` names the seed, `profile` selects identities under it.
- The utility lives in `@kokuin/controller`. No new package. v1 keystores are `node`, `electron`, `expo`, `deterministic` (raw-byte `KeyEntry<Uint8Array>`); `browser` and `ledger` are out of scope.
- The seed-based entry points return `FullIdentity`; the `WithKey` entry points stay `SigningIdentity` (no seed → no agreement key).
- The controller's agreement keys are independent X25519 keypairs at `agreementPath`, NOT the Montgomery form of the authority Ed25519 key — so the token addition takes a raw X25519 scalar, not an Ed25519 key.
- Internal deps use `workspace:^`. No cyclic dependencies (`controller → jwe → token` and `controller → token` stay acyclic).
- Commit messages end with the two trailers this repo requires (`Co-Authored-By:` and `Claude-Session:`).

---

### Task 1: Token — DID-bound X25519 key-agreement identity

**Files:**
- Modify: `packages/token/src/identity.ts` (add export after `createKeyAgreementIdentity`, ~line 157)
- Modify: `packages/token/src/index.ts` (export the new name near `createKeyAgreementIdentity`, line ~40)
- Test: `packages/token/test/identity.test.ts` (add cases; create the file only if absent — a `lib.test.ts` or `identity.test.ts` already exists, check first)

**Interfaces:**
- Consumes: `x25519` from `@noble/curves/ed25519.js` (already imported in `identity.ts`), `DIDString`, `KeyAgreementIdentity` (already defined in `identity.ts:42-44`).
- Produces: `createKeyAgreementIdentityForDID(id: DIDString, x25519PrivateKey: Uint8Array): KeyAgreementIdentity` — an agreement identity whose `id` is the supplied DID and whose `agreeKey` runs ECDH directly on the raw X25519 scalar (no Ed25519→Montgomery conversion).

- [ ] **Step 1: Write the failing test**

In `packages/token/test/identity.test.ts`:

```typescript
import { x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { createKeyAgreementIdentityForDID } from '../src/identity.js'

describe('createKeyAgreementIdentityForDID', () => {
  test('binds the supplied DID and agrees on the raw X25519 scalar', async () => {
    const recipientPriv = x25519.utils.randomSecretKey()
    const did = 'did:kokuin:zExampleControllerDigest'
    const identity = createKeyAgreementIdentityForDID(did, recipientPriv)

    expect(identity.id).toBe(did)

    // A sender agreeing with the recipient's X25519 public key must reach the same secret the
    // identity reaches with the sender's ephemeral public key.
    const senderPriv = x25519.utils.randomSecretKey()
    const recipientPub = x25519.getPublicKey(recipientPriv)
    const senderPub = x25519.getPublicKey(senderPriv)

    const senderSecret = x25519.getSharedSecret(senderPriv, recipientPub)
    const recipientSecret = await identity.agreeKey(senderPub)
    expect(recipientSecret).toEqual(senderSecret)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk proxy pnpm --filter @kokuin/token run test:unit -- identity`
Expected: FAIL — `createKeyAgreementIdentityForDID` is not exported.

- [ ] **Step 3: Write the implementation**

In `packages/token/src/identity.ts`, directly after `createKeyAgreementIdentity` (ends ~line 157):

```typescript
/**
 * A key-agreement identity for a **raw X25519 private key** under a caller-supplied DID.
 *
 * The counterpart of {@link createSigningIdentityForDID} for the agreement half. Two differences from
 * {@link createKeyAgreementIdentity}: the identifier is supplied (a `did:kokuin:` key rotates under a
 * fixed inception digest, so `id` cannot be a function of the key), and the input is the X25519 scalar
 * itself rather than an Ed25519 key to Montgomery-convert — a controller derives an independent
 * agreement keypair, not the Montgomery form of its signing key.
 */
export function createKeyAgreementIdentityForDID(
  id: DIDString,
  x25519PrivateKey: Uint8Array,
): KeyAgreementIdentity {
  async function agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
    return x25519.getSharedSecret(x25519PrivateKey, ephemeralPublicKey)
  }
  return { id, agreeKey }
}
```

- [ ] **Step 4: Export it**

In `packages/token/src/index.ts`, add to the identity export block (alphabetical, beside `createKeyAgreementIdentity`):

```typescript
  createKeyAgreementIdentityForDID,
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `rtk proxy pnpm --filter @kokuin/token run test:unit -- identity`
Expected: PASS.

- [ ] **Step 6: Format, type-check, commit**

```bash
pnpm exec biome check --write packages/token/src/identity.ts packages/token/src/index.ts packages/token/test/identity.test.ts
rtk proxy pnpm --filter @kokuin/token run test:types
git add packages/token/src/identity.ts packages/token/src/index.ts packages/token/test/identity.test.ts
git commit -m "feat(token): DID-bound X25519 key-agreement identity"
```

---

### Task 2: Controller — FullIdentity from folded state

**Files:**
- Modify: `packages/controller/src/identity.ts` (imports; `identityForState` ~line 99-127; return types of `createControllerIdentity` and `createControllerIdentityAsync`; their `...Params` return-type annotations)
- Test: `packages/controller/test/identity.test.ts` (add FullIdentity cases)

**Interfaces:**
- Consumes: `createKeyAgreementIdentityForDID` from `@kokuin/token` (Task 1); `agreementPath`, `deriveKeyPair` from `./derivation.js`; `encodeKey` from `./keys.js` (already imported); `KeyState.agreement: Array<string>` from `./fold.js`.
- Produces: `identityForState(...) : FullIdentity`; `createControllerIdentity(...) : FullIdentity`; `createControllerIdentityAsync(...) : Promise<FullIdentity>`. The `WithKey` variants are unchanged (`SigningIdentity`).

- [ ] **Step 1: Write the failing test**

In `packages/controller/test/identity.test.ts`, add:

```typescript
import { isFullIdentity } from '@kokuin/token'
// (existing imports include createInception/didFromInception/createControllerIdentity — add any
//  missing from '../src/...'.)

describe('controller identity is a FullIdentity', () => {
  test('the seed path yields signing and key agreement bound to the controller DID', async () => {
    const seed = new Uint8Array(32).fill(11)
    const profile = 0
    const inception = createInception(seed, profile)
    const did = didFromInception(inception.event)

    const identity = createControllerIdentity({ seed, profile, log: [inception] })

    expect(identity.id).toBe(did)
    expect(isFullIdentity(identity)).toBe(true)
    // Signing still stamps the authority kid. `event.k[0]` is already the multibase-encoded key.
    const token = await identity.signToken({ sub: 'x' })
    expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- identity`
Expected: FAIL — `isFullIdentity(identity)` is `false` (identity has no `agreeKey`).

- [ ] **Step 3: Extend `identityForState`**

In `packages/controller/src/identity.ts`:

Update imports:

```typescript
import {
  createKeyAgreementIdentityForDID,
  createSigningIdentityForDID,
  type DIDString,
  type FullIdentity,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
```
```typescript
import { agreementPath, authorityPath, deriveKeyPair } from './derivation.js'
```

Replace the body of `identityForState` (currently derives only the authority key and returns `identityForKey(...)`):

```typescript
function identityForState({
  seed,
  profile,
  did,
  state,
}: {
  seed: Uint8Array
  profile: number
  did: DIDString
  state: KeyState
}): FullIdentity {
  const authority = deriveKeyPair(
    seed,
    authorityPath(profile, state.keyGen, state.keySeq),
    'EdDSA',
  )
  const signing = identityForKey({
    privateKey: authority.privateKey,
    publicKey: authority.publicKey,
    did,
    state,
    mismatch: 'derived key is not one of the current authority keys',
  })
  // The agreement key sits at the same (keyGen, keySeq) as the authority key — both icp and rot
  // derive them at matching indices, and a rev carries the agreement set forward — so one position
  // locates both. Verified against the folded set, failing closed like the authority membership check.
  const agreement = deriveKeyPair(
    seed,
    agreementPath(profile, state.keyGen, state.keySeq),
    'X25519',
  )
  const encoded = encodeKey(agreement.publicKey, 'X25519')
  if (!state.agreement.includes(encoded)) {
    throw new Error(
      `${CONTEXT}: derived agreement key is not one of the current agreement keys of ${did}`,
    )
  }
  return { ...signing, ...createKeyAgreementIdentityForDID(did, agreement.privateKey) }
}
```

Change the return type of `createControllerIdentity` from `SigningIdentity` to `FullIdentity` (its body already `return identityForState(...)`), and of `createControllerIdentityAsync` from `Promise<SigningIdentity>` to `Promise<FullIdentity>`. Leave `createControllerIdentityWithKey` / `createControllerIdentityWithKeyAsync` and `identityForKey` returning `SigningIdentity`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- identity`
Expected: PASS.

- [ ] **Step 5: Add a fail-closed test for a mismatched agreement set**

```typescript
test('rejects a state whose agreement set omits the derived key', () => {
  const seed = new Uint8Array(32).fill(12)
  const inception = createInception(seed, 0)
  // A log whose inception advertises a foreign agreement key: the fold carries `ka` into
  // state.agreement, so the derived key is no longer a member and construction must throw.
  const tampered = {
    ...inception,
    event: { ...inception.event, ka: ['z6LSforeignAgreementKeyDoesNotMatchDerivation'] },
  }
  expect(() => createControllerIdentity({ seed, profile: 0, log: [tampered] })).toThrow(
    /agreement key is not one of the current agreement keys/,
  )
})
```

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- identity`
Expected: PASS. If the fold rejects the tampered inception earlier (bad signature over a changed body) the throw message differs — in that case sign a fresh inception whose `ka` is a valid-but-different X25519 key using the test helpers already in the suite, so the failure is the agreement-membership check specifically, not a fold rejection.

- [ ] **Step 6: Format, type-check, commit**

```bash
pnpm exec biome check --write packages/controller/src/identity.ts packages/controller/test/identity.test.ts
rtk proxy pnpm --filter @kokuin/controller run test:types
git add packages/controller/src/identity.ts packages/controller/test/identity.test.ts
git commit -m "feat(controller): seed-based identities are FullIdentity (signing + decryption)"
```

---

### Task 3: Controller — `provideControllerIdentity` utility

**Files:**
- Create: `packages/controller/src/keystore-identity.ts`
- Modify: `packages/controller/src/index.ts` (export the new function and its params type)
- Test: `packages/controller/test/keystore-identity.test.ts`

**Interfaces:**
- Consumes: `KeyEntry` from `@kokuin/token`; `FoldOptions` from `./fold.js`; `LogStore` from `./history.js`; `createInception`, `didFromInception` from `./events.js`; `createControllerIdentityAsync` from `./identity.js`; `FullIdentity` from `@kokuin/token`.
- Produces:
  - `type ProvideControllerIdentityParams = { entry: KeyEntry<Uint8Array>; profile: number; logStore: LogStore; options?: FoldOptions }`
  - `provideControllerIdentity(params: ProvideControllerIdentityParams): Promise<FullIdentity>`

- [ ] **Step 1: Write the failing test**

Create `packages/controller/test/keystore-identity.test.ts`:

```typescript
import type { KeyEntry } from '@kokuin/token'
import { isFullIdentity } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { createMemoryLogStore } from '../src/history.js'
import { provideControllerIdentity } from '../src/keystore-identity.js'

// A minimal raw-byte KeyEntry: provideAsync generates once and restores thereafter — the contract
// node/electron/expo/deterministic satisfy. `seed` lets a test pin the bytes.
function memoryEntry(seed?: Uint8Array): KeyEntry<Uint8Array> {
  let stored = seed
  return {
    keyID: 'test',
    async getAsync() {
      return stored ?? null
    },
    async provideAsync() {
      stored ??= new Uint8Array(32).fill(7)
      return stored
    },
  }
}

describe('provideControllerIdentity', () => {
  test('generates a fresh identity when the log store is empty', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const identity = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })

    const expectedDID = didFromInception(createInception(seed, 0).event)
    expect(identity.id).toBe(expectedDID)
    expect(isFullIdentity(identity)).toBe(true)
    // The generate path persisted the inception.
    const stored = await logStore.get(expectedDID)
    expect(stored).toHaveLength(1)
  })

  test('restores the same identity from an existing log', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const first = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
    const second = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
    expect(second.id).toBe(first.id)
  })

  test('a different profile under the same seed is a different DID', async () => {
    const seed = new Uint8Array(32).fill(7)
    const logStore = createMemoryLogStore()
    const a = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
    const b = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 1, logStore })
    expect(a.id).not.toBe(b.id)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- keystore-identity`
Expected: FAIL — `../src/keystore-identity.js` does not exist.

- [ ] **Step 3: Write the utility**

Create `packages/controller/src/keystore-identity.ts`:

```typescript
import type { FullIdentity, KeyEntry } from '@kokuin/token'

import { createInception, didFromInception } from './events.js'
import type { FoldOptions } from './fold.js'
import type { LogStore } from './history.js'
import { createControllerIdentityAsync } from './identity.js'

export type ProvideControllerIdentityParams = {
  /** The seed source: `provideAsync()`'s bytes are the controller root seed. Generates on first use. */
  entry: KeyEntry<Uint8Array>
  /** Which profile under the seed to resolve. */
  profile: number
  /** Where the last accepted log for the DID lives — loaded to restore, written to on first generate. */
  logStore: LogStore
  /** Forwarded to the fold for a log whose revoke carries a capability only the async fold can verify. */
  options?: FoldOptions
}

/**
 * Resolve a `did:kokuin:` {@link FullIdentity} from a keystore entry and a log store.
 *
 * Generate and restore in one call: the entry yields the seed (a fresh one on first use, the stored
 * one after), and the log store yields the event log (bootstrapping the inception when the DID has no
 * log yet). The DID is a pure function of `(seed, profile)`, so the same entry and profile always
 * resolve the same identity. A `KeyStore` caller passes `keyStore.entry(keyID)` as `entry`.
 */
export async function provideControllerIdentity({
  entry,
  profile,
  logStore,
  options,
}: ProvideControllerIdentityParams): Promise<FullIdentity> {
  const seed = await entry.provideAsync()
  const inception = createInception(seed, profile)
  const did = didFromInception(inception.event)
  let log = await logStore.get(did)
  if (log == null) {
    log = [inception]
    await logStore.set(did, log)
  }
  return createControllerIdentityAsync({ seed, profile, log, options })
}
```

- [ ] **Step 4: Export it**

In `packages/controller/src/index.ts`, add an export block (place beside the `./identity.js` block):

```typescript
export {
  provideControllerIdentity,
  type ProvideControllerIdentityParams,
} from './keystore-identity.js'
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- keystore-identity`
Expected: PASS.

- [ ] **Step 6: Add rotate/revoke coverage**

Append to the test file, using the suite's existing rotate/revoke builders (see `packages/controller/test/identity.test.ts` and `generation-lifecycle.test.ts` for the exact `createRotate`/`createRevoke` calls and how a log is grown):

```typescript
test('resolves the current key after a rotate', async () => {
  const seed = new Uint8Array(32).fill(7)
  const logStore = createMemoryLogStore()
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  const rot = createRotate({ seed, profile: 0, did, prior: inception.event })
  await logStore.set(did, [inception, rot])

  const identity = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
  expect(identity.id).toBe(did)
  const token = await identity.signToken({ sub: 'x' })
  // After a rotate the authority key is the rotate's revealed key, so the kid names it.
  expect(token.header.kid).toBe(`#${rot.event.k[0]}`)
})
```

Add `createRotate` to the imports from `../src/events.js`. Run the suite again; expected PASS.

Then add a revoke case — a `rev` advances the sequence without establishing a key and carries the
agreement set forward, so the identity must still resolve to the pre-revoke key and still decrypt.
Use the suite's `createRevoke` builder (see `generation-lifecycle.test.ts` for the exact
`keyPosition`/`target` arguments):

```typescript
test('resolves the pre-revoke key after a revoke', async () => {
  const seed = new Uint8Array(32).fill(7)
  const logStore = createMemoryLogStore()
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  const revoke = createRevoke({
    seed,
    profile: 0,
    did,
    prior: inception.event,
    target: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    keyPosition: { gen: 0, seq: 0 },
  })
  await logStore.set(did, [inception, revoke])

  const identity = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })
  expect(identity.id).toBe(did)
  const token = await identity.signToken({ sub: 'x' })
  // The revoke established no key, so the authority key is still the inception's.
  expect(token.header.kid).toBe(`#${inception.event.k[0]}`)
})
```

Add `createRevoke` to the imports from `../src/events.js`. Run the suite again; expected PASS.

- [ ] **Step 7: Format, type-check, commit**

```bash
pnpm exec biome check --write packages/controller/src/keystore-identity.ts packages/controller/src/index.ts packages/controller/test/keystore-identity.test.ts
rtk proxy pnpm --filter @kokuin/controller run test:types
git add packages/controller/src/keystore-identity.ts packages/controller/src/index.ts packages/controller/test/keystore-identity.test.ts
git commit -m "feat(controller): provideControllerIdentity utility for a keystore entry"
```

---

### Task 4: Controller — decryption round-trip and a real keystore

**Files:**
- Test: `packages/controller/test/keystore-identity.test.ts` (add a decryption round-trip block and a `@kokuin/deterministic` integration block)
- Modify: `packages/controller/package.json` (add `@kokuin/deterministic` devDependency)

**Interfaces:**
- Consumes: `createTokenEncrypter`, `encryptToken`, `decryptToken` from `@kokuin/jwe` (already a controller devDependency); `HDKeyStore` from `@kokuin/deterministic`; `deriveKeyPair`, `agreementPath` from `../src/derivation.js`; `provideControllerIdentity` (Task 3).
- Produces: no new production code — this task proves the FullIdentity decrypts and that a real raw-byte keystore drives the utility.

- [ ] **Step 1: Add the deterministic devDependency**

In `packages/controller/package.json`, add to `devDependencies` (keep alphabetical among `@kokuin/*`):

```json
    "@kokuin/deterministic": "workspace:^",
```

Then:

```bash
rtk proxy pnpm install
```

- [ ] **Step 2: Write the decryption round-trip test**

Append to `packages/controller/test/keystore-identity.test.ts`:

```typescript
import { createTokenEncrypter, decryptToken, encryptToken } from '@kokuin/jwe'

import { agreementPath, deriveKeyPair } from '../src/derivation.js'

test('the resolved FullIdentity decrypts a JWE encrypted to its agreement key', async () => {
  const seed = new Uint8Array(32).fill(7)
  const logStore = createMemoryLogStore()
  const identity = await provideControllerIdentity({ entry: memoryEntry(seed), profile: 0, logStore })

  // The agreement key at the inception position (gen 0, seq 0) is the current one for a fresh log.
  const agreementPublicKey = deriveKeyPair(seed, agreementPath(0, 0, 0), 'X25519').publicKey
  const encrypter = createTokenEncrypter(agreementPublicKey, { algorithm: 'X25519' })
  const plaintext = new TextEncoder().encode('sealed to the controller')
  const jwe = await encryptToken(encrypter, plaintext)

  const decrypted = await decryptToken(identity, jwe)
  expect(decrypted).toEqual(plaintext)
})
```

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- keystore-identity`
Expected: PASS (proves `agreeKey` on the FullIdentity actually decrypts).

- [ ] **Step 3: Write the real-keystore integration test**

Append:

```typescript
import { HDKeyStore } from '@kokuin/deterministic'

test('drives end to end from a real @kokuin/deterministic KeyStore', async () => {
  // A BIP39 mnemonic → HD seed; the entry hands back raw bytes the utility uses as the controller
  // seed. Deterministic, so the DID is stable across runs.
  const keyStore = HDKeyStore.fromMnemonic(
    'test test test test test test test test test test test junk',
  )
  const logStore = createMemoryLogStore()

  const identity = await provideControllerIdentity({
    entry: keyStore.entry('0'),
    profile: 0,
    logStore,
  })

  expect(identity.id.startsWith('did:kokuin:')).toBe(true)
  expect(isFullIdentity(identity)).toBe(true)

  // Restore returns the same identity.
  const again = await provideControllerIdentity({ entry: keyStore.entry('0'), profile: 0, logStore })
  expect(again.id).toBe(identity.id)
})
```

Run: `rtk proxy pnpm --filter @kokuin/controller run test:unit -- keystore-identity`
Expected: PASS. If `HDKeyStore.fromMnemonic` requires a valid BIP39 checksum that the placeholder mnemonic fails, generate one with `@scure/bip39`'s `generateMnemonic(wordlist)` at the top of the test instead — the point is a real store, not a fixed phrase.

- [ ] **Step 4: Verify no dependency cycle**

```bash
rm -rf packages/*/lib && rtk proxy pnpm run build
```
Expected: the build completes (no cyclic-dependency error). `controller → deterministic → token` and `controller → token` stay acyclic.

- [ ] **Step 5: Format, type-check, commit**

```bash
pnpm exec biome check --write packages/controller/test/keystore-identity.test.ts
rtk proxy pnpm --filter @kokuin/controller run test:types
git add packages/controller/package.json packages/controller/test/keystore-identity.test.ts pnpm-lock.yaml
git commit -m "test(controller): decryption round-trip and a real keystore driving provideControllerIdentity"
```

---

## Notes for the executor

- **Release intents.** This work adds public exports to `@kokuin/token` (`createKeyAgreementIdentityForDID`) and `@kokuin/controller` (`provideControllerIdentity`, `ProvideControllerIdentityParams`) and widens the controller identity return type. After the tasks pass, record intents: `rtk proxy pnpm change --bump minor --summary "..." @kokuin/token` and `... @kokuin/controller`. Controller is still unpublished (0.1.0), so its intent will not move it off 0.1.0 — that is expected.
- **Out of scope (do not implement here):** browser raw-secret entry support; ledger WithKey decryption; the downstream range-bump and `exp`/depth audit in enkaku/kumiai/kubun/sakui. These are separate follow-ups named in the spec.
