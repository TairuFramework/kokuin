# Profile DIDs with rotating keys — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Stage:** executing
**Mode:** tasks
**Spec:** `docs/superpowers/specs/2026-08-08-profile-did-key-events-design.md`

**Goal:** Ship `did:kokuin:` — a self-certifying profile DID whose key set rotates through a folded event log, verifiable offline with no group involved.

**Architecture:** A new `@kokuin/controller` package owns derivation, the event schema, self-addressing digests, the fold, and key-state-at-position. `@kokuin/token` gains an injected `DIDMethodResolver` so it can resolve `iss` through key state without importing the fold — `@kokuin/controller` depends on `@kokuin/token` for signing, so the reverse import would be a cycle. A private `@kokuin/controller-conformance` package holds the contract suite.

**Tech Stack:** TypeScript, vitest, `@noble/hashes` (SHA-256, HKDF), `@noble/curves` (ed25519), `@scure/base` (base58), `micro-key-producer` (SLIP-0010), biome, swc.

## Global Constraints

- pnpm only. Cross-repo deps (`@sozai/*`) are published `^` ranges, never `workspace:`.
- All dev tooling from `@kigu/dev`: extend `@kigu/dev/tsconfig.json`, `["@kigu/dev/biome.json"]`, `@kigu/dev/swc.json`.
- Every private package must be listed in `versioning.ignore` in `pnpm-workspace.yaml` **by exact name** — globs are not supported, and an omitted one makes `pnpm change status` / `pnpm version -r` crash.
- Tests live in `<package>/test/*.test.ts` and import source as `../src/<file>.js`.
- Dependencies use `catalog:` for third-party, `workspace:^` for sibling `@kokuin/*`.
- Derivation is SLIP-0010 ed25519, **hardened segments only**. Base path `44'/876'`.
- HKDF `info` string is exactly `did:kokuin/v1|<alg>`. This is baked into every derived key and can never change once a profile exists.
- The DID string carries **no version segment**: `did:kokuin:<multibase multihash(inception)>`.
- Commit style: `<type>(<scope>): <description>`, e.g. `feat(controller): fold superseding recovery`.
- Run `pnpm exec biome check --write ./packages` before each commit (the `rtk` shim redirects `pnpm run lint`).

## Wire-format decisions made by this plan

The spec fixes semantics; these are the concrete encodings. Flag any you want changed before execution.

**Event JSON** — a common envelope plus a type-specific body:

```
{ v, t, i, g, s, p, crit, ...body }
```

| Field | Meaning |
| --- | --- |
| `v` | inception format version, always `1` |
| `t` | `"icp"` \| `"rot"` \| `"rev"` |
| `i` | profile DID; **omitted** from the inception pre-image, since the DID is its hash |
| `g` | generation |
| `s` | sequence |
| `p` | digest of the previous event; absent on inception |
| `crit` | criticality marker — sits in the envelope so a verifier can read it without understanding `t` |

Bodies: `icp` and `rot` carry `k` (multibase public keys), `n` (next-key digests), `kt`, `nt`, and optionally `r` (recovery-key digest), `a` (seal), `d` (deny-set snapshot). `rev` carries `x` (the DID to deny) and optionally `cap` (a serialized capability authorising a non-authority signer).

**Canonical bytes** are JCS-style: keys sorted lexicographically, no insignificant whitespace, UTF-8.

**Signatures** are detached: `SignedEvent = { event, sigs }` where `sigs[i]` is base64url ed25519 over the canonical bytes, positionally matching `event.k`. A `rot` is signed by the **newly revealed** keys, per KERI, and verified against the prior event's `n` digests.

---

## Amendment A — reset anchors to the inception (decided during Task 8)

**This section is authoritative and supersedes the Task 7, 8, 9 and 10 text below wherever they disagree.**

Two defects surfaced while reviewing Task 8. Both are in the plan's own code, not in an implementation.

**1. A reset could not be authored from a mnemonic alone.** `createReset` took the prior event and derived both `p = digestOf(prior)` and `g = prior.g + 1` from it, so a root holding only its seed — the exact situation recovery exists for — could not author one. The docstring claimed the opposite. A compromised device could never *author* a reset (the recovery key is a hardened sibling of the delegable subtree, unreachable from any sub-seed), so the authority guarantee held; only availability failed.

A reset now anchors to the inception, which the root recomputes from the seed:

```ts
createReset(seed: Uint8Array, profile: number, gen: number): SignedEvent<RotateEvent>
verifyReset(signed: SignedEvent<RotateEvent>, inception: InceptionEvent): boolean
```

- `p = digestOf(inception)`; `i` is `didFromInception(inception)`, also derived internally. No prior event is passed.
- `s = 0`, `g = gen`, and `gen >= 1`.
- **No options.** No seal, and `d` is always `[]`. A reset is a pure function of `(seed, profile, gen)`, so two blind resets at the same generation produce identical bytes and resolve as idempotent re-derivation rather than duplicity. Admitting a seal or a deny snapshot would break that and is the reason the options parameter is gone.
- `verifyReset` takes the inception itself rather than `{ digest, r }` — both values it needs come from there, and passing the event makes the pairing impossible to get wrong.
- The root does not need to know the current generation. It only needs to eventually exceed it, and no attacker can author a competing reset at *any* generation. A blind root starts at `gen = 1` and retries higher if it learns of one; the cost is a round trip, never loss of control.

**2. `createRevoke` derived the wrong signing key for a second consecutive revoke.** It signed at `authorityPath(profile, prior.g, prior.s)`, which locates the active key only when `prior` is an `icp` or `rot` — those establish a key at their own `s`. A revoke establishes nothing, so a revoke chained onto a revoke signed with the unrevealed pre-committed next key and failed verification. An authority could revoke one device, then no more without an unrelated rotate. The key position is now passed explicitly:

```ts
createRevoke(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  target: string,
  keyPosition: { gen: number; seq: number },
  options?: { cap?: string },
): SignedEvent<RevokeEvent>
```

`prior` still answers "what is the next sequence number and what do I chain to"; `keyPosition` answers "where does the currently-active authority key live". They coincide only for `icp`/`rot`, which is why one parameter could not serve both.

`KeyState` (Task 9) gains `keyGen` and `keySeq` — the position at which the state's current `keys` were established — so the fold is the natural source for `keyPosition`. They advance only on an `icp` or `rot`; a `rev` carries them forward unchanged.

---

## Task 1: Scaffold `@kokuin/controller`

**Files:**
- Create: `packages/controller/package.json`
- Create: `packages/controller/tsconfig.json`
- Create: `packages/controller/tsconfig.test.json`
- Create: `packages/controller/src/index.ts`
- Test: `packages/controller/test/package.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: a buildable, testable workspace package named `@kokuin/controller`.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/package.test.ts
import { describe, expect, test } from 'vitest'

import { VERSION_TAG } from '../src/index.js'

describe('@kokuin/controller', () => {
  test('exposes the protocol version tag used for key derivation', () => {
    expect(VERSION_TAG).toBe('did:kokuin/v1')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit`
Expected: FAIL — the package does not exist yet, so the filter matches nothing.

- [ ] **Step 3: Create the package**

`packages/controller/package.json`:

```json
{
  "name": "@kokuin/controller",
  "version": "0.1.0",
  "description": "did:kokuin controller key event log",
  "keywords": ["did", "identity", "key-management", "rotation"],
  "repository": {
    "type": "git",
    "url": "https://github.com/TairuFramework/kokuin",
    "directory": "packages/controller"
  },
  "license": "MIT",
  "sideEffects": false,
  "type": "module",
  "exports": { ".": "./lib/index.js" },
  "main": "lib/index.js",
  "types": "lib/index.d.ts",
  "files": ["lib/*"],
  "scripts": {
    "build": "pnpm run build:clean && pnpm run build:js && pnpm run build:types",
    "build:clean": "del lib",
    "build:js": "swc src -d ./lib --config-file ../../node_modules/@kigu/dev/swc.json --strip-leading-paths",
    "build:types": "tsc --emitDeclarationOnly --skipLibCheck",
    "prepublishOnly": "pnpm run build",
    "test": "pnpm run test:types && pnpm run test:unit",
    "test:types": "tsc --noEmit --skipLibCheck -p tsconfig.test.json",
    "test:unit": "vitest run"
  },
  "dependencies": {
    "@kokuin/token": "workspace:^",
    "@noble/curves": "catalog:",
    "@noble/hashes": "catalog:",
    "@scure/base": "catalog:",
    "micro-key-producer": "catalog:"
  },
  "publishConfig": { "access": "public" }
}
```

`packages/controller/tsconfig.json`:

```json
{
  "extends": "@kigu/dev/tsconfig.json",
  "compilerOptions": {
    "types": ["node"],
    "rootDir": "./src",
    "outDir": "./lib"
  },
  "include": ["./src/**/*"]
}
```

`packages/controller/tsconfig.test.json`:

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "lib": ["es2025", "dom"],
    "types": ["node"],
    "rootDir": ".",
    "noEmit": true
  },
  "include": ["./src/**/*", "./test/**/*"]
}
```

No per-package `biome.json`: this repo has a single root `biome.json` extending `@kigu/dev/biome.json`, and no package under `packages/` carries its own.

`packages/controller/src/index.ts`:

```ts
/**
 * did:kokuin controller key event log.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/controller
 * ```
 *
 * @module controller
 */

/**
 * Protocol version tag. Forms the HKDF `info` string for every derived key, so the DID is a
 * function of it — it can never change once a profile exists. Deliberately independent of the
 * package name.
 */
export const VERSION_TAG = 'did:kokuin/v1'
```

- [ ] **Step 4: Install and run the test**

Run: `pnpm install && pnpm --filter @kokuin/controller test`
Expected: PASS, including `test:types`.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller pnpm-lock.yaml
git commit -m "feat(controller): scaffold the package"
```

---

## Task 2: Canonical serialisation and self-addressing digest

**Files:**
- Create: `packages/controller/src/canonical.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/canonical.test.ts`

**Interfaces:**
- Consumes: `VERSION_TAG` from Task 1.
- Produces: `canonicalBytes(value: unknown): Uint8Array`, `digestOf(value: unknown): string` (multibase multihash string), `verifyDigest(digest: string, value: unknown): boolean`.

Reuses `multihashSHA256` and `encodeMultibase` from `@kokuin/token` rather than reimplementing them.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/canonical.test.ts
import { describe, expect, test } from 'vitest'

import { canonicalBytes, digestOf, verifyDigest } from '../src/canonical.js'

const decoder = new TextDecoder()

describe('canonicalBytes()', () => {
  test('sorts object keys and emits no whitespace', () => {
    expect(decoder.decode(canonicalBytes({ b: 1, a: 2 }))).toBe('{"a":2,"b":1}')
  })

  test('sorts nested object keys', () => {
    expect(decoder.decode(canonicalBytes({ z: { y: 1, x: 2 } }))).toBe('{"z":{"x":2,"y":1}}')
  })

  test('preserves array order', () => {
    expect(decoder.decode(canonicalBytes({ a: ['c', 'b'] }))).toBe('{"a":["c","b"]}')
  })

  test('drops undefined properties so optional fields are absent, not null', () => {
    expect(decoder.decode(canonicalBytes({ a: 1, b: undefined }))).toBe('{"a":1}')
  })

  test('key order does not change the bytes', () => {
    expect(canonicalBytes({ a: 1, b: 2 })).toEqual(canonicalBytes({ b: 2, a: 1 }))
  })

  test('rejects a non-finite number — it would not round-trip', () => {
    expect(() => canonicalBytes({ a: Number.NaN })).toThrow(/finite/)
  })
})

describe('digestOf()', () => {
  test('is stable across key order', () => {
    expect(digestOf({ a: 1, b: 2 })).toBe(digestOf({ b: 2, a: 1 }))
  })

  test('differs for different content', () => {
    expect(digestOf({ a: 1 })).not.toBe(digestOf({ a: 2 }))
  })

  test('is a base58btc multibase string', () => {
    expect(digestOf({ a: 1 })).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
  })
})

describe('verifyDigest()', () => {
  test('accepts a matching value', () => {
    expect(verifyDigest(digestOf({ a: 1 }), { a: 1 })).toBe(true)
  })

  test('rejects a mismatched value', () => {
    expect(verifyDigest(digestOf({ a: 1 }), { a: 2 })).toBe(false)
  })

  test('rejects a malformed digest instead of throwing', () => {
    expect(verifyDigest('not-multibase', { a: 1 })).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit`
Expected: FAIL — `Cannot find module '../src/canonical.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/canonical.ts
import { decodeMultibase, encodeMultibase, multihashSHA256 } from '@kokuin/token'

const encoder = new TextEncoder()

function canonicalize(value: unknown): string {
  if (value === null) {
    return 'null'
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonicalization: numbers must be finite')
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`)
    return `{${entries.join(',')}}`
  }
  throw new Error(`Canonicalization: unsupported value type ${typeof value}`)
}

/**
 * JCS-style canonical bytes: keys sorted lexicographically, no insignificant whitespace,
 * `undefined` properties dropped so an absent optional field never encodes as `null`.
 *
 * The DID is the hash of these bytes, so any change to this function changes every identifier
 * the stack has ever issued. It is effectively frozen.
 */
export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value))
}

/** Self-addressing digest: multibase(multihash(canonical bytes)). */
export function digestOf(value: unknown): string {
  return encodeMultibase(multihashSHA256(canonicalBytes(value)))
}

/** Total: a malformed digest returns false rather than throwing. */
export function verifyDigest(digest: string, value: unknown): boolean {
  let expected: Uint8Array
  try {
    expected = decodeMultibase(digest)
  } catch {
    return false
  }
  const actual = multihashSHA256(canonicalBytes(value))
  if (expected.length !== actual.length) {
    return false
  }
  for (let i = 0; i < actual.length; i++) {
    if (expected[i] !== actual[i]) {
      return false
    }
  }
  return true
}
```

Add to `packages/controller/src/index.ts`:

```ts
export { canonicalBytes, digestOf, verifyDigest } from './canonical.js'
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): canonical serialisation and self-addressing digest"
```

---

## Task 3: Derivation paths and HKDF key material

**Files:**
- Create: `packages/controller/src/derivation.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/derivation.test.ts`

**Interfaces:**
- Consumes: `VERSION_TAG` from Task 1.
- Produces:
  - `authorityPath(profile: number, gen: number, seq: number): string`
  - `agreementPath(profile: number, gen: number, seq: number): string`
  - `recoveryPath(profile: number): string`
  - `deriveKeyMaterial(seed: Uint8Array, path: string, alg: string, length?: number): Uint8Array`
  - `deriveKeyPair(seed, path, alg): { privateKey: Uint8Array; publicKey: Uint8Array }`

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/derivation.test.ts
import { describe, expect, test } from 'vitest'

import {
  agreementPath,
  authorityPath,
  deriveKeyMaterial,
  deriveKeyPair,
  recoveryPath,
} from '../src/derivation.js'

const seed = Uint8Array.from(
  ('000102030405060708090a0b0c0d0e0f'.match(/.{2}/g) ?? []).map((b) => Number.parseInt(b, 16)),
)

describe('paths', () => {
  test('authority sits under the delegable branch', () => {
    expect(authorityPath(0, 0, 0)).toBe("m/44'/876'/0'/0'/0'/0'/0'")
    expect(authorityPath(3, 1, 7)).toBe("m/44'/876'/0'/3'/0'/1'/7'")
  })

  test('key agreement sits under the delegable branch at role 1', () => {
    expect(agreementPath(3, 1, 7)).toBe("m/44'/876'/0'/3'/1'/1'/7'")
  })

  test('recovery sits on the root-retained branch, outside the profile subtree', () => {
    expect(recoveryPath(3)).toBe("m/44'/876'/1'/3'")
  })

  test('the recovery path is not a descendant of the delegable profile subtree', () => {
    // Handing out m/44'/876'/0'/<profile>' must not hand out the recovery key. Hardened
    // derivation is one-way, so this is guaranteed by the paths being siblings.
    expect(recoveryPath(3).startsWith("m/44'/876'/0'/3'")).toBe(false)
  })

  test('rejects a negative or non-integer index', () => {
    expect(() => authorityPath(-1, 0, 0)).toThrow(/non-negative integer/)
    expect(() => authorityPath(0, 1.5, 0)).toThrow(/non-negative integer/)
  })
})

describe('deriveKeyMaterial()', () => {
  test('is deterministic for the same seed, path and algorithm', () => {
    const a = deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')
    const b = deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')
    expect(a).toEqual(b)
  })

  test('separates algorithms at the same path', () => {
    const path = authorityPath(0, 0, 0)
    expect(deriveKeyMaterial(seed, path, 'EdDSA')).not.toEqual(
      deriveKeyMaterial(seed, path, 'ML-DSA-65'),
    )
  })

  test('produces the requested length, so 64-byte algorithms need no path tricks', () => {
    expect(deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'ML-KEM-768', 64).length).toBe(64)
  })

  test('different positions produce different material', () => {
    expect(deriveKeyMaterial(seed, authorityPath(0, 0, 0), 'EdDSA')).not.toEqual(
      deriveKeyMaterial(seed, authorityPath(0, 0, 1), 'EdDSA'),
    )
  })
})

describe('deriveKeyPair()', () => {
  test('derives a 32-byte ed25519 keypair', () => {
    const { privateKey, publicKey } = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
    expect(privateKey.length).toBe(32)
    expect(publicKey.length).toBe(32)
  })

  test('rejects an algorithm it cannot build a keypair for', () => {
    expect(() => deriveKeyPair(seed, authorityPath(0, 0, 0), 'ML-DSA-65')).toThrow(/Unsupported/)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit`
Expected: FAIL — `Cannot find module '../src/derivation.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/derivation.ts
import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import HDKey from 'micro-key-producer/slip10.js'

import { VERSION_TAG } from './version.js'

const BASE_PATH = "m/44'/876'"
const DELEGABLE = "0'"
const ROOT_ONLY = "1'"
const ROLE_AUTHORITY = "0'"
const ROLE_AGREEMENT = "1'"

function assertIndex(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`Derivation: ${name} must be a non-negative integer, got ${value}`)
  }
}

function profilePath(profile: number): string {
  assertIndex('profile', profile)
  return `${BASE_PATH}/${DELEGABLE}/${profile}'`
}

/**
 * Authority signing key at a position. Lives under the delegable branch, so handing out the
 * profile sub-seed delegates it.
 */
export function authorityPath(profile: number, gen: number, seq: number): string {
  assertIndex('gen', gen)
  assertIndex('seq', seq)
  return `${profilePath(profile)}/${ROLE_AUTHORITY}/${gen}'/${seq}'`
}

/** Profile-level key agreement key. Durable data encrypts to these, never to device keys. */
export function agreementPath(profile: number, gen: number, seq: number): string {
  assertIndex('gen', gen)
  assertIndex('seq', seq)
  return `${profilePath(profile)}/${ROLE_AGREEMENT}/${gen}'/${seq}'`
}

/**
 * Recovery key, on the root-retained branch — a sibling of the delegable subtree, never a
 * descendant. Hardened derivation is one-way, so a sub-seed holder cannot reach it and the root
 * always keeps the one key that can supersede.
 */
export function recoveryPath(profile: number): string {
  assertIndex('profile', profile)
  return `${BASE_PATH}/${ROOT_ONLY}/${profile}'`
}

const KEY_LENGTHS: Record<string, number> = {
  EdDSA: 32,
  'ML-DSA-65': 32,
  'ML-KEM-768': 64,
}

/**
 * Key material for an algorithm at a path. SLIP-0010 fixes the tree position; HKDF supplies
 * algorithm separation and arbitrary lengths, so adding an algorithm needs a new `info` string
 * and no path change.
 */
export function deriveKeyMaterial(
  seed: Uint8Array,
  path: string,
  alg: string,
  length: number = KEY_LENGTHS[alg] ?? 32,
): Uint8Array {
  const node = HDKey.fromMasterSeed(seed).derive(path)
  const ikm = node.privateKey
  if (ikm == null) {
    throw new Error(`Derivation: no private key at path ${path}`)
  }
  return hkdf(sha256, ikm, undefined, `${VERSION_TAG}|${alg}`, length)
}

export function deriveKeyPair(
  seed: Uint8Array,
  path: string,
  alg: string,
): { privateKey: Uint8Array; publicKey: Uint8Array } {
  if (alg !== 'EdDSA') {
    throw new Error(`Derivation: Unsupported algorithm for key pair derivation: ${alg}`)
  }
  const privateKey = deriveKeyMaterial(seed, path, alg)
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) }
}
```

Move the `VERSION_TAG` constant into `packages/controller/src/version.ts` so `derivation.ts` does not import from the barrel:

```ts
// packages/controller/src/version.ts
/**
 * Protocol version tag. Forms the HKDF `info` string for every derived key, so the DID is a
 * function of it — it can never change once a profile exists. Deliberately independent of the
 * package name.
 */
export const VERSION_TAG = 'did:kokuin/v1'
```

`packages/controller/src/index.ts` re-exports it:

```ts
export {
  agreementPath,
  authorityPath,
  deriveKeyMaterial,
  deriveKeyPair,
  recoveryPath,
} from './derivation.js'
export { VERSION_TAG } from './version.js'
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): derivation paths and HKDF key material"
```

---

## Task 4: `DIDMethodResolver` interface in `@kokuin/token`

Sequenced here deliberately: it is independent of the fold, and defining it before `@kokuin/controller` consumes it is what surfaces a wrong shape early.

**Files:**
- Create: `packages/token/src/method.ts`
- Modify: `packages/token/src/did.ts` (`resolveIssuerWithDoc`, around lines 100-135)
- Modify: `packages/token/src/index.ts`
- Test: `packages/token/test/method.test.ts`

**Interfaces:**
- Consumes: `SignatureAlgorithm` from `./schemas.js`, `DIDString` from `./types.js`.
- Produces:
  - `type DIDMethodResolver = { method: string; resolve(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey> }`
  - `type ResolvedSigningKey = { alg: SignatureAlgorithm; publicKey: Uint8Array }`
  - `type MethodRegistry = ReadonlyArray<DIDMethodResolver>`
  - `findMethodResolver(registry: MethodRegistry, did: string): DIDMethodResolver | undefined`
  - `resolveIssuerWithDoc` gains an optional `methods?: MethodRegistry` argument.

- [ ] **Step 1: Write the failing test**

```ts
// packages/token/test/method.test.ts
import { describe, expect, test } from 'vitest'

import { resolveIssuerWithDoc } from '../src/did.js'
import { type DIDMethodResolver, findMethodResolver } from '../src/method.js'

const publicKey = new Uint8Array(32).fill(7)

const kokuinResolver: DIDMethodResolver = {
  method: 'kokuin',
  resolve: async (did) => {
    if (did !== 'did:kokuin:zABC') {
      throw new Error(`Unknown DID: ${did}`)
    }
    return { alg: 'EdDSA', publicKey }
  },
}

describe('findMethodResolver()', () => {
  test('matches on the method segment', () => {
    expect(findMethodResolver([kokuinResolver], 'did:kokuin:zABC')).toBe(kokuinResolver)
  })

  test('returns undefined for an unregistered method', () => {
    expect(findMethodResolver([kokuinResolver], 'did:example:1')).toBeUndefined()
  })

  test('returns undefined for a malformed DID rather than throwing', () => {
    expect(findMethodResolver([kokuinResolver], 'not-a-did')).toBeUndefined()
  })

  test('does not match a method that is only a prefix of the registered one', () => {
    expect(findMethodResolver([kokuinResolver], 'did:kokuinx:zABC')).toBeUndefined()
  })
})

describe('resolveIssuerWithDoc() with an injected method', () => {
  test('delegates an unknown method to its resolver', async () => {
    const result = await resolveIssuerWithDoc('did:kokuin:zABC', {}, undefined, [kokuinResolver])
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey).toEqual(publicKey)
  })

  test('still resolves did:key without any registry', async () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc(did)
    expect(result.alg).toBe('EdDSA')
    expect(result.publicKey.length).toBe(32)
  })

  test('a registered method takes precedence over the built-in did:key path', async () => {
    const override: DIDMethodResolver = {
      method: 'key',
      resolve: async () => ({ alg: 'EdDSA', publicKey }),
    }
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const result = await resolveIssuerWithDoc(did, {}, undefined, [override])
    expect(result.publicKey).toEqual(publicKey)
  })

  test('an unknown method with no registry reports the DID, not a codec error', async () => {
    await expect(resolveIssuerWithDoc('did:kokuin:zABC')).rejects.toThrow(/did:kokuin:zABC/)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/token test:unit -- method`
Expected: FAIL — `Cannot find module '../src/method.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/token/src/method.ts
import type { ResolveIssuerHeader } from './did.js'
import type { SignatureAlgorithm } from './schemas.js'

/** The signing key a DID method resolved for a given issuer and header. */
export type ResolvedSigningKey = {
  alg: SignatureAlgorithm
  publicKey: Uint8Array
}

/**
 * A DID method this package can resolve `iss` through without importing its implementation.
 *
 * Methods whose document is a projection of an event log — `did:kokuin:` — cannot be resolved
 * from the identifier alone and cannot be linked from here without a dependency cycle:
 * `@kokuin/controller` depends on this package for signing. Injecting the resolver keeps the
 * dependency one-way.
 */
export type DIDMethodResolver = {
  /** The method segment, without `did:` and without the trailing colon. E.g. `kokuin`. */
  method: string
  resolve(did: string, header: ResolveIssuerHeader): Promise<ResolvedSigningKey>
}

export type MethodRegistry = ReadonlyArray<DIDMethodResolver>

/** Total: a malformed DID yields `undefined` rather than throwing. */
export function findMethodResolver(
  registry: MethodRegistry,
  did: string,
): DIDMethodResolver | undefined {
  const parts = did.split(':')
  if (parts.length < 3 || parts[0] !== 'did') {
    return undefined
  }
  const method = parts[1]
  return registry.find((entry) => entry.method === method)
}
```

In `packages/token/src/did.ts`, import the new types and add the registry lookup as the **first** branch of `resolveIssuerWithDoc`, before the `isPeer4` check, so a registered method can override a built-in:

```ts
import { type DIDMethodResolver, findMethodResolver, type MethodRegistry } from './method.js'

export async function resolveIssuerWithDoc(
  iss: string,
  header: ResolveIssuerHeader = {},
  resolver?: DIDResolver,
  methods?: MethodRegistry,
): Promise<ResolveIssuerWithDocResult> {
  if (methods != null) {
    const methodResolver = findMethodResolver(methods, iss)
    if (methodResolver != null) {
      const { alg, publicKey } = await methodResolver.resolve(iss, header)
      return { alg, publicKey }
    }
  }

  if (isPeer4(iss)) {
    // ... existing body unchanged ...
  }

  if (!iss.startsWith(PREFIX)) {
    throw new Error(`Unknown DID: ${iss}`)
  }
  const [alg, publicKey] = getSignatureInfo(iss)
  return { alg, publicKey }
}
```

Thread the same optional argument through `resolveIssuer`:

```ts
export async function resolveIssuer(
  iss: string,
  header: ResolveIssuerHeader = {},
  resolver?: DIDResolver,
  methods?: MethodRegistry,
): Promise<[SignatureAlgorithm, Uint8Array]> {
  const { alg, publicKey } = await resolveIssuerWithDoc(iss, header, resolver, methods)
  return [alg, publicKey]
}
```

Export from `packages/token/src/index.ts`:

```ts
export {
  type DIDMethodResolver,
  findMethodResolver,
  type MethodRegistry,
  type ResolvedSigningKey,
} from './method.js'
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/token test`
Expected: PASS, including the existing token suite — the new argument is optional and the `did:key` path is unchanged except for a clearer error on an unknown method.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/token
git commit -m "feat(token): injected DID method resolver for iss resolution"
```

---

## Task 5: Inception event and the DID

**Files:**
- Create: `packages/controller/src/events.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/inception.test.ts`

**Interfaces:**
- Consumes: `digestOf` (Task 2), `authorityPath` / `recoveryPath` / `deriveKeyPair` (Task 3).
- Produces:
  - `type EventCommon = { v: 1; t: 'icp' | 'rot' | 'rev'; i?: string; g: number; s: number; p?: string; crit: boolean }`
  - `type InceptionEvent = EventCommon & { t: 'icp'; k: string[]; n: string[]; kt: number; nt: number; r: string }`
  - `type SignedEvent<E> = { event: E; sigs: string[] }`
  - `createInception(seed: Uint8Array, profile: number): SignedEvent<InceptionEvent>`
  - `didFromInception(event: InceptionEvent): string`
  - `verifyInception(signed: SignedEvent<InceptionEvent>, did: string): boolean`
  - `encodeKey(publicKey: Uint8Array): string` / `decodeKey(value: string): Uint8Array`

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/inception.test.ts
import { describe, expect, test } from 'vitest'

import { createInception, didFromInception, verifyInception } from '../src/events.js'

const seedA = new Uint8Array(32).fill(1)
const seedB = new Uint8Array(32).fill(2)

describe('createInception()', () => {
  test('is a pure function of seed and profile index', () => {
    expect(createInception(seedA, 0)).toEqual(createInception(seedA, 0))
  })

  test('contains no timestamp, nonce or label', () => {
    const { event } = createInception(seedA, 0)
    const keys = Object.keys(event).sort()
    expect(keys).toEqual(['crit', 'g', 'k', 'kt', 'n', 'nt', 'r', 's', 't', 'v'])
  })

  test('omits `i` from the inception body — the DID is its hash', () => {
    expect(createInception(seedA, 0).event.i).toBeUndefined()
  })

  test('starts at generation 0, sequence 0', () => {
    const { event } = createInception(seedA, 0)
    expect(event.g).toBe(0)
    expect(event.s).toBe(0)
  })

  test('has no previous-event digest', () => {
    expect(createInception(seedA, 0).event.p).toBeUndefined()
  })

  test('commits next-key digests, not next keys', () => {
    const { event } = createInception(seedA, 0)
    expect(event.n).toHaveLength(1)
    expect(event.n[0]).not.toBe(event.k[0])
  })

  test('commits a recovery key digest', () => {
    expect(createInception(seedA, 0).event.r).toMatch(/^z/)
  })

  test('is marked critical — a verifier that cannot read it must not proceed', () => {
    expect(createInception(seedA, 0).event.crit).toBe(true)
  })
})

describe('didFromInception()', () => {
  test('regenerates the same DID from the same mnemonic and index', () => {
    expect(didFromInception(createInception(seedA, 0).event)).toBe(
      didFromInception(createInception(seedA, 0).event),
    )
  })

  test('differs per profile index, so profiles are enumerable and distinct', () => {
    expect(didFromInception(createInception(seedA, 0).event)).not.toBe(
      didFromInception(createInception(seedA, 1).event),
    )
  })

  test('differs per seed', () => {
    expect(didFromInception(createInception(seedA, 0).event)).not.toBe(
      didFromInception(createInception(seedB, 0).event),
    )
  })

  test('carries no version segment', () => {
    const did = didFromInception(createInception(seedA, 0).event)
    expect(did).toMatch(/^did:kokuin:z[1-9A-HJ-NP-Za-km-z]+$/)
    expect(did.split(':')).toHaveLength(3)
  })
})

describe('verifyInception()', () => {
  test('accepts a self-consistent inception', () => {
    const signed = createInception(seedA, 0)
    expect(verifyInception(signed, didFromInception(signed.event))).toBe(true)
  })

  test('rejects a DID that is not the hash of the event', () => {
    const signed = createInception(seedA, 0)
    const other = didFromInception(createInception(seedA, 1).event)
    expect(verifyInception(signed, other)).toBe(false)
  })

  test('rejects a tampered key set', () => {
    const signed = createInception(seedA, 0)
    const did = didFromInception(signed.event)
    const tampered = { ...signed, event: { ...signed.event, k: ['zBOGUS'] } }
    expect(verifyInception(tampered, did)).toBe(false)
  })

  test('rejects a bad signature', () => {
    const signed = createInception(seedA, 0)
    const did = didFromInception(signed.event)
    expect(verifyInception({ ...signed, sigs: ['zzz'] }, did)).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit`
Expected: FAIL — `Cannot find module '../src/events.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/events.ts
import { ed25519 } from '@noble/curves/ed25519.js'
import { base58, base64urlnopad } from '@scure/base'

import { canonicalBytes, digestOf } from './canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from './derivation.js'

export const DID_PREFIX = 'did:kokuin:'

export type EventType = 'icp' | 'rot' | 'rev'

export type EventCommon = {
  /** Inception format version. Absent must never be inferred; always written. */
  v: 1
  t: EventType
  /** Profile DID. Omitted from an inception, whose hash *is* the DID. */
  i?: string
  /** Generation. Incremented only by a reset. */
  g: number
  /** Sequence within the generation. */
  s: number
  /** Digest of the previous event. Absent on inception. */
  p?: string
  /**
   * Criticality. Lives in the common envelope so a verifier can read it without understanding
   * `t`. An unknown event fails the fold closed when true, and is skipped when false.
   */
  crit: boolean
}

export type InceptionEvent = EventCommon & {
  t: 'icp'
  /** Current public keys, multibase-encoded. */
  k: string[]
  /** Digests of the next public keys — pre-rotation. */
  n: string[]
  /** Signing threshold. */
  kt: number
  /** Rotation threshold. */
  nt: number
  /** Digest of the recovery key. Root-retained; immutable unless a co-signed rotate moves it. */
  r: string
}

export type SignedEvent<E extends EventCommon = EventCommon> = {
  event: E
  /** base64url ed25519 signatures over the canonical event bytes, positional against `event.k`. */
  sigs: string[]
}

export function encodeKey(publicKey: Uint8Array): string {
  return `z${base58.encode(publicKey)}`
}

export function decodeKey(value: string): Uint8Array {
  if (!value.startsWith('z')) {
    throw new Error(`Invalid multibase key: ${value}`)
  }
  return base58.decode(value.slice(1))
}

export function signEvent(event: EventCommon, privateKeys: Uint8Array[]): string[] {
  const bytes = canonicalBytes(event)
  return privateKeys.map((key) => base64urlnopad.encode(ed25519.sign(bytes, key)))
}

/** Total: a malformed signature or key yields false rather than throwing. */
export function verifySignatures(event: EventCommon, sigs: string[], keys: string[]): boolean {
  if (sigs.length !== keys.length || sigs.length === 0) {
    return false
  }
  const bytes = canonicalBytes(event)
  for (let i = 0; i < sigs.length; i++) {
    try {
      if (!ed25519.verify(base64urlnopad.decode(sigs[i]), bytes, decodeKey(keys[i]))) {
        return false
      }
    } catch {
      return false
    }
  }
  return true
}

/**
 * Deterministic inception. Contains only seed-derived and canonical material — no timestamp, no
 * nonce, no user label — so its hash, and therefore the DID, is a pure function of the seed and
 * the profile index.
 *
 * A user label must never be added here. The DID depends on every byte, so a mistyped label on
 * recovery would reproduce a different DID.
 */
export function createInception(seed: Uint8Array, profile: number): SignedEvent<InceptionEvent> {
  const current = deriveKeyPair(seed, authorityPath(profile, 0, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, 0, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')

  const event: InceptionEvent = {
    v: 1,
    t: 'icp',
    g: 0,
    s: 0,
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    r: digestOf(encodeKey(recovery.publicKey)),
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

export function didFromInception(event: InceptionEvent): string {
  return `${DID_PREFIX}${digestOf(event)}`
}

export function verifyInception(signed: SignedEvent<InceptionEvent>, did: string): boolean {
  if (signed.event.t !== 'icp' || signed.event.i !== undefined) {
    return false
  }
  if (didFromInception(signed.event) !== did) {
    return false
  }
  return verifySignatures(signed.event, signed.sigs, signed.event.k)
}
```

Export the new names from `packages/controller/src/index.ts`.

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): deterministic inception and did:kokuin identifier"
```

---

## Task 6: Rotate event and pre-rotation verification

**Files:**
- Modify: `packages/controller/src/events.ts`
- Test: `packages/controller/test/rotate.test.ts`

**Interfaces:**
- Consumes: everything from Task 5.
- Produces:
  - `type RotateEvent = EventCommon & { t: 'rot'; k: string[]; n: string[]; kt: number; nt: number; r?: string; a?: string; d?: string[] }`
  - `createRotate(seed: Uint8Array, profile: number, did: string, prior: EventCommon, options?: CreateRotateOptions): SignedEvent<RotateEvent>`
  - `type CreateRotateOptions = { seal?: string; deny?: string[]; reset?: boolean }`
  - `verifyRotate(signed: SignedEvent<RotateEvent>, prior: { digest: string; n: string[] }): boolean`

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/rotate.test.ts
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import {
  createInception,
  createRotate,
  didFromInception,
  verifyRotate,
} from '../src/events.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  return { inception, did, priorDigest: digestOf(inception.event) }
}

describe('createRotate()', () => {
  test('advances the sequence and keeps the generation', () => {
    const { inception, did } = setup()
    const { event } = createRotate(seed, 0, did, inception.event)
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('names the DID explicitly, unlike inception', () => {
    const { inception, did } = setup()
    expect(createRotate(seed, 0, did, inception.event).event.i).toBe(did)
  })

  test('chains to the previous event by digest', () => {
    const { inception, did, priorDigest } = setup()
    expect(createRotate(seed, 0, did, inception.event).event.p).toBe(priorDigest)
  })

  test('reveals the keys the prior event pre-committed', () => {
    const { inception, did } = setup()
    const { event } = createRotate(seed, 0, did, inception.event)
    expect(digestOf(event.k[0])).toBe(inception.event.n[0])
  })

  test('is reproducible from the seed when it carries no optional fields', () => {
    const { inception, did } = setup()
    expect(createRotate(seed, 0, did, inception.event)).toEqual(
      createRotate(seed, 0, did, inception.event),
    )
  })

  test('carries a seal when one is given', () => {
    const { inception, did } = setup()
    const seal = digestOf({ grant: 'management' })
    expect(createRotate(seed, 0, did, inception.event, { seal }).event.a).toBe(seal)
  })

  test('carries a deny-set snapshot when one is given', () => {
    const { inception, did } = setup()
    const deny = ['did:key:zStolen']
    expect(createRotate(seed, 0, did, inception.event, { deny }).event.d).toEqual(deny)
  })
})

describe('verifyRotate()', () => {
  test('accepts a rotate signed by the pre-committed next keys', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(true)
  })

  test('rejects a rotate whose keys were not pre-committed — a stolen device cannot rotate', () => {
    const { inception, did, priorDigest } = setup()
    const other = new Uint8Array(32).fill(9)
    const signed = createRotate(other, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })

  test('rejects a rotate that does not chain to the prior digest', () => {
    const { inception, did } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    expect(verifyRotate(signed, { digest: digestOf({ other: true }), n: inception.event.n })).toBe(
      false,
    )
  })

  test('rejects a tampered deny snapshot — it is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRotate(seed, 0, did, inception.event)
    const tampered = { ...signed, event: { ...signed.event, d: ['did:key:zInjected'] } }
    expect(verifyRotate(tampered, { digest: priorDigest, n: inception.event.n })).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- rotate`
Expected: FAIL — `createRotate is not exported`.

- [ ] **Step 3: Write the implementation**

Append to `packages/controller/src/events.ts`:

```ts
export type RotateEvent = EventCommon & {
  t: 'rot'
  k: string[]
  n: string[]
  kt: number
  nt: number
  /** Recovery-commitment update. Only valid when co-signed by the current recovery key. */
  r?: string
  /** Seal: an anchored external digest, used to pin a high-value grant to a log position. */
  a?: string
  /** Deny-set snapshot. Replaces the accumulated set, pruning it. */
  d?: string[]
}

export type CreateRotateOptions = {
  seal?: string
  deny?: string[]
  /** Increment the generation instead of the sequence — a reset. */
  reset?: boolean
}

/**
 * A rotate reveals the keys the prior event pre-committed and commits the next set. Signed by the
 * newly revealed keys, per KERI, which is what makes a stolen current key unable to rotate.
 *
 * Reproducible from the seed alone unless it carries a seal, a deny snapshot, or a recovery
 * update — see the spec's "Determinism and its boundary".
 */
export function createRotate(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  options: CreateRotateOptions = {},
): SignedEvent<RotateEvent> {
  const gen = options.reset === true ? prior.g + 1 : prior.g
  const seq = options.reset === true ? 0 : prior.s + 1
  const current = deriveKeyPair(seed, authorityPath(profile, gen, seq), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, seq + 1), 'EdDSA')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: seq,
    p: digestOf(prior),
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    a: options.seal,
    d: options.deny,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/**
 * A rotate is valid when it chains to the prior digest, its revealed keys match the prior
 * event's pre-rotation commitment, and its signatures verify against those keys.
 */
export function verifyRotate(
  signed: SignedEvent<RotateEvent>,
  prior: { digest: string; n: string[] },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== prior.digest) {
    return false
  }
  if (event.k.length !== prior.n.length) {
    return false
  }
  for (let i = 0; i < event.k.length; i++) {
    if (digestOf(event.k[i]) !== prior.n[i]) {
      return false
    }
  }
  return verifySignatures(event, sigs, event.k)
}
```

Export `createRotate`, `verifyRotate`, `RotateEvent` and `CreateRotateOptions` from `index.ts`.

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): rotate events verified against pre-rotation commitments"
```

---

## Task 7: Reset — generation increment under the recovery key

> **Superseded in part by Amendment A.** The signatures and test code below take a `prior` event
> and an options object; both are gone. Read Amendment A for the shapes that ship. The rationale,
> the derivation paths, and the `recoveryKey`-on-the-envelope mechanism below are all still current.

**Files:**
- Modify: `packages/controller/src/events.ts`
- Test: `packages/controller/test/reset.test.ts`

**Interfaces:**
- Consumes: `createRotate` (Task 6), `recoveryPath` (Task 3).
- Produces: `createReset(seed, profile, did, prior: EventCommon, options?): SignedEvent<RotateEvent>`, `verifyReset(signed, prior: { digest: string; r: string }): boolean`.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/reset.test.ts
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createInception, createReset, didFromInception, verifyReset } from '../src/events.js'

const seed = new Uint8Array(32).fill(1)

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
    priorDigest: digestOf(inception.event),
  }
}

describe('createReset()', () => {
  test('increments the generation and restarts the sequence', () => {
    const { inception, did } = setup()
    const { event } = createReset(seed, 0, did, inception.event)
    expect(event.g).toBe(1)
    expect(event.s).toBe(0)
  })

  test('is a rotate variant, not a fourth event type', () => {
    const { inception, did } = setup()
    expect(createReset(seed, 0, did, inception.event).event.t).toBe('rot')
  })

  test('clears the deny set by carrying an empty snapshot', () => {
    const { inception, did } = setup()
    expect(createReset(seed, 0, did, inception.event).event.d).toEqual([])
  })
})

describe('verifyReset()', () => {
  test('accepts a reset signed by the committed recovery key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createReset(seed, 0, did, inception.event)
    expect(verifyReset(signed, { digest: priorDigest, r: inception.event.r })).toBe(true)
  })

  test('rejects a reset signed by any other key — the root always wins the race', () => {
    const { inception, did, priorDigest } = setup()
    const thiefSeed = new Uint8Array(32).fill(9)
    const signed = createReset(thiefSeed, 0, did, inception.event)
    expect(verifyReset(signed, { digest: priorDigest, r: inception.event.r })).toBe(false)
  })

  test('rejects a reset that does not increment the generation', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createReset(seed, 0, did, inception.event)
    const tampered = { ...signed, event: { ...signed.event, g: 0 } }
    expect(verifyReset(tampered, { digest: priorDigest, r: inception.event.r })).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- reset`
Expected: FAIL — `createReset is not exported`.

- [ ] **Step 3: Write the implementation**

Append to `packages/controller/src/events.ts`:

```ts
/**
 * A reset: a rotate signed by the recovery key that increments the generation and discards
 * everything under the prior one, including every capability minted there.
 *
 * The recovery key lives on the root-retained derivation branch and its digest is committed in
 * the deterministic inception, so a restored mnemonic can always author one with no log at all.
 */
export function createReset(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  options: Omit<CreateRotateOptions, 'reset'> = {},
): SignedEvent<RotateEvent> {
  const gen = prior.g + 1
  const current = deriveKeyPair(seed, authorityPath(profile, gen, 0), 'EdDSA')
  const next = deriveKeyPair(seed, authorityPath(profile, gen, 1), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(profile), 'EdDSA')

  const event: RotateEvent = {
    v: 1,
    t: 'rot',
    i: did,
    g: gen,
    s: 0,
    p: digestOf(prior),
    crit: true,
    k: [encodeKey(current.publicKey)],
    n: [digestOf(encodeKey(next.publicKey))],
    kt: 1,
    nt: 1,
    a: options.seal,
    // A reset clears the deny set: every capability under the prior generation is gone anyway.
    d: options.deny ?? [],
  }

  return { event, sigs: signEvent(event, [recovery.privateKey]) }
}

/** A reset verifies against the committed recovery digest, not against the pre-rotation set. */
export function verifyReset(
  signed: SignedEvent<RotateEvent>,
  prior: { digest: string; r: string },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rot' || event.p !== prior.digest || event.s !== 0) {
    return false
  }
  if (sigs.length !== 1) {
    return false
  }
  // The recovery public key is not published until it is used; the commitment is its digest.
  // Recover it from the signature check by trying the event's own key list is not possible here,
  // so the caller supplies the revealed recovery key alongside the signature.
  const revealed = signed.recoveryKey
  if (revealed == null || digestOf(revealed) !== prior.r) {
    return false
  }
  return verifySignatures(event, sigs, [revealed])
}
```

This needs the revealed recovery key on the wire. Extend `SignedEvent`:

```ts
export type SignedEvent<E extends EventCommon = EventCommon> = {
  event: E
  sigs: string[]
  /**
   * The revealed recovery public key, present only on a reset. Pre-rotation means the recovery
   * key is committed as a digest and unpublished until used, so a reset must reveal it for the
   * commitment to be checkable.
   */
  recoveryKey?: string
}
```

And set it in `createReset`:

```ts
  return {
    event,
    sigs: signEvent(event, [recovery.privateKey]),
    recoveryKey: encodeKey(recovery.publicKey),
  }
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): reset as a recovery-key-signed generation increment"
```

---

## Task 8: Revoke events and the deny set

> **Superseded in part by Amendment A.** `createRevoke` takes an explicit `keyPosition` argument
> between `target` and `options`; the test code below omits it. Read Amendment A for the shape
> that ships and for why one `prior` parameter could not answer both questions it was being asked.

**Files:**
- Modify: `packages/controller/src/events.ts`
- Test: `packages/controller/test/revoke.test.ts`

**Interfaces:**
- Consumes: Task 6 types.
- Produces: `type RevokeEvent = EventCommon & { t: 'rev'; x: string; cap?: string }`, `createRevoke(seed, profile, did, prior, target, options?)`, `verifyRevoke(signed, prior: { digest: string; keys: string[] })`.

Revocation authorised by the hot management capability (`cap` present) is verified in Task 11, where the capability chain is available. This task covers the authority-signed path.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/revoke.test.ts
import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { createInception, createRevoke, didFromInception, verifyRevoke } from '../src/events.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function setup() {
  const inception = createInception(seed, 0)
  return {
    inception,
    did: didFromInception(inception.event),
    priorDigest: digestOf(inception.event),
  }
}

describe('createRevoke()', () => {
  test('names the device DID, not a capability jti', () => {
    const { inception, did } = setup()
    expect(createRevoke(seed, 0, did, inception.event, stolen).event.x).toBe(stolen)
  })

  test('advances the sequence within the generation', () => {
    const { inception, did } = setup()
    const { event } = createRevoke(seed, 0, did, inception.event, stolen)
    expect(event.s).toBe(1)
    expect(event.g).toBe(0)
  })

  test('is critical — a verifier that skips it accepts a revoked device', () => {
    const { inception, did } = setup()
    expect(createRevoke(seed, 0, did, inception.event, stolen).event.crit).toBe(true)
  })

  test('does not rotate the key set', () => {
    const { inception, did } = setup()
    const { event } = createRevoke(seed, 0, did, inception.event, stolen)
    expect(event).not.toHaveProperty('k')
    expect(event).not.toHaveProperty('n')
  })
})

describe('verifyRevoke()', () => {
  test('accepts a revoke signed by the current authority key', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke(seed, 0, did, inception.event, stolen)
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(true)
  })

  test('rejects a revoke signed by an unrelated key', () => {
    const { inception, did, priorDigest } = setup()
    const thief = new Uint8Array(32).fill(9)
    const signed = createRevoke(thief, 0, did, inception.event, stolen)
    expect(verifyRevoke(signed, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })

  test('rejects a tampered target — the DID is covered by the signature', () => {
    const { inception, did, priorDigest } = setup()
    const signed = createRevoke(seed, 0, did, inception.event, stolen)
    const tampered = { ...signed, event: { ...signed.event, x: 'did:key:zOther' } }
    expect(verifyRevoke(tampered, { digest: priorDigest, keys: inception.event.k })).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- revoke`
Expected: FAIL — `createRevoke is not exported`.

- [ ] **Step 3: Write the implementation**

Append to `packages/controller/src/events.ts`:

```ts
export type RevokeEvent = EventCommon & {
  t: 'rev'
  /** The DID to deny. A device DID, never a capability `jti`. */
  x: string
  /** A serialized capability authorising a non-authority signer. Verified in the fold. */
  cap?: string
}

/**
 * Revoke a DID: no capability whose `aud` is that DID is valid from this position onward.
 *
 * Naming the device DID rather than a `jti` makes this one entry per device for that device's
 * life — it covers capabilities the verifier has never seen and covers future re-mints, where
 * per-`jti` revocation would grow with every renewal.
 */
export function createRevoke(
  seed: Uint8Array,
  profile: number,
  did: string,
  prior: EventCommon,
  target: string,
  options: { cap?: string } = {},
): SignedEvent<RevokeEvent> {
  const current = deriveKeyPair(seed, authorityPath(profile, prior.g, prior.s), 'EdDSA')

  const event: RevokeEvent = {
    v: 1,
    t: 'rev',
    i: did,
    g: prior.g,
    s: prior.s + 1,
    p: digestOf(prior),
    crit: true,
    x: target,
    cap: options.cap,
  }

  return { event, sigs: signEvent(event, [current.privateKey]) }
}

/** Authority-signed revoke. Capability-authorised revokes are checked in the fold. */
export function verifyRevoke(
  signed: SignedEvent<RevokeEvent>,
  prior: { digest: string; keys: string[] },
): boolean {
  const { event, sigs } = signed
  if (event.t !== 'rev' || event.p !== prior.digest) {
    return false
  }
  return verifySignatures(event, sigs, prior.keys)
}
```

Export the new names.

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): revoke events naming device DIDs"
```

---

## Task 9: Sequential fold and key state

**Files:**
- Create: `packages/controller/src/fold.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/fold.test.ts`

**Interfaces:**
- Consumes: all event types and verifiers from Tasks 5-8.
- Produces:
  - `type KeyState = { did: string; gen: number; seq: number; keyGen: number; keySeq: number; keys: Array<string>; next: Array<string>; recovery: string; deny: ReadonlySet<string>; digest: string }` — see Amendment A for `keyGen`/`keySeq`
  - `type FoldResult = { ok: true; states: KeyState[] } | { ok: false; reason: string; index: number }`
  - `foldLog(did: string, events: SignedEvent[]): FoldResult`
  - `keyStateAt(result: FoldResult, position: number): KeyState | undefined`

`states[i]` is the state *after* applying `events[i]`, so `keyStateAt(result, i)` is the state a verifier evaluating at log position `i` must use.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/fold.test.ts
import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { foldLog, keyStateAt } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate(seed, 0, did, icp.event)
  // The rotate established the active key at its own position (gen 0, seq 1), so that is the
  // keyPosition the revoke signs with — see Amendment A.
  const rev = createRevoke(seed, 0, did, rot.event, stolen, { gen: 0, seq: 1 })
  return { did, icp, rot, rev }
}

describe('foldLog()', () => {
  test('folds inception alone', () => {
    const { did, icp } = build()
    const result = foldLog(did, [icp])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[0].keys).toEqual(icp.event.k)
    expect(result.states[0].gen).toBe(0)
    expect(result.states[0].seq).toBe(0)
  })

  test('applies a rotate, replacing the key set', () => {
    const { did, icp, rot } = build()
    const result = foldLog(did, [icp, rot])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].keys).toEqual(rot.event.k)
    expect(result.states[1].keys).not.toEqual(icp.event.k)
  })

  test('applies a revoke, adding to the deny set without touching the keys', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[2].deny.has(stolen)).toBe(true)
    expect(result.states[2].keys).toEqual(rot.event.k)
  })

  test('rejects a log whose first event is not an inception', () => {
    const { did, rot } = build()
    const result = foldLog(did, [rot])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/inception/)
  })

  test('rejects an inception whose hash is not the DID', () => {
    const { icp } = build()
    const result = foldLog('did:kokuin:zWRONG', [icp])
    expect(result.ok).toBe(false)
  })

  test('rejects a sequence gap', () => {
    const { did, icp, rot } = build()
    const gapped = { ...rot, event: { ...rot.event, s: 5 } }
    const result = foldLog(did, [icp, gapped])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.index).toBe(1)
  })

  test('rejects an event that does not chain to the previous digest', () => {
    const { did, icp, rot } = build()
    const orphan = { ...rot, event: { ...rot.event, p: 'zNOTTHEPRIOR' } }
    const result = foldLog(did, [icp, orphan])
    expect(result.ok).toBe(false)
  })

  test('a reset increments the generation and clears the deny set', () => {
    const { did, icp, rot, rev } = build()
    // Anchored to the inception, not to the head — see Amendment A.
    const reset = createReset(seed, 0, 1)
    const result = foldLog(did, [icp, rot, rev, reset])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[3].gen).toBe(1)
    expect(result.states[3].seq).toBe(0)
    expect(result.states[3].deny.size).toBe(0)
  })
})

describe('keyStateAt()', () => {
  test('returns the state after the event at that position', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(keyStateAt(result, 1)?.keys).toEqual(rot.event.k)
  })

  test('a device denied later is not denied at an earlier position', () => {
    const { did, icp, rot, rev } = build()
    const result = foldLog(did, [icp, rot, rev])
    expect(keyStateAt(result, 1)?.deny.has(stolen)).toBe(false)
    expect(keyStateAt(result, 2)?.deny.has(stolen)).toBe(true)
  })

  test('a revoke carries the key position forward, so a second revoke can be signed', () => {
    const { did, icp, rot, rev } = build()
    const state = keyStateAt(foldLog(did, [icp, rot, rev]), 2)
    expect(state).toBeDefined()
    if (state == null) return
    // The revoke did not rotate, so the keys are still the rotate's and so is their position.
    expect(state.keys).toEqual(rot.event.k)
    expect(state.keyGen).toBe(0)
    expect(state.keySeq).toBe(1)
    // Signing a second revoke from that position must produce a foldable event — the defect
    // Amendment A fixes was that this chained revoke signed with an unrevealed key.
    const second = createRevoke(seed, 0, did, rev.event, 'did:key:zOther', {
      gen: state.keyGen,
      seq: state.keySeq,
    })
    const chained = foldLog(did, [icp, rot, rev, second])
    expect(chained.ok).toBe(true)
    if (!chained.ok) return
    expect(chained.states[3].deny.has(stolen)).toBe(true)
    expect(chained.states[3].deny.has('did:key:zOther')).toBe(true)
  })

  test('returns undefined past the end of the log', () => {
    const { did, icp } = build()
    expect(keyStateAt(foldLog(did, [icp]), 9)).toBeUndefined()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- fold`
Expected: FAIL — `Cannot find module '../src/fold.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/fold.ts
import { digestOf } from './canonical.js'
import {
  type EventCommon,
  type InceptionEvent,
  type RevokeEvent,
  type RotateEvent,
  type SignedEvent,
  verifyInception,
  verifyReset,
  verifyRevoke,
  verifyRotate,
} from './events.js'

export type KeyState = {
  did: string
  gen: number
  seq: number
  keys: string[]
  next: string[]
  recovery: string
  deny: ReadonlySet<string>
  /** Digest of the event that produced this state — the `p` any successor must carry. */
  digest: string
}

export type FoldResult =
  | { ok: true; states: KeyState[] }
  | { ok: false; reason: string; index: number }

function fail(reason: string, index: number): FoldResult {
  return { ok: false, reason, index }
}

/**
 * Fold a controller's log into per-position key state.
 *
 * `states[i]` is the state *after* `events[i]`, which is what a verifier evaluating at log
 * position `i` must use. That is what makes the deny set position-dependent: clearing a DID at a
 * later position never retroactively validates its earlier actions.
 */
export function foldLog(did: string, events: SignedEvent[]): FoldResult {
  if (events.length === 0) {
    return fail('empty log', 0)
  }

  const first = events[0] as SignedEvent<InceptionEvent>
  if (first.event.t !== 'icp') {
    return fail('first event must be an inception', 0)
  }
  if (!verifyInception(first, did)) {
    return fail('invalid inception', 0)
  }

  const states: Array<KeyState> = [
    {
      did,
      gen: first.event.g,
      seq: first.event.s,
      keyGen: first.event.g,
      keySeq: first.event.s,
      keys: first.event.k,
      next: first.event.n,
      recovery: first.event.r,
      deny: new Set<string>(),
      digest: digestOf(first.event),
    },
  ]

  for (let i = 1; i < events.length; i++) {
    const signed = events[i]
    const event = signed.event
    const prior = states[i - 1]

    if (event.i !== did) {
      return fail('event names a different controller', i)
    }

    if (event.t === 'rot') {
      const rot = signed as SignedEvent<RotateEvent>
      const isReset = rot.event.g > prior.gen

      if (isReset) {
        // A reset chains to the inception, not to the head — Amendment A. That is what lets a
        // root holding only its seed author one: `p` is recomputable without the log.
        if (rot.event.s !== 0) {
          return fail('reset must restart the sequence', i)
        }
        if (!verifyReset(rot, first.event)) {
          return fail('invalid reset', i)
        }
      } else {
        if (rot.event.p !== prior.digest) {
          return fail('event does not chain to the previous digest', i)
        }
        if (rot.event.g !== prior.gen || rot.event.s !== prior.seq + 1) {
          return fail('sequence gap', i)
        }
        if (!verifyRotate(rot, { digest: prior.digest, n: prior.next })) {
          return fail('invalid rotate', i)
        }
      }

      states.push({
        did,
        gen: rot.event.g,
        seq: rot.event.s,
        // A rotate (reset included) establishes new keys at its own position.
        keyGen: rot.event.g,
        keySeq: rot.event.s,
        keys: rot.event.k,
        next: rot.event.n,
        recovery: rot.event.r ?? prior.recovery,
        deny: rot.event.d == null ? prior.deny : new Set(rot.event.d),
        digest: digestOf(rot.event),
      })
      continue
    }

    if (event.p !== prior.digest) {
      return fail('event does not chain to the previous digest', i)
    }

    if (event.t === 'rev') {
      const rev = signed as SignedEvent<RevokeEvent>
      if (rev.event.g !== prior.gen || rev.event.s !== prior.seq + 1) {
        return fail('sequence gap', i)
      }
      if (!verifyRevoke(rev, { digest: prior.digest, keys: prior.keys })) {
        return fail('invalid revoke', i)
      }
      const deny = new Set(prior.deny)
      deny.add(rev.event.x)
      // `keyGen`/`keySeq` ride along in the spread: a revoke establishes no key, so the active
      // position is still wherever the last icp/rot put it.
      states.push({ ...prior, seq: rev.event.s, deny, digest: digestOf(rev.event) })
      continue
    }

    return fail(`unknown event type: ${String((event as EventCommon).t)}`, i)
  }

  return { ok: true, states }
}

export function keyStateAt(result: FoldResult, position: number): KeyState | undefined {
  return result.ok ? result.states[position] : undefined
}
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): sequential fold to per-position key state"
```

---

## Task 10: Superseding recovery and duplicity

**Files:**
- Create: `packages/controller/src/supersede.ts`
- Modify: `packages/controller/src/fold.ts`, `packages/controller/src/index.ts`
- Test: `packages/controller/test/supersede.test.ts`

**Interfaces:**
- Consumes: `foldLog`, `KeyState` (Task 9).
- Produces:
  - `type Branch = { events: SignedEvent[] }`
  - `type Duplicity = { gen: number; seq: number; digests: [string, string] }`
  - `resolveBranches(did: string, branches: SignedEvent[][]): { ok: true; winner: SignedEvent[]; superseded: number } | { ok: false; duplicity: Duplicity }`

Precedence: `(gen, seq)` lexicographic; at an equal position, a `rot` verifying against the prior event's pre-rotation commitment beats an event signed by current keys. Anything else is duplicity — surfaced, never merged.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/supersede.test.ts
import { describe, expect, test } from 'vitest'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const victim = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  return { did, icp }
}

describe('resolveBranches()', () => {
  test('a longer branch at the same generation wins on sequence', () => {
    const { did, icp } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [[icp], [icp, rot]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner).toHaveLength(2)
  })

  test('a higher generation wins outright over a longer lower generation', () => {
    const { did, icp } = build()
    const rot = createRotate(seed, 0, did, icp.event)
    const rev = createRevoke(seed, 0, did, rot.event, victim, { gen: 0, seq: 1 })
    const reset = createReset(seed, 0, 1)
    const result = resolveBranches(did, [[icp, rot, rev], [icp, reset]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner[1].event.g).toBe(1)
  })

  test('a rotate signed by pre-committed next keys supersedes a current-key event at the same position', () => {
    const { did, icp } = build()
    // The thief holds the current authority key — established by the inception at (0, 0) — and
    // revokes the owner's other device.
    const thiefRevoke = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    // The owner rotates using the pre-committed next keys at the same position.
    const ownerRotate = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [[icp, thiefRevoke], [icp, ownerRotate]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.winner[1].event.t).toBe('rot')
    expect(result.superseded).toBe(1)
  })

  test('order of presentation does not change the winner', () => {
    const { did, icp } = build()
    const thiefRevoke = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const ownerRotate = createRotate(seed, 0, did, icp.event)
    const a = resolveBranches(did, [[icp, ownerRotate], [icp, thiefRevoke]])
    const b = resolveBranches(did, [[icp, thiefRevoke], [icp, ownerRotate]])
    expect(a.ok && b.ok).toBe(true)
    if (!a.ok || !b.ok) return
    expect(a.winner[1].event.t).toBe(b.winner[1].event.t)
  })

  test('two current-key events at the same position are duplicity, not a merge', () => {
    const { did, icp } = build()
    const revokeA = createRevoke(seed, 0, did, icp.event, victim, { gen: 0, seq: 0 })
    const revokeB = createRevoke(seed, 0, did, icp.event, 'did:key:zOther', { gen: 0, seq: 0 })
    const result = resolveBranches(did, [[icp, revokeA], [icp, revokeB]])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
  })

  test('re-derivation is idempotent, so identical branches are not duplicity', () => {
    const { did, icp } = build()
    const a = createRotate(seed, 0, did, icp.event)
    const b = createRotate(seed, 0, did, icp.event)
    const result = resolveBranches(did, [[icp, a], [icp, b]])
    expect(result.ok).toBe(true)
  })

  test('a single branch resolves to itself', () => {
    const { did, icp } = build()
    const result = resolveBranches(did, [[icp]])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.superseded).toBe(0)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- supersede`
Expected: FAIL — `Cannot find module '../src/supersede.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/supersede.ts
import { digestOf } from './canonical.js'
import { type RotateEvent, type SignedEvent, verifyRotate } from './events.js'
import { foldLog } from './fold.js'

export type Duplicity = {
  gen: number
  seq: number
  digests: [string, string]
}

export type ResolveResult =
  | { ok: true; winner: SignedEvent[]; superseded: number }
  | { ok: false; duplicity: Duplicity }

function head(branch: SignedEvent[]): { gen: number; seq: number } {
  const last = branch[branch.length - 1].event
  return { gen: last.g, seq: last.s }
}

/**
 * Does `candidate` supersede `incumbent` at the same position?
 *
 * Per KERI, a rotate signed by the pre-committed next keys outranks any operation signed by
 * current keys. That is what makes the owner win the race against a thief holding a current
 * authority key regardless of who published first.
 */
function supersedes(
  candidate: SignedEvent,
  incumbent: SignedEvent,
  priorDigest: string,
  priorNext: string[],
): boolean {
  if (candidate.event.t !== 'rot') {
    return false
  }
  if (incumbent.event.t === 'rot') {
    return false
  }
  return verifyRotate(candidate as SignedEvent<RotateEvent>, {
    digest: priorDigest,
    n: priorNext,
  })
}

/**
 * Pick the authoritative branch. Precedence is `(gen, seq)` lexicographic; at an equal position,
 * a superseding rotate wins. Anything else at an equal position is duplicity — surfaced rather
 * than merged, because rotation is sequential per controller.
 *
 * `superseded` counts events discarded from losing branches, which is what a cache must
 * invalidate: folded state is not append-only under supersession.
 */
export function resolveBranches(did: string, branches: SignedEvent[][]): ResolveResult {
  const valid = branches.filter((branch) => foldLog(did, branch).ok)
  if (valid.length === 0) {
    return { ok: false, duplicity: { gen: 0, seq: 0, digests: ['', ''] } }
  }

  let winner = valid[0]
  let superseded = 0

  for (let i = 1; i < valid.length; i++) {
    const challenger = valid[i]
    const w = head(winner)
    const c = head(challenger)

    if (c.gen !== w.gen) {
      if (c.gen > w.gen) {
        superseded += winner.length
        winner = challenger
      } else {
        superseded += challenger.length
      }
      continue
    }

    if (c.seq !== w.seq) {
      if (c.seq > w.seq) {
        superseded += winner.length
        winner = challenger
      } else {
        superseded += challenger.length
      }
      continue
    }

    const wHead = winner[winner.length - 1]
    const cHead = challenger[challenger.length - 1]
    const wDigest = digestOf(wHead.event)
    const cDigest = digestOf(cHead.event)

    // Re-derivation is idempotent: identical bytes are the same event, not a fork.
    if (wDigest === cDigest) {
      continue
    }

    const priorIndex = winner.length - 2
    if (priorIndex < 0) {
      return { ok: false, duplicity: { gen: c.gen, seq: c.seq, digests: [wDigest, cDigest] } }
    }
    const priorState = foldLog(did, winner.slice(0, -1))
    if (!priorState.ok) {
      return { ok: false, duplicity: { gen: c.gen, seq: c.seq, digests: [wDigest, cDigest] } }
    }
    const prior = priorState.states[priorState.states.length - 1]

    if (supersedes(cHead, wHead, prior.digest, prior.next)) {
      superseded += 1
      winner = challenger
      continue
    }
    if (supersedes(wHead, cHead, prior.digest, prior.next)) {
      superseded += 1
      continue
    }

    return { ok: false, duplicity: { gen: c.gen, seq: c.seq, digests: [wDigest, cDigest] } }
  }

  return { ok: true, winner, superseded }
}
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): superseding recovery and duplicity detection"
```

---

## Task 11: Criticality and capability-authorised revoke

**Files:**
- Modify: `packages/controller/src/fold.ts`
- Test: `packages/controller/test/criticality.test.ts`

**Interfaces:**
- Consumes: `foldLog` (Task 9), `checkDelegationChain` from `@kokuin/capability`.
- Produces: `foldLog` gains an options argument `{ verifyCapability?: (cap: string, did: string, target: string) => Promise<boolean> }` and becomes async as `foldLogAsync`; the sync `foldLog` keeps rejecting `cap`-bearing revokes.

Keeping a sync path matters: offline verifiers in kubun fold on the apply path and should not be forced async for logs with no capability-authorised events.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/criticality.test.ts
import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { foldLog, foldLogAsync } from '../src/fold.js'

const seed = new Uint8Array(32).fill(1)
const stolen = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

function unknownEvent(did: string, prior: ReturnType<typeof createInception>, crit: boolean) {
  return {
    event: {
      v: 1 as const,
      t: 'xyz' as never,
      i: did,
      g: 0,
      s: 1,
      p: (foldLog(did, [prior]) as { ok: true; states: Array<{ digest: string }> }).states[0]
        .digest,
      crit,
    },
    sigs: [],
  }
}

describe('criticality', () => {
  test('an unknown critical event fails the fold closed', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, true)])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/unknown critical event/)
  })

  test('an unknown non-critical event is skipped and the fold continues', () => {
    const { icp, did } = build()
    const result = foldLog(did, [icp, unknownEvent(did, icp, false)])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Skipped events do not advance state, so the position maps to the last applied state.
    expect(result.states).toHaveLength(2)
    expect(result.states[1].seq).toBe(0)
  })

  test('a revoke is critical, so a verifier that cannot read it never accepts the device', () => {
    const { icp, did } = build()
    const forged = {
      event: { ...unknownEvent(did, icp, true).event, t: 'rev' as never, x: stolen },
      sigs: [],
    }
    expect(foldLog(did, [icp, forged]).ok).toBe(false)
  })
})

describe('capability-authorised revoke', () => {
  test('the sync fold rejects a cap-bearing revoke rather than trusting it', () => {
    const { icp, did } = build()
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: (foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> }).states[0]
          .digest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = foldLog(did, [icp, withCap])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/capability/)
  })

  test('the async fold accepts one when the injected verifier approves', async () => {
    const { icp, did } = build()
    const priorDigest = (
      foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> }
    ).states[0].digest
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: priorDigest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = await foldLogAsync(did, [icp, withCap], {
      verifyCapability: async (cap, subject, target) => {
        expect(subject).toBe(did)
        expect(target).toBe(stolen)
        return cap === 'eyJ.fake.token'
      },
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(stolen)).toBe(true)
  })

  test('the async fold rejects one the verifier declines', async () => {
    const { icp, did } = build()
    const priorDigest = (
      foldLog(did, [icp]) as { ok: true; states: Array<{ digest: string }> }
    ).states[0].digest
    const withCap = {
      event: {
        v: 1 as const,
        t: 'rev' as const,
        i: did,
        g: 0,
        s: 1,
        p: priorDigest,
        crit: true,
        x: stolen,
        cap: 'eyJ.fake.token',
      },
      sigs: ['zzz'],
    }
    const result = await foldLogAsync(did, [icp, withCap], {
      verifyCapability: async () => false,
    })
    expect(result.ok).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- criticality`
Expected: FAIL — `foldLogAsync is not exported`, and the unknown-event cases fail because `foldLog` currently rejects every unknown type regardless of `crit`.

- [ ] **Step 3: Write the implementation**

In `packages/controller/src/fold.ts`, replace the final `return fail('unknown event type: ...')` with criticality handling, and extract the loop body so both a sync and an async entry point share it:

```ts
export type FoldOptions = {
  /**
   * Verify a capability authorising a non-authority signer to revoke. Injected rather than
   * imported so the fold stays free of a capability dependency on the sync path.
   *
   * Receives the serialized capability, the controller DID (which must be the capability `sub`),
   * and the DID being denied.
   */
  verifyCapability?: (cap: string, subject: string, target: string) => Promise<boolean>
}
```

Unknown-type branch:

```ts
    // Unknown type. Criticality lives in the envelope precisely so this decision can be made
    // without understanding `t`. Failing closed on a critical event is what stops a verifier
    // that does not understand `rev` from accepting a revoked device.
    if (event.crit) {
      return fail(`unknown critical event type: ${String(event.t)}`, i)
    }
    // Non-critical: skip, carrying state forward unchanged so positions stay aligned with the
    // input array.
    states.push({ ...prior, digest: prior.digest })
    continue
```

`rev` branch, sync path:

```ts
    if (event.t === 'rev') {
      const rev = signed as SignedEvent<RevokeEvent>
      if (rev.event.g !== prior.gen || rev.event.s !== prior.seq + 1) {
        return fail('sequence gap', i)
      }
      if (rev.event.cap != null) {
        if (verifyCapability == null) {
          return fail('capability-authorised revoke needs an async fold', i)
        }
        if (!(await verifyCapability(rev.event.cap, did, rev.event.x))) {
          return fail('capability does not authorise this revoke', i)
        }
      } else if (!verifyRevoke(rev, { digest: prior.digest, keys: prior.keys })) {
        return fail('invalid revoke', i)
      }
      // ... unchanged deny-set application ...
    }
```

**Do not** try to write one `foldInternal` that "only awaits when a `cap` is present" and have `foldLog` guard with `result instanceof Promise`. An `async function` always returns a promise, so that guard would throw on every log; making it work needs a thenable trampoline, which is worse than the duplication it avoids.

Instead, factor the per-event work into one **pure, synchronous** step function that both loops share. It returns a third outcome for the one case that cannot be decided synchronously:

```ts
type StepOutcome =
  | { status: 'ok'; state: KeyState }
  | { status: 'fail'; reason: string }
  /** A cap-bearing revoke: `state` is what to apply *if* the capability verifies. */
  | { status: 'capability'; cap: string; target: string; state: KeyState }

/**
 * Validate one event against the state so far and produce the next state. Pure and total —
 * every rejection is a returned reason, never a throw. Criticality is decided here, so both
 * fold entry points inherit it: an unknown critical event fails closed, an unknown
 * non-critical one is skipped by carrying the prior state forward unchanged.
 */
function stepEvent(
  did: string,
  inception: InceptionEvent,
  signed: SignedEvent,
  prior: KeyState,
): StepOutcome
```

`foldLog` walks the events, and on `status: 'capability'` fails with a reason naming the capability — an offline verifier must not trust one it cannot check. `foldLogAsync` walks the same steps and, on `status: 'capability'`, awaits `verifyCapability(cap, did, target)` and either pushes `state` or fails. Neither loop re-implements validation; the only difference is what they do with the third outcome.

Do **not** add `@kokuin/capability` to `packages/controller/package.json`. The verifier is injected, so this package imports nothing from it — adding it would be an unused dependency. If Task 13's conformance suite wants to build a real `verifyCapability`, it takes the dependency there.

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): criticality handling and capability-authorised revoke"
```

---

## Task 12: Profile enumeration and recovery handles

**Files:**
- Create: `packages/controller/src/profiles.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/profiles.test.ts`

**Interfaces:**
- Consumes: `createInception`, `didFromInception` (Task 5).
- Produces:
  - `enumerateProfiles(seed: Uint8Array, count: number): Array<{ index: number; did: string; handle: string }>`
  - `handleForDID(did: string): string`

The handle is a pronounceable syllable triple derived from the DID, so a cold picker works offline: which profiles were used, and what the user called them, are not seed-derived. Syllables rather than a wordlist — a fixed 256-word table would have to be frozen forever and shipped in every app, and generated syllables give the same recognisability with no data to keep in sync.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/profiles.test.ts
import { describe, expect, test } from 'vitest'

import { createInception, didFromInception } from '../src/events.js'
import { enumerateProfiles, handleForDID } from '../src/profiles.js'

const seed = new Uint8Array(32).fill(1)
const other = new Uint8Array(32).fill(2)

describe('enumerateProfiles()', () => {
  test('derives the requested number of profiles', () => {
    expect(enumerateProfiles(seed, 5)).toHaveLength(5)
  })

  test('indexes are contiguous from zero', () => {
    expect(enumerateProfiles(seed, 3).map((p) => p.index)).toEqual([0, 1, 2])
  })

  test('DIDs match the inception-derived identifiers', () => {
    const [first] = enumerateProfiles(seed, 1)
    expect(first.did).toBe(didFromInception(createInception(seed, 0).event))
  })

  test('is a pure function of the seed — the picker works offline', () => {
    expect(enumerateProfiles(seed, 3)).toEqual(enumerateProfiles(seed, 3))
  })

  test('different seeds produce different profiles', () => {
    expect(enumerateProfiles(seed, 1)[0].did).not.toBe(enumerateProfiles(other, 1)[0].did)
  })

  test('rejects a non-positive count', () => {
    expect(() => enumerateProfiles(seed, 0)).toThrow(/at least 1/)
  })
})

describe('handleForDID()', () => {
  test('is three hyphenated three-letter syllables', () => {
    expect(handleForDID(enumerateProfiles(seed, 1)[0].did)).toMatch(
      /^[a-z]{3}-[a-z]{3}-[a-z]{3}$/,
    )
  })

  test('every syllable is consonant-vowel-consonant, so it is pronounceable', () => {
    for (const { did } of enumerateProfiles(seed, 20)) {
      for (const syllable of handleForDID(did).split('-')) {
        expect(syllable[1]).toMatch(/[aeiou]/)
        expect(syllable[0]).not.toMatch(/[aeiou]/)
        expect(syllable[2]).not.toMatch(/[aeiou]/)
      }
    }
  })

  test('is stable for the same DID', () => {
    const { did } = enumerateProfiles(seed, 1)[0]
    expect(handleForDID(did)).toBe(handleForDID(did))
  })

  test('differs between profiles so a user can tell them apart', () => {
    const [a, b] = enumerateProfiles(seed, 2)
    expect(handleForDID(a.did)).not.toBe(handleForDID(b.did))
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- profiles`
Expected: FAIL — `Cannot find module '../src/profiles.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/profiles.ts
import { sha256 } from '@noble/hashes/sha2.js'

import { createInception, didFromInception } from './events.js'

export type ProfileEntry = {
  index: number
  did: string
  handle: string
}

const encoder = new TextEncoder()

// Frozen forever: a handle a user wrote down must keep resolving to the same profile. Letters
// that are easily confused when read aloud or handwritten are left out — no c/k or q, no i/l.
const CONSONANTS = 'bdfghjkmnprstvwz'
const VOWELS = 'aeou'

/**
 * A three-syllable handle derived from the DID itself. No stored data and no wordlist to keep in
 * sync across apps — which is what lets a cold picker label profiles with no network and no cache.
 *
 * Each syllable is consonant-vowel-consonant, so the handle is pronounceable and can be read out
 * or written down. 16 x 4 x 16 per syllable gives 1024 combinations, about 30 bits across three —
 * ample to tell a handful of profiles apart, and not a security boundary.
 *
 * A user label must never feed the DID, so this is the inverse: the label is a function of the
 * identifier, not the other way round.
 */
export function handleForDID(did: string): string {
  const digest = sha256(encoder.encode(did))
  const syllables: string[] = []
  for (let i = 0; i < 3; i++) {
    syllables.push(
      CONSONANTS[digest[i * 3] % CONSONANTS.length] +
        VOWELS[digest[i * 3 + 1] % VOWELS.length] +
        CONSONANTS[digest[i * 3 + 2] % CONSONANTS.length],
    )
  }
  return syllables.join('-')
}

/**
 * Enumerate the first `count` profiles for a seed.
 *
 * Every index yields a valid-looking DID whether or not the profile was ever used — which
 * profiles were used is not seed-derived. A picker should present all of them and let a probe
 * grey out the unused ones when a group, hub, or cache is reachable.
 */
export function enumerateProfiles(seed: Uint8Array, count: number): ProfileEntry[] {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error('enumerateProfiles: count must be at least 1')
  }
  const entries: ProfileEntry[] = []
  for (let index = 0; index < count; index++) {
    const did = didFromInception(createInception(seed, index).event)
    entries.push({ index, did, handle: handleForDID(did) })
  }
  return entries
}
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): offline profile enumeration and recovery handles"
```

---

## Task 13: `@kokuin/controller-conformance`

**Files:**
- Create: `packages/controller-conformance/package.json`
- Create: `packages/controller-conformance/tsconfig.json`
- Create: `packages/controller-conformance/tsconfig.test.json`
- Create: `packages/controller-conformance/src/index.ts`
- Modify: `pnpm-workspace.yaml` (`versioning.ignore`)
- Modify: `packages/controller/package.json` (devDependency)
- Test: `packages/controller/test/conformance.test.ts`

**Interfaces:**
- Consumes: the full `@kokuin/controller` surface.
- Produces: `runControllerConformance(suite: { describe; expect; test }, impl: ControllerImplementation): void`, mirroring how `@kokuin/keystore-conformance` is consumed from `packages/deterministic/test/conformance.test.ts`.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/conformance.test.ts
import { describe, expect, test } from 'vitest'

import { runControllerConformance } from '@kokuin/controller-conformance'

import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { enumerateProfiles } from '../src/profiles.js'
import { resolveBranches } from '../src/supersede.js'

runControllerConformance(
  { describe, expect, test },
  {
    name: '@kokuin/controller',
    createInception,
    createRotate,
    createReset,
    createRevoke,
    didFromInception,
    foldLog,
    resolveBranches,
    enumerateProfiles,
  },
)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- conformance`
Expected: FAIL — `Cannot find package '@kokuin/controller-conformance'`.

- [ ] **Step 3: Create the conformance package**

`packages/controller-conformance/package.json` — mirror `packages/keystore-conformance/package.json` exactly, which is `"private": true`, has no `publishConfig`, and **builds to `lib/`** like every other package here:

```json
{
  "name": "@kokuin/controller-conformance",
  "version": "0.0.0",
  "private": true,
  "description": "Contract suite for did:kokuin controller implementations",
  "license": "MIT",
  "sideEffects": false,
  "type": "module",
  "exports": { ".": "./lib/index.js" },
  "main": "lib/index.js",
  "types": "lib/index.d.ts",
  "files": ["lib/*"],
  "scripts": {
    "build": "pnpm run build:clean && pnpm run build:js && pnpm run build:types",
    "build:clean": "del lib",
    "build:js": "swc src -d ./lib --config-file ../../node_modules/@kigu/dev/swc.json --strip-leading-paths",
    "build:types": "tsc --emitDeclarationOnly --skipLibCheck",
    "test:types": "tsc --noEmit --skipLibCheck -p tsconfig.test.json"
  }
}
```

No dependency on `@kokuin/controller`: the implementation is **injected**, and depending on it would make a cycle with the devDependency `@kokuin/controller` takes on this package. The suite's types describe the contract structurally; it imports nothing from the package under test. This mirrors `@kokuin/keystore-conformance`, which depends on `@kokuin/token` for shared types and never on `@kokuin/deterministic`.

Copy `tsconfig.json` and `tsconfig.test.json` from `packages/keystore-conformance`. No per-package `biome.json` — the root one covers every package.

Add to `pnpm-workspace.yaml` under `versioning.ignore`, keeping the list alphabetical:

```yaml
  ignore:
    - '@kokuin/controller-conformance'
    - '@kokuin/keystore-conformance'
    - '@kokuin/ledger-tests'
    - e2e-electron
    - e2e-expo
    - e2e-node
    - e2e-web
```

Omitting this makes `pnpm change status` and `pnpm version -r` crash as soon as a bump has to propagate into it — globs are not supported, so the exact name is required.

`packages/controller-conformance/src/index.ts` asserts the contract every implementation owes. It must cover, at minimum:

```ts
export type ControllerImplementation = {
  name: string
  createInception: (seed: Uint8Array, profile: number) => unknown
  createRotate: (...args: never[]) => unknown
  createReset: (...args: never[]) => unknown
  createRevoke: (...args: never[]) => unknown
  didFromInception: (event: never) => string
  foldLog: (did: string, events: never[]) => unknown
  resolveBranches: (did: string, branches: never[][]) => unknown
  enumerateProfiles: (seed: Uint8Array, count: number) => unknown
}

export type ConformanceSuite = {
  describe: (name: string, fn: () => void) => void
  test: (name: string, fn: () => void | Promise<void>) => void
  expect: (value: unknown) => any
}

/**
 * The contract every did:kokuin controller implementation owes, framework-agnostic so it can run
 * under any runner. Mirrors the `@kokuin/keystore-conformance` habit.
 */
export function runControllerConformance(
  suite: ConformanceSuite,
  impl: ControllerImplementation,
): void {
  // Groups, each asserting a property from the spec:
  //  1. Determinism — same seed + index reproduces identical inception bytes and the same DID.
  //  2. No ambient state — inception carries no timestamp, nonce, or label.
  //  3. Pre-rotation — a rotate not signed by the pre-committed keys is rejected.
  //  4. Root override — a reset signed by anything but the recovery key is rejected.
  //  5. Position-dependence — a device denied at seq N is not denied at seq N-1.
  //  6. Reset clears the deny set and increments the generation.
  //  7. Precedence — higher (gen, seq) wins; a superseding rotate beats a current-key event.
  //  8. Idempotence — identical re-derived branches are not duplicity.
  //  9. Duplicity — two distinct current-key events at one position are surfaced, not merged.
  // 10. Criticality — an unknown critical event fails closed; a non-critical one is skipped.
  // 11. Enumeration — profiles are pure functions of the seed and handles are stable.
}
```

Write each group as real assertions using `impl`, following the tests already written in Tasks 5-12 — those tests are the source material, restated against the injected implementation rather than against direct imports.

Add `"@kokuin/controller-conformance": "workspace:^"` to `packages/controller/package.json` `devDependencies`.

- [ ] **Step 4: Run the tests**

Run: `pnpm install && pnpm --filter @kokuin/controller test`
Expected: PASS. Then run `pnpm change status` and confirm it does not crash.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller-conformance packages/controller pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "feat(controller-conformance): contract suite for did:kokuin implementations"
```

---

## Task 14: Wire the controller into token's resolver

**Files:**
- Create: `packages/controller/src/resolver.ts`
- Modify: `packages/controller/src/index.ts`
- Test: `packages/controller/test/resolver.test.ts`

**Interfaces:**
- Consumes: `DIDMethodResolver` (Task 4), `foldLog` / `keyStateAt` (Task 9), `decodeKey` (Task 5).
- Produces: `createControllerResolver(options: { loadLog(did: string): Promise<SignedEvent[] | undefined> }): DIDMethodResolver`.

This is the payoff of Task 4: `@kokuin/controller` depends on `@kokuin/token`, and injection is what keeps the dependency one-way.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/resolver.test.ts
import { verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createInception, decodeKey, didFromInception } from '../src/events.js'
import { createControllerResolver } from '../src/resolver.js'

const seed = new Uint8Array(32).fill(1)

function build() {
  const icp = createInception(seed, 0)
  return { icp, did: didFromInception(icp.event) }
}

describe('createControllerResolver()', () => {
  test('registers for the kokuin method', () => {
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    expect(resolver.method).toBe('kokuin')
  })

  test('resolves the current signing key from the folded log', async () => {
    const { icp, did } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.alg).toBe('EdDSA')
    expect(resolved.publicKey).toEqual(decodeKey(icp.event.k[0]))
  })

  test('rejects a DID with no log rather than returning a guess', async () => {
    const { did } = build()
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    await expect(resolver.resolve(did, {})).rejects.toThrow(/Unknown DID/)
  })

  test('rejects a log that does not fold to the requested DID', async () => {
    const { icp } = build()
    const resolver = createControllerResolver({ loadLog: async () => [icp] })
    await expect(resolver.resolve('did:kokuin:zWRONG', {})).rejects.toThrow()
  })

  test('resolves the rotated key after a rotation, not the original', async () => {
    const { icp, did } = build()
    const { createRotate } = await import('../src/events.js')
    const rot = createRotate(seed, 0, did, icp.event)
    const resolver = createControllerResolver({ loadLog: async () => [icp, rot] })
    const resolved = await resolver.resolve(did, {})
    expect(resolved.publicKey).toEqual(decodeKey(rot.event.k[0]))
    expect(resolved.publicKey).not.toEqual(decodeKey(icp.event.k[0]))
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- resolver`
Expected: FAIL — `Cannot find module '../src/resolver.js'`.

- [ ] **Step 3: Write the implementation**

```ts
// packages/controller/src/resolver.ts
import type { DIDMethodResolver, ResolvedSigningKey } from '@kokuin/token'

import { decodeKey, DID_PREFIX, type SignedEvent } from './events.js'
import { foldLog } from './fold.js'

export type ControllerResolverOptions = {
  /** Load a controller's event log. Returns undefined when the DID is unknown. */
  loadLog(did: string): Promise<SignedEvent[] | undefined>
}

/**
 * A `did:kokuin:` resolver for `@kokuin/token`.
 *
 * Injected rather than imported by token: this package depends on token for signing, so the
 * reverse import would be a cycle. Token resolves `iss` through the interface without knowing
 * the fold exists.
 */
export function createControllerResolver(
  options: ControllerResolverOptions,
): DIDMethodResolver {
  return {
    method: 'kokuin',
    async resolve(did: string): Promise<ResolvedSigningKey> {
      if (!did.startsWith(DID_PREFIX)) {
        throw new Error(`Unknown DID: ${did}`)
      }
      const events = await options.loadLog(did)
      if (events == null || events.length === 0) {
        throw new Error(`Unknown DID: ${did}`)
      }
      const result = foldLog(did, events)
      if (!result.ok) {
        throw new Error(`Invalid controller log for ${did}: ${result.reason}`)
      }
      const state = result.states[result.states.length - 1]
      if (state.keys.length === 0) {
        throw new Error(`Controller ${did} has no signing key`)
      }
      return { alg: 'EdDSA', publicKey: decodeKey(state.keys[0]) }
    },
  }
}
```

Export from `index.ts`.

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/controller test && pnpm --filter @kokuin/token test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller
git commit -m "feat(controller): did:kokuin resolver for token iss resolution"
```

---

## Task 15: Capability depth cap and mandated expiry

**Files:**
- Modify: `packages/capability/src/index.ts:30` (`DEFAULT_MAX_DELEGATION_DEPTH`)
- Modify: `packages/capability/src/index.ts` (add `assertDeviceCapabilityPolicy`)
- Test: `packages/capability/test/policy.test.ts`

**Interfaces:**
- Consumes: `CapabilityPayload`, `assertNonExpired` from `@kokuin/capability`.
- Produces: `DEFAULT_MAX_DELEGATION_DEPTH = 4`, `assertDeviceCapabilityPolicy(payload: { exp?: number }, options?: { maxLifetimeSeconds?: number; now?: number }): void`, `DEFAULT_MAX_DEVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60`.

- [ ] **Step 1: Write the failing test**

```ts
// packages/capability/test/policy.test.ts
import { describe, expect, test } from 'vitest'

import {
  assertDeviceCapabilityPolicy,
  DEFAULT_MAX_DELEGATION_DEPTH,
  DEFAULT_MAX_DEVICE_LIFETIME_SECONDS,
} from '../src/index.js'

describe('DEFAULT_MAX_DELEGATION_DEPTH', () => {
  test('is 4 — management, device, connector, plus headroom', () => {
    expect(DEFAULT_MAX_DELEGATION_DEPTH).toBe(4)
  })
})

describe('assertDeviceCapabilityPolicy()', () => {
  const now = 1_800_000_000

  test('rejects a capability with no exp — the schema enforces it only when present', () => {
    expect(() => assertDeviceCapabilityPolicy({}, { now })).toThrow(/must set exp/)
  })

  test('accepts an expiry inside the accepted-loss window', () => {
    expect(() =>
      assertDeviceCapabilityPolicy({ exp: now + 60 * 60 * 24 }, { now }),
    ).not.toThrow()
  })

  test('rejects an expiry beyond the default window', () => {
    expect(() =>
      assertDeviceCapabilityPolicy({ exp: now + 60 * 60 * 24 * 30 }, { now }),
    ).toThrow(/lifetime/)
  })

  test('rejects an already-expired capability', () => {
    expect(() => assertDeviceCapabilityPolicy({ exp: now - 1 }, { now })).toThrow()
  })

  test('honours a caller-supplied window', () => {
    expect(() =>
      assertDeviceCapabilityPolicy(
        { exp: now + 60 * 60 * 24 * 30 },
        { now, maxLifetimeSeconds: 60 * 60 * 24 * 60 },
      ),
    ).not.toThrow()
  })

  test('the default window is seven days', () => {
    expect(DEFAULT_MAX_DEVICE_LIFETIME_SECONDS).toBe(7 * 24 * 60 * 60)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/capability test:unit -- policy`
Expected: FAIL — `assertDeviceCapabilityPolicy is not exported`, and the depth assertion fails at 20.

- [ ] **Step 3: Write the implementation**

In `packages/capability/src/index.ts`, change line 30 and add the policy helper:

```ts
/**
 * Maximum delegation links an offline verifier will walk.
 *
 * Four: management → device → connector is three, plus one of headroom. Lowered from 20 —
 * lowering the default can only reject chains, never accept new ones, and `maxDepth` stays
 * overridable per call for anything that legitimately needs more.
 */
export const DEFAULT_MAX_DELEGATION_DEPTH = 4

/**
 * Default ceiling on a device capability's lifetime.
 *
 * The expiry length *is* the accepted-loss window at an offline verifier: revocation reaches it
 * best-effort, an unrenewed expiry is unconditional. On-log revocation narrows the window but
 * does not remove it, so pick this by how many days of a thief writing as the victim is
 * acceptable — not by renewal convenience.
 */
export const DEFAULT_MAX_DEVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60

export type DeviceCapabilityPolicyOptions = {
  maxLifetimeSeconds?: number
  now?: number
}

/**
 * Enforce that a device capability sets a bounded expiry.
 *
 * `exp` is optional in the capability schema and `assertNonExpired` only enforces it when
 * present, so the schema will never require it. Mint and verify paths for device capabilities
 * must call this.
 */
export function assertDeviceCapabilityPolicy(
  payload: { exp?: number },
  options: DeviceCapabilityPolicyOptions = {},
): void {
  const atTime = options.now ?? now()
  const maxLifetime = options.maxLifetimeSeconds ?? DEFAULT_MAX_DEVICE_LIFETIME_SECONDS
  if (payload.exp == null) {
    throw new Error('CapabilityError.PolicyViolation: device capabilities must set exp')
  }
  assertNonExpired(payload, atTime)
  if (payload.exp - atTime > maxLifetime) {
    throw new Error(
      `CapabilityError.PolicyViolation: device capability lifetime exceeds ${maxLifetime}s`,
    )
  }
}
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/capability test && pnpm test`
Expected: PASS. If any existing test asserted a chain deeper than 4, update it to pass `maxDepth` explicitly — that is the intended migration.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/capability
git commit -m "feat(capability): cap delegation depth at 4 and mandate device expiry"
```

---

## Task 16: Split `@kokuin/jwe` out of `@kokuin/token`

**Files:**
- Create: `packages/jwe/package.json`, `tsconfig.json`, `tsconfig.test.json`, `biome.json`
- Move: `packages/token/src/jwe.ts` → `packages/jwe/src/index.ts`
- Move: `packages/token/test/jwe.test.ts` → `packages/jwe/test/jwe.test.ts`
- Modify: `packages/token/src/index.ts` (drop the JWE re-exports)
- Modify: `packages/token/package.json` (drop `@noble/ciphers`)

**Interfaces:**
- Consumes: `@kokuin/token` for `DIDDoc`, `getAgreementKey`, `concatBytes`.
- Produces: `@kokuin/jwe` exporting everything `token/src/jwe.ts` exported today — `concatKDF`, `createTokenEncrypter`, `decryptToken`, `deriveSharedSecret`, `encryptToken`, `unwrapEnvelope`, `wrapEnvelope`, and the types `ConcatKDFParams`, `EncryptOptions`, `EnvelopeMode`, `JWEHeader`, `SharedSecretResult`, `TokenEncrypter`, `UnwrapOptions`, `UnwrappedEnvelope`, `WrapOptions`.

This is a breaking change to `@kokuin/token`'s public API. It rides the same major as the `iss` resolution change rather than being released separately.

- [ ] **Step 1: Move the tests first and watch them fail**

```bash
mkdir -p packages/jwe/src packages/jwe/test
git mv packages/token/test/jwe.test.ts packages/jwe/test/jwe.test.ts
```

Change the import in `packages/jwe/test/jwe.test.ts` from `../src/jwe.js` to `../src/index.js`.

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/jwe test:unit`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Create the package and move the source**

`packages/jwe/package.json` — same shape as Task 1's, with:

```json
{
  "name": "@kokuin/jwe",
  "version": "0.1.0",
  "description": "JWE encryption for kokuin tokens",
  "dependencies": {
    "@kokuin/token": "workspace:^",
    "@noble/ciphers": "catalog:",
    "@noble/curves": "catalog:",
    "@noble/hashes": "catalog:"
  }
}
```

Copy `tsconfig.json`, `tsconfig.test.json` and `biome.json` from `packages/controller`.

```bash
git mv packages/token/src/jwe.ts packages/jwe/src/index.ts
```

Rewrite the relative imports at the top of `packages/jwe/src/index.ts` to import from `@kokuin/token` instead of `./did.js`, `./peer4.js`, `./utils.js` and friends. Remove the JWE export block from `packages/token/src/index.ts`, and remove `@noble/ciphers` from `packages/token/package.json`.

- [ ] **Step 4: Run the full test suite**

Run: `pnpm install && pnpm test`
Expected: PASS. Any package that imported JWE symbols from `@kokuin/token` now needs `@kokuin/jwe` — add the dependency and update the import there. Grep first: `grep -rn "encryptToken\|decryptToken\|wrapEnvelope\|unwrapEnvelope\|createTokenEncrypter\|deriveSharedSecret\|concatKDF" packages tests --include=*.ts`.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages ./tests
git add packages/jwe packages/token pnpm-lock.yaml
git commit -m "refactor(token)!: split JWE into @kokuin/jwe"
```

---

## Task 17: Remove `createRotationAssertion`

**Files:**
- Delete: `packages/token/src/rotation.ts`
- Delete: `packages/token/test/rotation.test.ts`
- Modify: `packages/token/src/index.ts` (drop the `createRotationAssertion` / `RotationPayload` exports, around lines 93-94)
- Test: `packages/token/test/exports.test.ts` (drop `'createRotationAssertion'` from the expected-names list, around line 20)

**Interfaces:**
- Consumes: nothing new.
- Produces: `@kokuin/token` no longer exports `createRotationAssertion` or `RotationPayload`.

Rotation chains are exactly what this design replaces: `createRotationAssertion` links two **different** DIDs, which forces a data migration on every rotation, while `did:kokuin:` keeps the identifier stable and rotates the key set beneath it. It has no consumer anywhere in the workspace, and Task 16 already makes this release a breaking `@kokuin/token` major — so it goes now rather than living one more cycle behind a `@deprecated` tag.

- [ ] **Step 1: Confirm there is no consumer, then make the exports test fail**

```bash
grep -rn "createRotationAssertion\|RotationPayload" --include="*.ts" packages tests | grep -v "/lib/"
```

Expected: matches only in `packages/token/src/rotation.ts`, `packages/token/src/index.ts`, `packages/token/test/rotation.test.ts` and `packages/token/test/exports.test.ts`. **If anything else matches, stop and report it** — the removal is only safe because nothing depends on it.

Then drop the name from the expected public surface in `packages/token/test/exports.test.ts`:

```ts
    // 'createRotationAssertion' removed — see @kokuin/controller for did:kokuin controller logs.
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @kokuin/token test:unit -- exports`
Expected: FAIL — the barrel still exports `createRotationAssertion`, and `exports.test.ts` asserts the surface is exactly the listed names.

If `exports.test.ts` only checks that each listed name is *present* and never checks for extras, the deletion is not observable from that test alone. In that case add the negative assertion, which is what makes this task testable:

```ts
  test('no longer exports the superseded rotation-chain helper', () => {
    expect(token).not.toHaveProperty('createRotationAssertion')
  })
```

- [ ] **Step 3: Delete the module**

```bash
git rm packages/token/src/rotation.ts packages/token/test/rotation.test.ts
```

Remove the export block from `packages/token/src/index.ts`:

```ts
export {
  createRotationAssertion,
  type RotationPayload,
} from './rotation.js'
```

- [ ] **Step 4: Run the tests**

Run: `pnpm --filter @kokuin/token test && pnpm test`
Expected: PASS across the workspace. Any remaining reference is a real consumer the Step 1 grep missed — report it rather than patching around it.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/token
git commit -m "refactor(token)!: remove createRotationAssertion in favour of controller logs"
```

---

## Task 18: Package documentation and release metadata

**Files:**
- Modify: `packages/controller/src/index.ts` (module doc)
- Modify: `AGENTS.md`
- Test: `packages/controller/test/exports.test.ts`

**Interfaces:**
- Consumes: the whole public surface.
- Produces: a documented barrel and an accurate repo description.

- [ ] **Step 1: Write the failing test**

```ts
// packages/controller/test/exports.test.ts
import { describe, expect, test } from 'vitest'

import * as controller from '../src/index.js'

describe('public surface', () => {
  test('exports everything downstream repos need', () => {
    for (const name of [
      'VERSION_TAG',
      'canonicalBytes',
      'digestOf',
      'verifyDigest',
      'authorityPath',
      'agreementPath',
      'recoveryPath',
      'deriveKeyMaterial',
      'deriveKeyPair',
      'createInception',
      'createRotate',
      'createReset',
      'createRevoke',
      'didFromInception',
      'encodeKey',
      'decodeKey',
      'foldLog',
      'foldLogAsync',
      'keyStateAt',
      'resolveBranches',
      'enumerateProfiles',
      'handleForDID',
      'createControllerResolver',
    ]) {
      expect(controller).toHaveProperty(name)
    }
  })

  test('does not leak internal helpers', () => {
    expect(controller).not.toHaveProperty('signEvent')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/controller test:unit -- exports`
Expected: FAIL on whichever names are not yet re-exported.

- [ ] **Step 3: Complete the barrel and update `AGENTS.md`**

Finish `packages/controller/src/index.ts` with the module doc comment and every export above.

In `AGENTS.md`, update the "What this repo is" paragraph so the package list is accurate:

```markdown
Identity primitives: JWT-style tokens, JWE encryption, capabilities, `did:kokuin:` controller key
event logs, and keystores per runtime (browser, node, electron, expo, deterministic HD,
ledger-device). Three supporting packages: `@kokuin/otel` (tracer factory and span/attribute
names), `@kokuin/keystore-conformance` and `@kokuin/controller-conformance` (both private — the
framework-agnostic suites that enforce the `KeyStore` / `KeyEntry` and controller contracts).
```

- [ ] **Step 4: Run the full suite**

Run: `pnpm test && pnpm change status`
Expected: PASS, and `pnpm change status` does not crash.

- [ ] **Step 5: Commit**

```bash
pnpm exec biome check --write ./packages
git add packages/controller AGENTS.md
git commit -m "docs(controller): document the public surface and update the repo map"
```

---

## Self-review notes

**Spec coverage.** Every spec section maps to a task: identifier and no-version-segment (5), derivation with HKDF and the root-retained branch (3), the three event types (5, 6, 8) with reset as a rotate variant (7), criticality (11), fold precedence and superseding recovery (9, 10), deny-set position-dependence (9, 10), key state at position (9), duplicity (10), enumeration and handles (12), the conformance suite (13), the injected resolver (4, 14), the depth cap and mandated `exp` (15), the JWE split (16), the `rotation.ts` removal (17), packaging and `versioning.ignore` (1, 13, 18).

**Deliberately not covered**, matching the spec's *Out of scope*: kumiai binding entries and roster projection, kubun's cut-off position, ML-DSA in `SUPPORTED_ALGORITHMS`, DIF registration, adopted profiles. The co-signature-gated recovery-commitment field exists in the `RotateEvent` type (Task 6, field `r`) and the fold carries it forward (Task 9), but no task implements *updating* it — that is the retained-but-unimplemented hook the spec describes. **The co-signature check is therefore not implemented**: any task that starts using `r` on a rotate must add it first.

**Known gaps to resolve during execution.**

- Task 13 sketches the conformance suite's eleven groups as comments rather than full assertions. The material is the tests from Tasks 5-12, restated against the injected implementation — the only task in this plan that asks the implementer to write assertions the plan does not spell out.
- Task 11's `foldInternal` must return synchronously when no `cap` is present. If that proves awkward, the fallback is two separate implementations sharing a `validateTransition` helper — but do not silently make `foldLog` async, since kubun's apply path depends on it being sync.
