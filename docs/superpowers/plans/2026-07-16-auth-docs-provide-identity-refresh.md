# Auth Docs Store-Method Identity API Refresh — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Stage:** executing
**Mode:** tasks
**Spec:** `docs/superpowers/specs/2026-07-16-auth-docs-provide-identity-refresh-design.md`
**Branch:** `docs/provide-identity-refresh` (already created)

**Goal:** Correct three docs that publish the pre-PR#9 identity API — removed free `provide*` functions, a browser section describing a signing-only ES256 store that now does full decryption, and a stale `KeyEntry` contract.

**Architecture:** A throwaway snippet-typecheck harness is built first and must go red against the current docs. Each doc section is then fixed to the canonical shape pinned in the spec, re-running the harness until green. The harness extracts fenced blocks from the real docs rather than copying them, so it cannot drift from what it gates. It is never committed and is deleted in the final task.

**Tech Stack:** TypeScript 6 (`tsc --noEmit`), pnpm workspace, markdown docs.

## Global Constraints

- Canonical form for node/electron/expo/deterministic/browser: `await store.provideIdentity(keyID)` → `FullIdentity`. Ledger: `await provider.provideIdentity(keyID)` → `FullIdentity`.
- Sync twin `store.provideIdentitySync(keyID)` exists on node, electron, expo only. Deterministic and ledger are async-only.
- Browser only: `await store.provideSigningIdentity(keyID)` → `SigningIdentity`, accepts both suites.
- No free `provide*` name may appear in any `import` in any of the three docs — no package exports one.
- Do NOT `git add -A` / `git add .` — the untracked `.docs-snippets/` harness must never be committed. Always `git add` the explicit doc paths listed in each task.
- Do not edit generated files (`lib/`). Do not touch `docs/reference/capability.md` — verified already correct.
- Prose style: match the surrounding docs. `type` not `interface`; `Array<T>` not `T[]`; capital `ID`/`HTTP`/`JWT`.
- No changeset — `docs/` is not a published package and no package source changes.

## Verified Source of Truth

Every claim below was confirmed against source during planning. Do not re-litigate; do not "fix" these to match the old docs.

| Fact | Source |
|---|---|
| `NodeKeyStore.provideIdentity` / `provideIdentitySync` | `packages/node/src/store.ts:94,120` |
| `provideIdentitySync` throws when store opened with `lockPath` | `packages/node/src/store.ts:114-118` |
| `ElectronKeyStore.provideIdentity` / `provideIdentitySync` | `packages/electron/src/store.ts:111,132` |
| `ExpoKeyStore.open()` is the static; `entry()` is an instance method | `packages/expo/src/store.ts:23,41` |
| `ExpoKeyStore.provideIdentity` / `provideIdentitySync` | `packages/expo/src/store.ts:46,67` |
| `HDKeyStore.provideIdentity` exists (async-only) | `packages/deterministic/src/store.ts:50` |
| `BrowserKeyStore.provideIdentity` → `FullIdentity`, throws on legacy ES256 record | `packages/browser/src/store.ts:79` |
| `BrowserKeyStore.provideSigningIdentity` → `SigningIdentity`, both suites | `packages/browser/src/store.ts:109` |
| Browser store type is `KeyStore<StoredKeyRecord, BrowserKeyEntry>` | `packages/browser/src/store.ts:28` |
| Ledger `provideIdentity` → `FullIdentity` | `packages/ledger-device/src/provider.ts:82` |
| `KeyEntry` = `{keyID, getAsync, provideAsync}`; `MutableKeyEntry` adds `setAsync`/`removeAsync` | `packages/token/src/keystore.ts:21,46` |
| `MutableKeyEntry` is exported | `packages/token/src/index.ts:73` |
| `StoredKeyRecord` is exported | `packages/browser/src/index.ts:21` |
| Electron entry is `MutableKeyEntry<Uint8Array>` (not `string`) | `packages/electron/src/entry.ts:26` |
| `listAsync`, `setAsync`, `removeAsync`, `HDKeyStore.fromMnemonic`, HD `entry().provideAsync()` all still exist and typecheck | verified during planning |

---

### Task 1: Snippet typecheck harness (red gate)

Builds the throwaway harness and records the failing baseline. Nothing is committed — the harness is a tool, not a deliverable.

**Files:**
- Create: `.docs-snippets/tsconfig.json` (untracked, deleted in Task 8)
- Create: `.docs-snippets/extract.mjs` (untracked, deleted in Task 8)

**Interfaces:**
- Produces: the command `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`, used as the gate by Tasks 2–6 and 8.

- [ ] **Step 1: Create the harness tsconfig**

Path mappings point straight at each package's built `lib/index.d.ts`. This is deliberate: there is no root `node_modules/@kokuin` symlink (pnpm links workspace packages only into each consumer package's own `node_modules`), so bare `@kokuin/*` specifiers do not resolve from a root-level directory. Do not "simplify" this to `["../packages/*"]` — it fails with TS2307.

```json
{
  "extends": "../node_modules/@kigu/dev/tsconfig.json",
  "compilerOptions": {
    "noEmit": true,
    "lib": ["es2025", "dom"],
    "types": ["node"],
    "paths": {
      "@kokuin/token": ["../packages/token/lib/index.d.ts"],
      "@kokuin/node": ["../packages/node/lib/index.d.ts"],
      "@kokuin/browser": ["../packages/browser/lib/index.d.ts"],
      "@kokuin/electron": ["../packages/electron/lib/index.d.ts"],
      "@kokuin/expo": ["../packages/expo/lib/index.d.ts"],
      "@kokuin/deterministic": ["../packages/deterministic/lib/index.d.ts"],
      "@kokuin/ledger-device": ["../packages/ledger-device/lib/index.d.ts"]
    }
  },
  "include": ["./*.ts"]
}
```

- [ ] **Step 2: Create the extractor**

Skips fenced blocks containing a line starting with `type ` — those are illustrative type declarations (the `Identity` hierarchy, `SignedPayload`, the `KeyEntry`/`KeyStore` contract, `IdentityProvider`) that redeclare imported names and are not runnable examples. Every real example imports and calls; none has a top-level `type ` line.

```javascript
import { readFileSync, writeFileSync, readdirSync, unlinkSync } from 'node:fs'

const DOCS = [
  'docs/reference/auth.md',
  'docs/skills/auth.skill.md',
  'docs/skills/discover.skill.md',
]
const PREAMBLE = `declare const masterSeed: Uint8Array
declare const transport: any
export {}
`
for (const f of readdirSync('.docs-snippets')) {
  if (f.endsWith('.ts')) unlinkSync(`.docs-snippets/${f}`)
}
let kept = 0
let skipped = 0
for (const doc of DOCS) {
  const src = readFileSync(doc, 'utf8')
  const blocks = [...src.matchAll(/```typescript\n([\s\S]*?)```/g)].map((m) => m[1])
  blocks.forEach((code, i) => {
    if (/^type /m.test(code)) { skipped++; return }
    const slug = doc.replace(/[^a-z0-9]+/gi, '-')
    writeFileSync(`.docs-snippets/${slug}-${i}.ts`, PREAMBLE + code)
    kept++
  })
}
console.log(`kept=${kept} skipped=${skipped}`)
```

- [ ] **Step 3: Ensure the packages are built**

The harness reads `lib/*.d.ts`. If they are stale or absent, run:

Run: `pnpm run build:types`
Expected: every package prints `Done`.

- [ ] **Step 4: Run the harness and confirm it goes RED**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`

Expected: `kept=23 skipped=4`, then exactly these 10 errors:

```
docs-reference-auth-md-11.ts: Module '"@kokuin/node"' has no exported member 'provideFullIdentityAsync'.
docs-reference-auth-md-12.ts: Module '"@kokuin/browser"' has no exported member 'provideSigningIdentity'.
docs-reference-auth-md-13.ts: Module '"@kokuin/expo"' has no exported member 'provideFullIdentityAsync'.
docs-reference-auth-md-13.ts: Property 'entry' does not exist on type 'typeof ExpoKeyStore'.
docs-reference-auth-md-14.ts: Module '"@kokuin/electron"' has no exported member 'provideFullIdentityAsync'.
docs-skills-auth-skill-md-1.ts: Module '"@kokuin/node"' has no exported member 'provideFullIdentityAsync'.
docs-skills-auth-skill-md-2.ts: Module '"@kokuin/browser"' has no exported member 'provideSigningIdentity'.
docs-skills-auth-skill-md-3.ts: Module '"@kokuin/expo"' has no exported member 'provideFullIdentityAsync'.
docs-skills-auth-skill-md-3.ts: Property 'entry' does not exist on type 'typeof ExpoKeyStore'.
docs-skills-auth-skill-md-4.ts: Module '"@kokuin/electron"' has no exported member 'provideFullIdentityAsync'.
```

If the harness is green here, it is not wired up correctly — stop and fix it before touching any doc.

- [ ] **Step 5: No commit**

The harness is untracked and stays that way. Confirm no doc changed yet:

Run: `git status --short`
Expected: only `?? .docs-snippets/`.

---

### Task 2: `auth.md` — node, electron, expo, deterministic, ledger examples

**Files:**
- Modify: `docs/reference/auth.md` (the `@kokuin/node`, `@kokuin/electron`, `@kokuin/expo`, `@kokuin/deterministic`, `@kokuin/ledger-device` keystore sections)

**Interfaces:**
- Consumes: harness command from Task 1.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Replace the `@kokuin/node` example**

Replace the existing block with:

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

Immediately after the block, add:

```markdown
> `provideIdentitySync` is beyond the `IdentityProvider` contract and is **not** cross-process
> safe: a file lock cannot be acquired synchronously, so it throws when the store was opened
> with a `lockPath`.
```

- [ ] **Step 2: Replace the `@kokuin/electron` example**

Replace the existing block with:

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

- [ ] **Step 3: Replace the `@kokuin/expo` example**

`ExpoKeyStore.open()` returns the process-wide store; `entry()` is an instance method. The old `ExpoKeyStore.entry(...)` was a TypeError.

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

- [ ] **Step 4: Replace the `@kokuin/deterministic` example and its false claim**

Delete the sentence **"There is no `provide*` helper.** Build identities manually with `createFullIdentity` from `@kokuin/token`." — `HDKeyStore.provideIdentity` exists, and the claim contradicts this same file's contract section. Replace with:

```markdown
`HDKeyStore` implements `IdentityProvider<FullIdentity>` — call `store.provideIdentity(keyID)`.
Derivation is async-only; there is no sync twin. `derivePrivateKey` remains available for
standalone derivation without a store.
```

Replace the example block with:

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

- [ ] **Step 5: Fix the ledger return type**

The section prose at `docs/reference/auth.md:395` is already accurate — leave it. Only the in-example comment is wrong. Replace this line:

```typescript
// Call provideIdentity with a keyID string to obtain a signing identity from the device
```

with:

```typescript
// Call provideIdentity with a keyID string to obtain a FullIdentity from the device
```

Then change the example's type-only import so the annotation matches what the provider returns:

```typescript
import type { FullIdentity, IdentityProvider } from '@kokuin/token'
```

The call stays `await provider.provideIdentity('0')`. This matches `apps/ledger/README.md:101`, which already says `FullIdentity`.

- [ ] **Step 6: Run the harness**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: the four `docs-reference-auth-md-11/13/14` errors and the `ExpoKeyStore` error are gone. The `docs-reference-auth-md-12` (browser) error and all five `docs-skills-auth-skill-md-*` errors REMAIN — Tasks 3 and 5 fix those.

- [ ] **Step 7: Commit**

```bash
git add docs/reference/auth.md
git commit -m "docs(auth): use store.provideIdentity in keystore examples

Replaces the removed provideFullIdentityAsync free function with the
store method across node, electron, expo, and deterministic; fixes
ExpoKeyStore.entry (a TypeError — entry is an instance method); drops the
false 'no provide* helper' claim for deterministic, which contradicted
this file's own contract section; corrects ledger to FullIdentity.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `auth.md` — browser section rewrite

The published section describes the pre-PR#9 store. It is not a call-site fix: the claims are inverted.

**Files:**
- Modify: `docs/reference/auth.md` (the `@kokuin/browser` section, including the trailing note block)

**Interfaces:**
- Consumes: harness command from Task 1.

- [ ] **Step 1: Replace the browser section heading prose**

Delete: "Uses IndexedDB for persistence and Web Crypto (ES256 / P-256) for key generation. Returns a **`SigningIdentity`** only — browsers use non-exportable `CryptoKeyPair` objects, so decryption is not supported."

Replace with (mirrors `packages/browser/README.md`, which is already correct):

```markdown
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
```

- [ ] **Step 2: Replace the browser example**

There is no default-store free function any more; `BrowserKeyStore.open()` is memoized per name, so opening is the convenience.

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

- [ ] **Step 3: Delete the stale note block**

Remove entirely:

```markdown
> **Note**: `@kokuin/browser` exports `provideSigningIdentity` only. There is no `provideFullIdentity` — use `@kokuin/node`, `@kokuin/expo`, or `@kokuin/electron` when a `FullIdentity` (signing + decryption) is required.
```

It is false in both halves: browser exports neither free function, and it does provide a `FullIdentity`. Do not replace it with a softened version — the section prose from Step 1 already states the real constraint.

- [ ] **Step 4: Run the harness**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: no `docs-reference-auth-md-*` errors remain. Only the five `docs-skills-auth-skill-md-*` errors are left.

- [ ] **Step 5: Commit**

```bash
git add docs/reference/auth.md
git commit -m "docs(auth): correct the browser keystore story

The section described the pre-PR#9 store: ES256/P-256, SigningIdentity
only, 'decryption is not supported'. BrowserKeyStore now holds Ed25519
plus a derived X25519 key and provideIdentity returns a FullIdentity;
ES256 is the legacy signing-only path, never auto-re-keyed since that
would change the DID. Mirrors packages/browser/README.md.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `auth.md` — keystore contract section

**Files:**
- Modify: `docs/reference/auth.md` (the `## Keystore contract` section)

**Interfaces:**
- Consumes: `KeyEntry` / `MutableKeyEntry` / `KeyStore` shapes from `packages/token/src/keystore.ts`.

- [ ] **Step 1: Replace the contract type block**

The published `KeyEntry` carries `setAsync`/`removeAsync`, which moved to `MutableKeyEntry`. Replace the block with:

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

(The extractor skips this block — it has top-level `type ` lines. It is illustrative.)

- [ ] **Step 2: Document the split**

After the block, add:

```markdown
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
```

- [ ] **Step 3: Fix the platform key types list**

Replace the list with:

```markdown
- `@kokuin/node`, `@kokuin/expo`, `@kokuin/electron`: `Uint8Array` (raw Ed25519 private key)
- `@kokuin/browser`: `StoredKeyRecord` (a non-extractable Web Crypto key record)
- `@kokuin/deterministic`: keys derived on demand; `HDKeyStore.entry(keyID)` returns an `HDKeyEntry` whose `provideAsync()` calls `derivePrivateKey` internally.
```

Electron was documented as `string` (base64) "decoded by the `provide*` helpers" — it is `MutableKeyEntry<Uint8Array>` (`packages/electron/src/entry.ts:26`), and the cited helpers no longer exist.

- [ ] **Step 4: Verify the closing `IdentityProvider` paragraph**

It already reads "`HDKeyStore` implements `IdentityProvider<FullIdentity>` directly; call `store.provideIdentity('0')`" — correct, and no longer contradicted by the deterministic section after Task 2. Leave it. Confirm it says `FullIdentity` for ledger too.

- [ ] **Step 5: Run the harness**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: unchanged from Task 3 (`skipped` rises to 5 if the block count shifts). No new errors.

- [ ] **Step 6: Commit**

```bash
git add docs/reference/auth.md
git commit -m "docs(auth): document the KeyEntry/MutableKeyEntry split

KeyEntry lost setAsync/removeAsync to MutableKeyEntry; HD and ledger
deliberately omit the mutable facet. Also corrects the electron key type
(Uint8Array, not a base64 string decoded by since-removed helpers) and
the browser key type (StoredKeyRecord, not CryptoKeyPair).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `auth.skill.md` — patterns 2, 4, 5, 6, 7 and "When to Use What"

**Files:**
- Modify: `docs/skills/auth.skill.md`

**Interfaces:**
- Consumes: harness command from Task 1. Same canonical shapes as Task 2 — keep the two docs identical in substance.

- [ ] **Step 1: Pattern 2 (node)**

Replace the block with:

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

In its key points, replace "`provideFullIdentityAsync()` helper creates a `FullIdentity` from a keystore entry" with:

```markdown
- `store.provideIdentity(keyID)` returns a `FullIdentity`; `store.provideIdentitySync(keyID)` is the sync twin, which throws when the store was opened with a `lockPath` (a file lock cannot be acquired synchronously)
```

- [ ] **Step 2: Pattern 4 (expo)**

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

- [ ] **Step 3: Pattern 5 (electron)**

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

- [ ] **Step 4: Pattern 6 (deterministic)**

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

Delete the key point "**No `provide*` helper** — build identities manually with `createFullIdentity` from `@kokuin/token`" and replace with:

```markdown
- `HDKeyStore` implements `IdentityProvider<FullIdentity>` — call `store.provideIdentity(keyID)`. Async-only; there is no sync twin
```

- [ ] **Step 5: Pattern 7 (ledger)**

Change the comment "Call provideIdentity with a keyID string to get a signing identity from the device" to "// Call provideIdentity with a keyID string to get a FullIdentity from the device", and in the key points change "`createLedgerIdentityProvider` returns an `IdentityProvider` (not a keystore class)" to:

```markdown
- `createLedgerIdentityProvider` returns an `IdentityProvider<FullIdentity>` (not a keystore class); it implements neither `KeyStore` nor `MutableKeyEntry`, since the key never leaves the device
```

- [ ] **Step 6: "When to Use What" — browser entry**

Replace the `@kokuin/browser` bullets:

```markdown
**Use `@kokuin/browser`** when:
- Building web applications (SPA, PWA)
- Need persistent browser-based authentication
- Want Web Crypto security (non-extractable Ed25519 + derived X25519 keys)
- Client-side signing and decryption required (Chrome 137+, Firefox 130+, Safari 17+)
```

The old text said "signing identity only — no decryption", which is now false.

- [ ] **Step 7: Run the harness**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: only the `docs-skills-auth-skill-md-2` browser error remains (Task 6 fixes it).

- [ ] **Step 8: Commit**

```bash
git add docs/skills/auth.skill.md
git commit -m "docs(auth-skill): use store methods in keystore patterns

Mirrors the reference-doc fix: provideFullIdentityAsync is gone, entry is
an instance method on ExpoKeyStore, deterministic does have a provide*
method, and ledger returns a FullIdentity.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `auth.skill.md` — Pattern 3 browser rewrite

**Files:**
- Modify: `docs/skills/auth.skill.md` (Pattern 3)

**Interfaces:**
- Consumes: the browser prose settled in Task 3 — keep the two docs consistent.

- [ ] **Step 1: Replace the Pattern 3 block**

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

- [ ] **Step 2: Replace the Pattern 3 key points**

```markdown
- Uses IndexedDB for persistent storage across page reloads
- Holds a non-extractable Ed25519 signing key plus the X25519 agreement key derived from it — a current record both signs and decrypts
- Requires `SubtleCrypto` support for both algorithms: Chrome 137+, Firefox 130+, Safari 17+. Older browsers hard-error rather than falling back to ES256, since a fallback would mint a different DID for the same keyID
- Legacy ES256 records sign but cannot decrypt (WebCrypto will not let an ECDSA key do `deriveBits`). `store.provideIdentity(keyID)` throws on one; use `store.provideSigningIdentity(keyID)`. They are never silently re-keyed — that would change the DID
- All operations are async (IndexedDB requirement)
- Keys survive browser restart but are per-origin
```

- [ ] **Step 3: Run the harness — expect GREEN**

Run: `node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: no errors, exit 0. All 10 baseline errors from Task 1 are now resolved.

- [ ] **Step 4: Commit**

```bash
git add docs/skills/auth.skill.md
git commit -m "docs(auth-skill): correct the browser keystore pattern

Pattern 3 described the pre-PR#9 ES256 signing-only store. Matches the
reference doc: Ed25519 + derived X25519, FullIdentity via provideIdentity,
ES256 as the legacy signing-only path.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: `discover.skill.md` — package export lines

This doc has no TypeScript blocks, so the harness cannot gate it. Verify by reading against the package index files.

**Files:**
- Modify: `docs/skills/discover.skill.md:28-31`

- [ ] **Step 1: Replace lines 28-31**

```markdown
- **@kokuin/node** — Node.js keystore backed by OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service). Exports `NodeKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/browser** — Browser keystore backed by IndexedDB / Web Crypto (non-extractable Ed25519 + derived X25519). Exports `BrowserKeyStore`; `store.provideIdentity(keyID)` returns a `FullIdentity`, `store.provideSigningIdentity(keyID)` accepts legacy ES256 records signing-only.
- **@kokuin/expo** — React Native / Expo keystore backed by `expo-secure-store`. Exports `ExpoKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
- **@kokuin/electron** — Electron keystore using `safeStorage` + `electron-store` (main process only). Exports `ElectronKeyStore`; call `store.provideIdentity(keyID)` for a `FullIdentity`.
```

- [ ] **Step 2: Check the neighbouring lines**

Read the `@kokuin/deterministic` and `@kokuin/ledger-device` lines in the same list. If either repeats the "no `provide*` helper" or "signing identity" claims corrected elsewhere in this plan, fix it the same way. If they are already accurate, leave them.

- [ ] **Step 3: Verify no removed name survives anywhere**

Run: `grep -rn "provideFullIdentity\|provideFullIdentityAsync" docs/`
Expected: no output.

Run: `grep -rn "provideSigningIdentity" docs/`
Expected: only `store.provideSigningIdentity(...)` method-call forms — no free-function call and no `import { ..., provideSigningIdentity }`.

- [ ] **Step 4: Commit**

```bash
git add docs/skills/discover.skill.md
git commit -m "docs(discover): list the store-method identity surface

The package blurbs advertised provideFullIdentityAsync and a free
provideSigningIdentity; no package exports either.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Full green, README cross-check, harness teardown

**Files:**
- Delete: `.docs-snippets/` (untracked)

- [ ] **Step 1: Rebuild types and run the harness clean**

Run: `pnpm run build:types && node .docs-snippets/extract.mjs && pnpm exec tsc --noEmit --skipLibCheck -p .docs-snippets/tsconfig.json`
Expected: `kept=23 skipped=4` (± if block counts shifted), then no errors, exit 0.

- [ ] **Step 2: Cross-check the docs against the package READMEs**

Read `packages/browser/README.md` and `apps/ledger/README.md:101,121`. Confirm the browser suite/legacy story and the ledger `FullIdentity` claim in the docs now agree with them. These READMEs were refreshed in PR #9 and are the reference — if they disagree with a doc, the doc is wrong.

Run: `grep -rn "ES256" docs/reference/auth.md docs/skills/auth.skill.md`
Expected: every hit describes ES256 as the **legacy** record path, never as the default suite.

- [ ] **Step 3: Confirm the spec's success criteria**

- No free `provide*` name in any of the three docs (Task 7 Step 3 greps).
- Every example matches its package's canonical shape (harness green).
- Browser, deterministic, ledger, expo, `KeyEntry`/`MutableKeyEntry`, electron key type all match the Verified Source of Truth table.

- [ ] **Step 4: Delete the harness**

```bash
rm -rf .docs-snippets
```

Run: `git status --short`
Expected: clean. The harness must not appear in any commit.

- [ ] **Step 5: Update the plan Stage and commit**

Set `**Stage:** reviewing` in this plan file, then:

```bash
git add docs/superpowers/plans/2026-07-16-auth-docs-provide-identity-refresh.md
git commit -m "docs: advance auth-docs plan to reviewing

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```
