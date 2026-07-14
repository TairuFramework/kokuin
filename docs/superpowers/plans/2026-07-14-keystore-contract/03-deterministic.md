## Task 3: deterministic — `KeyEntry` only, honest keyID, hardened paths

HD is the backend the old contract lied about hardest: `setAsync` threw, `removeAsync` silently no-op'd, and `entry(x).keyID` returned the *derivation path*, not `x`.

**Files:**
- Modify: `packages/deterministic/src/derivation.ts` (reject non-hardened paths)
- Modify: `packages/deterministic/src/entry.ts` (full rewrite)
- Modify: `packages/deterministic/src/store.ts:41-45` (`entry`) and `:25` (`#entries`)
- Modify: `packages/deterministic/src/index.ts`
- Create: `packages/deterministic/test/conformance.test.ts`
- Modify: `packages/deterministic/test/derivation.test.ts` (add the non-hardened cases)

**Interfaces:**
- Consumes: `KeyEntry`, `KeyStore`, `keyStoreConformanceCases` from `@kokuin/token` (Task 1).
- Produces: `HDKeyEntry implements KeyEntry<Uint8Array>` with `readonly keyID` (the caller's) and a new `readonly path` (the resolved derivation path). `HDKeyStore` unchanged in shape.

- [ ] **Step 1: Write the failing tests**

Create `packages/deterministic/test/conformance.test.ts`:

```ts
import { keyStoreConformanceCases } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { HDKeyStore } from '../src/store.js'

const SEED = new Uint8Array(64).fill(7)

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

describe('HDKeyStore conformance', () => {
  // HD derives rather than stores: getAsync can always produce a key, so it never returns
  // null. That is contract-legal — every other invariant still applies.
  const cases = keyStoreConformanceCases({
    createStore: () => HDKeyStore.fromSeed(SEED),
    isSameKey: sameBytes,
    neverAbsent: true,
    keyIDs: ['0', '1'],
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('HDKeyEntry', () => {
  test('keyID is the caller’s keyID, not the derivation path', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry('0')
    expect(entry.keyID).toBe('0')
    expect(entry.path).toBe("m/44'/876'/0'")
  })

  test('a full path keyID round-trips as both keyID and path', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry("m/44'/876'/5'")
    expect(entry.keyID).toBe("m/44'/876'/5'")
    expect(entry.path).toBe("m/44'/876'/5'")
  })

  test('has no setAsync or removeAsync — the substrate cannot do either', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry('0')
    expect('setAsync' in entry).toBe(false)
    expect('removeAsync' in entry).toBe(false)
  })
})
```

Add to `packages/deterministic/test/derivation.test.ts` (inside its existing `describe` for `resolveDerivationPath`):

```ts
  test('rejects a non-hardened segment — SLIP-0010 ed25519 has no public derivation', () => {
    expect(() => resolveDerivationPath("m/44'/876/0'")).toThrow(/hardened/)
    expect(() => resolveDerivationPath("m/44'/876'/0")).toThrow(/hardened/)
    expect(() => resolveDerivationPath('m/0')).toThrow(/hardened/)
  })

  test('accepts hardened segments with either notation', () => {
    expect(resolveDerivationPath("m/44'/876'/0'")).toBe("m/44'/876'/0'")
    expect(resolveDerivationPath('m/44h/876h/0h')).toBe('m/44h/876h/0h')
  })

  test('accepts the bare master path', () => {
    expect(resolveDerivationPath('m')).toBe('m')
  })
```

- [ ] **Step 2: Run to verify they fail**

Run from `packages/deterministic`: `pnpm exec vitest run`

Expected: FAIL — `entry.path` is undefined, `keyID` returns `m/44'/876'/0'` instead of `0`, `setAsync`/`removeAsync` still exist, and `resolveDerivationPath` accepts non-hardened paths.

- [ ] **Step 3: Reject non-hardened paths**

Replace `resolveDerivationPath` in `packages/deterministic/src/derivation.ts`. Note `m` alone (the master key) is legal and has no segments to check.

```ts
const INDEX_RE = /^\d+$/
const HARDENED_SEGMENT_RE = /^\d+['h]$/

/**
 * SLIP-0010 ed25519 supports **hardened derivation only** — there is no public-key
 * derivation for ed25519, so a non-hardened segment is not a weaker key, it is not a key.
 * Reject it here rather than letting the derivation library decide.
 */
function assertHardened(path: string): void {
  if (path === 'm') {
    return
  }
  const segments = path.slice(2).split('/')
  for (const segment of segments) {
    if (!HARDENED_SEGMENT_RE.test(segment)) {
      throw new Error(
        `Invalid derivation path "${path}": segment "${segment}" is not hardened. ` +
          "SLIP-0010 ed25519 requires every segment to be hardened (e.g. 0' or 0h).",
      )
    }
  }
}

export function resolveDerivationPath(keyID: string, basePath: string = DEFAULT_BASE_PATH): string {
  if (keyID.startsWith('m/') || keyID === 'm') {
    assertHardened(keyID)
    return keyID
  }
  if (INDEX_RE.test(keyID)) {
    const path = `m/${basePath}/${keyID}'`
    assertHardened(path)
    return path
  }
  throw new Error(`Invalid keyID: "${keyID}" — expected a numeric index or full derivation path`)
}
```

- [ ] **Step 4: Rewrite the entry**

Replace `packages/deterministic/src/entry.ts`:

```ts
import type { KeyEntry } from '@kokuin/token'

import { derivePrivateKey } from './derivation.js'

export type HDKeyEntryParams = {
  seed: Uint8Array
  /** The caller's keyID, as passed to `HDKeyStore#entry`. */
  keyID: string
  /** The derivation path `keyID` resolved to. */
  path: string
}

/**
 * A derived HD key.
 *
 * Implements {@link KeyEntry} and **not** `MutableKeyEntry`: an HD key is a pure function of
 * (seed, path). There is nothing to set, and deleting it would not stop it being derivable.
 * Previously `setAsync` threw and `removeAsync` silently resolved without doing anything —
 * the type now says what the substrate can do, so neither method exists.
 *
 * {@link getAsync} never returns `null`: the key can always be derived. That is contract-legal
 * for a derived backend (see `KeyEntry`'s invariant 2), and it means the `existing != null`
 * branch every storage-backed package has is dead code here.
 */
export class HDKeyEntry implements KeyEntry<Uint8Array> {
  #seed: Uint8Array
  #keyID: string
  #path: string
  #cachedKey?: Uint8Array

  constructor(params: HDKeyEntryParams) {
    this.#seed = params.seed
    this.#keyID = params.keyID
    this.#path = params.path
  }

  /** The keyID this entry was created for — NOT the derivation path. See {@link path}. */
  get keyID(): string {
    return this.#keyID
  }

  /** The SLIP-0010 derivation path {@link keyID} resolved to, e.g. `m/44'/876'/0'`. */
  get path(): string {
    return this.#path
  }

  #derive(): Uint8Array {
    this.#cachedKey ??= derivePrivateKey(this.#seed, this.#path)
    return this.#cachedKey
  }

  /** The derived key. Never `null` — a derived key always exists. */
  async getAsync(): Promise<Uint8Array | null> {
    return this.#derive()
  }

  async provideAsync(): Promise<Uint8Array> {
    return this.#derive()
  }
}
```

- [ ] **Step 5: Cache entries by keyID in the store**

In `packages/deterministic/src/store.ts`, change `#entries` (line 25) to a null-prototype record and rewrite `entry` (lines 41-45). Caching by **path** was what made `entry(x).keyID` return the path; cache by the caller's keyID instead.

```ts
  #entries: Record<string, HDKeyEntry> = Object.create(null)
```

```ts
  entry(keyID: string): HDKeyEntry {
    this.#entries[keyID] ??= new HDKeyEntry({
      seed: this.#seed,
      keyID,
      path: resolveDerivationPath(keyID, this.#basePath),
    })
    return this.#entries[keyID]
  }
```

Note: two different keyIDs may resolve to the same path (`'0'` and `"m/44'/876'/0'"`), and each now gets its own entry object holding the same derived key. That is correct — `keyID` round-trips for both, and the key they derive is identical.

- [ ] **Step 6: Run tests and commit**

Run from `packages/deterministic`:
- `pnpm exec vitest run` — expected: PASS.
- `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: clean.

Then commit (still `--no-verify`; node/electron/expo/browser do not compile yet):

```bash
git add packages/deterministic
git commit --no-verify -m "$(cat <<'EOF'
fix(deterministic)!: honest KeyEntry, keyID round-trip, hardened-path validation

- HDKeyEntry implements KeyEntry only. setAsync (which threw) and removeAsync
  (a silent no-op) are deleted: the substrate cannot do either.
- entry(x).keyID now returns x, not the derivation path. The resolved path is
  exposed separately as `path`.
- Non-hardened derivation paths throw. SLIP-0010 ed25519 has no public
  derivation, so a non-hardened segment is not a key at all.
EOF
)"
```

---

