# Node e2e — two real processes racing a real Secret Service

Task 13. The centerpiece of the whole plan's test story.

Every existing node test mocks `@napi-rs/keyring`. A mock is a single in-process object, so it **structurally cannot** exhibit the cross-process race — which is precisely why the bug survived the existing suite. This suite spawns two real Node processes against a **real** Secret Service and races them on a fresh keyID.

Without `lockPath` it **demonstrates the key loss**. With `lockPath` it **proves the loss is closed**. The first half is a test that asserts the bug still exists when you opt out — if it ever stops failing that way, the race is gone for some other reason and we want to know.

Unlike the other three e2e suites (web, desktop, android/iOS), this is a small spawned CLI, not a GUI app driven by Playwright. It gets a **local** workflow, not a `kigu` reusable one, because the runner needs `dbus` + `gnome-keyring`.

**Files:**
- Create: `tests/e2e-node/package.json`
- Create: `tests/e2e-node/tsconfig.json`
- Create: `tests/e2e-node/src/provide.ts` — the CLI the test spawns
- Create: `tests/e2e-node/test/race.test.ts`
- Create: `.github/workflows/e2e-node.yml`

**Interfaces:**
- Consumes: `NodeKeyStore` from `@kokuin/node` (Tasks 4–5), specifically `open(service, { lockPath })`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Scaffold the workspace package**

`tests/*` is already a workspace glob in `pnpm-workspace.yaml`, so no config change is needed there.

Create `tests/e2e-node/package.json`:

```json
{
  "name": "e2e-node",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "test": "vitest run"
  },
  "dependencies": {
    "@kokuin/node": "workspace:^",
    "@kokuin/token": "workspace:^"
  },
  "devDependencies": {
    "@types/node": "catalog:",
    "typescript": "catalog:"
  }
}
```

Create `tests/e2e-node/tsconfig.json` (mirror `packages/node/tsconfig.json`, which extends `@kigu/dev/tsconfig.json` — read it and copy the shape):

```json
{
  "extends": "@kigu/dev/tsconfig.json",
  "include": ["src", "test"]
}
```

From the repo root: `pnpm install`

- [ ] **Step 2: Write the CLI the test spawns**

Create `tests/e2e-node/src/provide.ts`. It does exactly one thing: provide an identity, print its DID as JSON, exit. Two of these racing each other is the whole experiment.

A barrier is needed so both processes hit `provideAsync` at genuinely the same moment rather than one finishing before the other starts: each process waits until a shared start file appears.

```ts
import { existsSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'

import { NodeKeyStore } from '@kokuin/node'

const [service, keyID, startFile, lockPath] = process.argv.slice(2)

async function waitForStart(): Promise<void> {
  // Spin until the parent drops the start file, so both processes enter provideAsync together.
  // Without this the first process finishes before the second begins, and there is no race.
  while (!existsSync(startFile)) {
    await sleep(2)
  }
}

async function main(): Promise<void> {
  const store = NodeKeyStore.open(service, lockPath ? { lockPath } : undefined)
  await waitForStart()
  const identity = await store.provideIdentity(keyID)
  process.stdout.write(JSON.stringify({ did: identity.id }))
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ error: String(error) }))
  process.exit(1)
})
```

- [ ] **Step 3: Write the race test**

Create `tests/e2e-node/test/race.test.ts`.

```ts
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { Entry, findCredentials } from '@napi-rs/keyring'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'

const run = promisify(execFile)
const CLI = new URL('../src/provide.ts', import.meta.url).pathname

let dir: string
let startFile: string
let service: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'kokuin-e2e-'))
  startFile = join(dir, 'start')
  service = `kokuin-e2e-${process.pid}-${Math.trunc(performance.now())}`
})

afterEach(async () => {
  // Leave no credentials behind in the developer's (or runner's) real keyring.
  for (const credential of findCredentials(service)) {
    new Entry(service, credential.account).deletePassword()
  }
  await rm(dir, { recursive: true, force: true })
})

/** Spawn two processes, release them together, and return what each one resolved to. */
async function race(keyID: string, lockPath?: string): Promise<Array<{ did?: string; error?: string }>> {
  const args = [service, keyID, startFile, ...(lockPath ? [lockPath] : [])]
  const processes = [
    run(process.execPath, ['--experimental-strip-types', CLI, ...args]),
    run(process.execPath, ['--experimental-strip-types', CLI, ...args]),
  ]
  // Both are now spinning on the start file. Release them at once.
  await writeFile(startFile, '')
  const results = await Promise.all(processes)
  return results.map((result) => JSON.parse(result.stdout))
}

/** The DID that actually survived in the OS keyring — the one any later process will load. */
function storedDID(keyID: string): string | null {
  const stored = new Entry(service, keyID).getPassword()
  return stored
}

describe('cross-process provideAsync', () => {
  // This test asserts the BUG. @napi-rs/keyring's write is an unconditional upsert with no
  // compare-and-set, so without a lock both processes observe null, both generate, both
  // write — and the loser holds a key that is no longer in the keychain. If this ever stops
  // failing this way, the race closed for some other reason and we want to know why.
  test('WITHOUT lockPath, the two processes can disagree — silent key loss', async () => {
    // Racing is nondeterministic; run several rounds and look for a single divergence.
    let diverged = false
    for (let round = 0; round < 12 && !diverged; round++) {
      const keyID = `unlocked-${round}`
      await writeFile(startFile, '').catch(() => undefined)
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID)
      expect(first.error).toBeUndefined()
      expect(second.error).toBeUndefined()
      if (first.did !== second.did) {
        diverged = true
        // The loser signed with a key that is NOT what the keychain now holds.
        const survivor = storedDID(keyID)
        expect(survivor).not.toBeNull()
      }
    }
    expect(
      diverged,
      'expected at least one divergence across 12 unlocked rounds — if this fails, the race ' +
        'may have closed some other way, or the barrier is not releasing both processes together',
    ).toBe(true)
  }, 60_000)

  test('WITH lockPath, both processes always agree on one identity', async () => {
    const lockPath = join(dir, 'keystore.lock')
    for (let round = 0; round < 12; round++) {
      const keyID = `locked-${round}`
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID, lockPath)
      expect(first.error).toBeUndefined()
      expect(second.error).toBeUndefined()
      expect(second.did).toBe(first.did)
      expect(storedDID(keyID)).not.toBeNull()
    }
  }, 60_000)
})
```

Add `@napi-rs/keyring` to `tests/e2e-node/package.json` `devDependencies` as `"catalog:"` — the test reads and cleans the real keyring directly.

- [ ] **Step 4: Run it locally**

macOS has a Keychain, so this runs on a dev machine without extra setup:

```bash
cd tests/e2e-node && pnpm exec vitest run
```

Expected: both tests PASS. The first proves the race is real without a lock; the second proves `lockPath` closes it.

macOS may prompt for Keychain access on the first run. If the unlocked test does **not** diverge in 12 rounds, widen the window — the two processes may be serializing on the Keychain prompt rather than racing. Raise the round count before weakening the assertion, and do not convert it into a `skipIf`.

- [ ] **Step 5: Add the CI workflow**

Create `.github/workflows/e2e-node.yml`. Unlike the other e2e workflows this is **local**, not a `kigu` reusable one: it needs a D-Bus session and a gnome-keyring daemon.

It must **not** skip itself when the daemon is absent. That is the silent-green pattern the `ci-release-gating` item already flags on the Speculos suite: a suite that skips when its dependency is missing reports success while testing nothing.

```yaml
name: Node E2E
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Secret Service
        run: |
          sudo apt-get update
          sudo apt-get install -y gnome-keyring dbus-x11 libsecret-1-0

      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: pnpm

      - run: pnpm install --frozen-lockfile
      - run: pnpm run -r build:js

      # A real Secret Service, unlocked with an empty password. If this fails, the job fails —
      # it never degrades into a skipped suite that reports green while testing nothing.
      - name: Run e2e against a real Secret Service
        working-directory: tests/e2e-node
        run: |
          dbus-run-session -- bash -c '
            echo "" | gnome-keyring-daemon --unlock --components=secrets
            pnpm exec vitest run
          '
```

- [ ] **Step 6: Commit**

```bash
git add tests/e2e-node .github/workflows/e2e-node.yml pnpm-lock.yaml
git commit -m "$(cat <<'EOF'
test(e2e-node): two real processes racing a real Secret Service

Every existing node test mocks @napi-rs/keyring, and a mock is a single
in-process object — it structurally cannot exhibit the cross-process race, which
is why the bug survived the suite.

This spawns two real processes, releases them through a barrier so they enter
provideAsync together, and races them on a fresh keyID. Without lockPath it
asserts the divergence (the loser signs with a key no longer in the keychain);
with lockPath it asserts both processes always agree.

The workflow is local rather than a kigu reusable one because it needs dbus +
gnome-keyring, and it does not skipIf the daemon away when absent.
EOF
)"
```
