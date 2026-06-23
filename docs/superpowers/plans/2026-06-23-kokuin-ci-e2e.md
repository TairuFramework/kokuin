# kokuin CI + e2e coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub Actions CI to `kokuin` (mirroring sozai) plus end-to-end coverage for the three platform keystores — `@kokuin/browser` (web), `@kokuin/electron` (desktop), `@kokuin/expo` (mobile) — each adapted from enkaku's suites and reduced to kokuin-only scope.

**Architecture:** One base `build-test.yml` delegates to the shared kigu reusable workflow (lint + unit/type tests across `packages/*`). Three e2e apps live under `tests/` as private workspace packages; each signs a token in one keystore and verifies it. Four dedicated e2e workflows run them. The fast build-test lane stays lean via pnpm postinstall gating + shared caches.

**Tech Stack:** pnpm workspaces + turbo, Vite, React (react-native-web for web, plain react-dom for electron, react-native/Expo for mobile), Playwright (web + electron), Maestro (mobile), GitHub Actions, kigu reusable workflows.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-23-kokuin-ci-e2e-design.md`.
- **Source repo for ports:** enkaku checkout at `/Users/paul/dev/yulsi/enkaku` (sibling). Referenced `cp` source paths assume it is present.
- **Stack layering** (`@sozai ← @kokuin ← @enkaku ← @kumiai`, deps strictly downward): a kokuin test **must not** import `@enkaku/*` or `@kumiai/*` (upward dep / cycle). `@sozai/*` deps are always allowed (downward).
- **Keystore service rename:** any `EnkakuKeystore` literal → `KokuinKeystore`. App ids `dev.enkaku.e2e` → `dev.kokuin.e2e`.
- **e2e package scripts** are named `test` / `build` / `start` — **never** `test:unit` / `test:types` / `build:js` — so turbo's base CI tasks skip them.
- **Workflow triggers:** base build-test and every e2e workflow trigger on `pull_request` + `push: branches: [main]` only.
- **Node versions in CI:** `[24, 26]` for build-test; `24` for e2e jobs.
- **Catalog versions (exact):** `react` 19.2.3, `react-dom` 19.2.3, `react-native-web` 0.21.2, `@playwright/test` 1.61.0, `vite` ^8.0.16, `@vitejs/plugin-react` ^6.0.2, `@electron-forge/cli` ^7.11.2, `@electron-forge/plugin-vite` ^7.11.2, `@types/react` ^19.2.17, `@types/react-dom` ^19.2.3. Expo SDK 56 deps (`expo`, `expo-status-bar`, `react-native`, expo's `react`) are explicit versions in the expo app (not catalog), pinned via `expo install --fix`.
- **Validate every workflow** with `actionlint <file>` (installed at `/opt/homebrew/bin/actionlint`).
- **Commit after every task.** Branch: work on current `chore/further-setup` (already off main).

---

## Phase 0 — Base CI + workspace plumbing

### Task 1: Base build-test workflow

**Files:**
- Create: `.github/workflows/build-test.yml`

**Interfaces:**
- Produces: the repo's primary CI lane (lint + `pnpm test` across `packages/*` on Node 24/26). Later e2e workflows are independent of it.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/build-test.yml`:

```yaml
name: Build and test
on:
  push:
    branches: [main]
  pull_request:
jobs:
  build-test:
    uses: TairuFramework/kigu/.github/workflows/build-test.yml@main
    with:
      node-versions: '[24, 26]'
      ts-readiness-check: true
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `actionlint .github/workflows/build-test.yml`
Expected: no output (exit 0). A `could not parse the workflow file` error or a job/step error is a FAIL.

- [ ] **Step 3: Sanity-check the local test lane still works**

Run: `pnpm install --frozen-lockfile && pnpm test`
Expected: turbo runs `test:types` + `test:unit` across `packages/*`, all pass. (This is what the workflow runs remotely.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build-test.yml
git commit -m "ci: add base build-test workflow (kigu reusable, node 24/26)"
```

---

### Task 2: Workspace plumbing — tests glob, catalog, postinstall gating

**Files:**
- Modify: `pnpm-workspace.yaml`

**Interfaces:**
- Produces: `tests/*` recognized as workspace packages; catalog entries the e2e apps consume via `catalog:`; `electron` postinstall gated off the shared install.

- [ ] **Step 1: Add `tests/*` to the workspace and gate electron's postinstall**

In `pnpm-workspace.yaml`, change the `packages` list and the `allowBuilds` map:

```yaml
packages:
  - packages/*
  - tests/*
```

```yaml
allowBuilds:
  '@swc/core': true
  esbuild: false
  electron: false
```

(`electron: false` makes pnpm skip electron's ~100MB binary download during the shared install. The desktop e2e workflow fetches it explicitly.)

- [ ] **Step 2: Add the e2e catalog entries**

In `pnpm-workspace.yaml`, extend the `catalog:` block with (keep existing entries; `electron` is already present):

```yaml
  '@electron-forge/cli': ^7.11.2
  '@electron-forge/plugin-vite': ^7.11.2
  '@playwright/test': 1.61.0
  '@types/react': ^19.2.17
  '@types/react-dom': ^19.2.3
  '@vitejs/plugin-react': ^6.0.2
  react: 19.2.3
  react-dom: 19.2.3
  react-native-web: 0.21.2
  vite: ^8.0.16
```

Do **not** catalog the Expo-SDK-managed deps (`expo`, `expo-status-bar`, `react-native`, and expo's own `react`): the `catalog:` protocol is opaque to `expo install --fix`, which manages explicit version strings in `package.json`. Those stay as explicit versions in the expo app (Task 9).

- [ ] **Step 3: Verify the workspace still installs cleanly**

Run: `pnpm install`
Expected: completes without error. pnpm may print `Ignored build scripts: electron` — that is intended. No `ERR_PNPM` failures.

- [ ] **Step 4: Verify no stray build breakage**

Run: `pnpm test`
Expected: same pass as Task 1 Step 3 (no `tests/*` packages exist yet, so nothing new runs).

- [ ] **Step 5: Commit**

```bash
git add pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "chore: add tests/* workspace, e2e catalog deps, gate electron postinstall"
```

---

## Phase 1 — e2e-web (`@kokuin/browser`)

### Task 3: Scaffold the web e2e app

**Files:**
- Create: `tests/e2e-web/package.json`
- Create: `tests/e2e-web/index.html`
- Create: `tests/e2e-web/vite.config.ts`
- Create: `tests/e2e-web/playwright.config.ts`
- Create: `tests/e2e-web/tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`
- Create: `tests/e2e-web/.gitignore`
- Create: `tests/e2e-web/src/App.tsx`
- Create: `tests/e2e-web/src/main.tsx`

**Interfaces:**
- Produces: a Vite app whose page renders a "Sign token" button (via `@kokuin/browser` `provideSigningIdentity`) → "Verify token" (via `@kokuin/token` `verifyToken`) → text `Verified token: OK`. Served by `pnpm start` on `http://localhost:4173`.

- [ ] **Step 1: Copy the verbatim boilerplate from enkaku**

```bash
mkdir -p tests/e2e-web/src
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/vite.config.ts        tests/e2e-web/vite.config.ts
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/playwright.config.ts  tests/e2e-web/playwright.config.ts
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/tsconfig.json         tests/e2e-web/tsconfig.json
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/tsconfig.app.json     tests/e2e-web/tsconfig.app.json
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/tsconfig.node.json    tests/e2e-web/tsconfig.node.json
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/.gitignore            tests/e2e-web/.gitignore
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-web/src/main.tsx          tests/e2e-web/src/main.tsx
```

These are kokuin-pure already (no `@enkaku` imports). `main.tsx` uses `react-native`'s `AppRegistry`; `vite.config.ts` aliases `react-native` → `react-native-web`.

- [ ] **Step 2: Write `tests/e2e-web/package.json`**

```json
{
  "name": "e2e-web",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "start": "vite preview",
    "test": "playwright test"
  },
  "dependencies": {
    "@kokuin/browser": "workspace:^",
    "@kokuin/token": "workspace:^",
    "react": "catalog:",
    "react-dom": "catalog:",
    "react-native-web": "catalog:"
  },
  "devDependencies": {
    "@playwright/test": "catalog:",
    "@types/node": "catalog:",
    "@types/react": "catalog:",
    "@types/react-dom": "catalog:",
    "@vitejs/plugin-react": "catalog:",
    "typescript": "catalog:",
    "vite": "catalog:"
  }
}
```

- [ ] **Step 3: Write `tests/e2e-web/index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Kokuin Web E2E tests</title>
    <style>body { user-select: none } #root { display: flex; flex-direction: column; height: 100vh; }</style>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 4: Write `tests/e2e-web/src/App.tsx`**

```tsx
import { provideSigningIdentity } from '@kokuin/browser'
import { type Token, verifyToken } from '@kokuin/token'
import { useState } from 'react'
import { Button, StyleSheet, Text, View } from 'react-native'

const identityPromise = provideSigningIdentity('test')

type Data = {
  test: string
}

export default function App() {
  const [signedToken, setSignedToken] = useState<Token<Data> | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)

  let button = null
  if (signedToken == null) {
    button = (
      <Button
        title="Sign token"
        onPress={() => {
          identityPromise
            .then((identity) => identity.signToken({ test: 'OK' }))
            .then(setSignedToken)
        }}
      />
    )
  } else if (verifiedToken == null) {
    button = (
      <Button
        title="Verify token"
        onPress={() => {
          verifyToken(signedToken).then(setVerifiedToken)
        }}
      />
    )
  }
  return (
    <View style={styles.container}>
      {button}
      {verifiedToken ? <Text>Verified token: {verifiedToken.payload.test}</Text> : null}
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 10,
  },
})
```

- [ ] **Step 5: Install and build the app**

```bash
pnpm install
pnpm --filter e2e-web build
```
Expected: `pnpm install` links the new workspace package; `vite build` produces `tests/e2e-web/dist/` with no TypeScript errors.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e-web pnpm-lock.yaml
git commit -m "test(e2e-web): scaffold @kokuin/browser sign-verify app"
```

---

### Task 4: Web e2e test passes

**Files:**
- Create: `tests/e2e-web/test/sign-verify.spec.ts`

**Interfaces:**
- Consumes: the running app from Task 3 (`pnpm start` → `http://localhost:4173`).

- [ ] **Step 1: Write the Playwright test**

Create `tests/e2e-web/test/sign-verify.spec.ts`:

```ts
import { test } from '@playwright/test'

test('sign and verify token', async ({ page }) => {
  await page.goto('/')
  await page.getByText('Sign token').click()
  await page.getByText('Verify token').click()
  await page.getByText('Verified token: OK').waitFor()
})
```

- [ ] **Step 2: Install the Playwright browser**

Run: `pnpm --filter e2e-web exec playwright install chromium`
Expected: chromium downloaded (or already cached).

- [ ] **Step 3: Run the test (full browser matrix may need firefox/webkit; chromium proves the flow)**

Run: `cd tests/e2e-web && pnpm exec playwright test --project=chromium; cd -`
Expected: `1 passed`. The `webServer` config builds+previews automatically. If it FAILS, the app wiring is wrong — fix Task 3 before proceeding.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-web/test/sign-verify.spec.ts
git commit -m "test(e2e-web): add sign-verify playwright spec"
```

---

### Task 5: Web e2e workflow

**Files:**
- Create: `.github/workflows/e2e-web.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/e2e-web.yml`:

```yaml
name: Web E2E
on:
  push:
    branches: [main]
  pull_request:
env:
  CI: true
  DO_NOT_TRACK: 1
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Setup environment
        uses: TairuFramework/kigu/setup@main
        with:
          node-version: 24

      - name: Cache Playwright browsers
        uses: actions/cache@v4
        with:
          path: ~/.cache/ms-playwright
          key: playwright-${{ runner.os }}-${{ hashFiles('pnpm-lock.yaml') }}

      - name: Install Playwright browsers
        run: pnpm --filter e2e-web exec playwright install --with-deps

      - name: Build app
        working-directory: tests/e2e-web
        run: pnpm run build

      - name: Run Playwright tests
        working-directory: tests/e2e-web
        run: pnpm run test

      - uses: actions/upload-artifact@v4
        if: ${{ !cancelled() }}
        with:
          name: playwright-report-web
          path: tests/e2e-web/playwright-report/
          retention-days: 30
```

- [ ] **Step 2: Validate**

Run: `actionlint .github/workflows/e2e-web.yml`
Expected: no output (exit 0).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/e2e-web.yml
git commit -m "ci(e2e-web): add web e2e workflow with playwright cache"
```

---

## Phase 2 — e2e-electron (`@kokuin/electron`, vanilla IPC, plain react-dom)

### Task 6: Scaffold the electron e2e app shell

**Files:**
- Create: `tests/e2e-electron/package.json`
- Create: `tests/e2e-electron/forge.config.ts`
- Create: `tests/e2e-electron/forge.env.d.ts`
- Create: `tests/e2e-electron/index.html`
- Create: `tests/e2e-electron/tsconfig.json`
- Create: `tests/e2e-electron/.gitignore`
- Create: `tests/e2e-electron/config/vite.main.config.mts`
- Create: `tests/e2e-electron/config/vite.preload.config.mts`
- Create: `tests/e2e-electron/config/vite.renderer.config.mts`

**Interfaces:**
- Produces: an electron-forge + Vite app shell (main/preload/renderer build targets). The keystore wiring lands in Task 7. Renderer uses plain `react-dom` (no react-native) per spec.

- [ ] **Step 1: Copy the verbatim forge/vite/gitignore boilerplate**

```bash
mkdir -p tests/e2e-electron/config tests/e2e-electron/src
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/forge.config.ts            tests/e2e-electron/forge.config.ts
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/forge.env.d.ts             tests/e2e-electron/forge.env.d.ts
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/tsconfig.json              tests/e2e-electron/tsconfig.json
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/.gitignore                 tests/e2e-electron/.gitignore
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/config/vite.main.config.mts    tests/e2e-electron/config/vite.main.config.mts
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/config/vite.preload.config.mts tests/e2e-electron/config/vite.preload.config.mts
```

- [ ] **Step 2: Write the renderer vite config (plain react, no react-native alias)**

Create `tests/e2e-electron/config/vite.renderer.config.mts`:

```ts
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vitejs.dev/config
export default defineConfig({
  plugins: [react()],
})
```

- [ ] **Step 3: Write `tests/e2e-electron/index.html` (renderer entry → `renderer.tsx`)**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Kokuin Electron E2E tests</title>
    <style>body { user-select: none } #root { display: flex; flex-direction: column; height: 100vh; }</style>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/renderer.tsx"></script>
  </body>
</html>
```

- [ ] **Step 4: Write `tests/e2e-electron/package.json`**

```json
{
  "name": "e2e-electron",
  "productName": "e2e-electron",
  "version": "1.0.1",
  "private": true,
  "description": "Kokuin electron keystore e2e",
  "main": ".vite/build/main.js",
  "scripts": {
    "start": "electron-forge start",
    "package": "electron-forge package",
    "test": "playwright test"
  },
  "dependencies": {
    "@kokuin/electron": "workspace:^",
    "@kokuin/token": "workspace:^",
    "react": "catalog:",
    "react-dom": "catalog:"
  },
  "devDependencies": {
    "@electron-forge/cli": "catalog:",
    "@electron-forge/plugin-vite": "catalog:",
    "@playwright/test": "catalog:",
    "@types/node": "catalog:",
    "@types/react": "catalog:",
    "@types/react-dom": "catalog:",
    "@vitejs/plugin-react": "catalog:",
    "electron": "catalog:",
    "typescript": "catalog:",
    "vite": "catalog:"
  }
}
```

- [ ] **Step 5: Install**

Run: `pnpm install`
Expected: links `e2e-electron`. pnpm still prints `Ignored build scripts: electron` (gated). No errors.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e-electron pnpm-lock.yaml
git commit -m "test(e2e-electron): scaffold forge+vite shell (plain react renderer)"
```

---

### Task 7: Vanilla-IPC keystore wiring + electron e2e test

**Files:**
- Create: `tests/e2e-electron/src/main.ts`
- Create: `tests/e2e-electron/src/preload.ts`
- Create: `tests/e2e-electron/src/renderer.tsx`
- Create: `tests/e2e-electron/src/App.tsx`
- Create: `tests/e2e-electron/src/global.d.ts`
- Create: `tests/e2e-electron/test/sign-verify.test.ts`

**Interfaces:**
- Consumes: `@kokuin/electron` `provideFullIdentityAsync(service: string, keyID: string)`; `@kokuin/token` `stringifyToken` / `verifyToken`.
- Produces: a packaged electron app exposing `window.kokuin.sign(payload, keyID?) => Promise<string>` over `contextBridge`/`ipcMain`; Playwright `_electron` test driving Sign → Verify → assert.

- [ ] **Step 1: Write the main process (vanilla `ipcMain`, no `@enkaku`)**

Create `tests/e2e-electron/src/main.ts`:

```ts
import path from 'node:path'
import { provideFullIdentityAsync } from '@kokuin/electron'
import { stringifyToken } from '@kokuin/token'
import { app, BrowserWindow, ipcMain } from 'electron'

ipcMain.handle(
  'sign',
  async (_event, payload: Record<string, unknown>, keyID?: string) => {
    const identity = await provideFullIdentityAsync('KokuinKeystore', keyID ?? 'test')
    const token = await identity.signToken(payload)
    return stringifyToken(token)
  },
)

const createWindow = () => {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  })

  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL)
  } else {
    mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`))
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
  })
}

app.on('ready', createWindow)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow()
  }
})
```

- [ ] **Step 2: Write the preload (contextBridge, no `@enkaku`)**

Create `tests/e2e-electron/src/preload.ts`:

```ts
import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('kokuin', {
  sign: (payload: Record<string, unknown>, keyID?: string): Promise<string> =>
    ipcRenderer.invoke('sign', payload, keyID),
})
```

- [ ] **Step 3: Write the renderer types and entry**

Create `tests/e2e-electron/src/global.d.ts`:

```ts
export {}

declare global {
  interface Window {
    kokuin: {
      sign: (payload: Record<string, unknown>, keyID?: string) => Promise<string>
    }
  }
}
```

Create `tests/e2e-electron/src/renderer.tsx`:

```tsx
import { createRoot } from 'react-dom/client'

import App from './App'

const root = document.getElementById('root')
if (root != null) {
  createRoot(root).render(<App />)
}
```

- [ ] **Step 4: Write `tests/e2e-electron/src/App.tsx` (plain DOM, IPC sign + local verify)**

```tsx
import { type Token, verifyToken } from '@kokuin/token'
import { useState } from 'react'

type Data = {
  test: string
}

export default function App() {
  const [signedToken, setSignedToken] = useState<string | null>(null)
  const [verifiedToken, setVerifiedToken] = useState<Token<Data> | null>(null)

  if (verifiedToken != null) {
    return <p>Verified token: {verifiedToken.payload.test}</p>
  }
  if (signedToken != null) {
    return (
      <button
        type="button"
        onClick={() => {
          verifyToken<Data>(signedToken).then(setVerifiedToken)
        }}
      >
        Verify token
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={() => {
        window.kokuin.sign({ test: 'OK' }).then(setSignedToken)
      }}
    >
      Sign token
    </button>
  )
}
```

- [ ] **Step 5: Write the Playwright `_electron` test**

Create `tests/e2e-electron/test/sign-verify.test.ts`:

```ts
import { _electron as electron, test } from '@playwright/test'

import { productName } from '../package.json'

function getAppPath() {
  switch (process.platform) {
    case 'darwin':
      return `out/${productName}-darwin-${process.arch}/${productName}.app/Contents/MacOS/${productName}`
    case 'linux':
      return `out/${productName}-linux-${process.arch}/${productName}`
    case 'win32':
      return `out/${productName}-win32-${process.arch}/${productName}.exe`
    default:
      throw new Error(`Unsupported platform: ${process.platform}`)
  }
}

const executablePath = getAppPath()

test('sign and verify token', async () => {
  const app = await electron.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  })
  const page = await app.firstWindow()
  await page.waitForLoadState('domcontentloaded')
  await page.getByText('Sign token').click()
  await page.getByText('Verify token').click()
  await page.getByText('Verified token: OK').waitFor()
  await app.close()
})
```

Also copy the playwright config (electron project, no webServer):

```bash
cp /Users/paul/dev/yulsi/enkaku/tests/e2e-electron/playwright.config.ts tests/e2e-electron/playwright.config.ts
```

- [ ] **Step 6: Fetch the gated electron binary, package, and test (run on macOS)**

```bash
pnpm rebuild electron        # runs electron's gated postinstall → fetches the binary
pnpm --filter e2e-electron exec playwright install chromium   # provides playwright driver deps
cd tests/e2e-electron && pnpm run package && pnpm run test; cd -
```
Expected: `electron-forge package` produces `out/e2e-electron-darwin-arm64/...`; `playwright test` reports `1 passed`. A failure on `Verified token: OK` means the IPC wiring is wrong — fix Steps 1–4.

- [ ] **Step 7: Commit**

```bash
git add tests/e2e-electron
git commit -m "test(e2e-electron): vanilla-IPC @kokuin/electron sign-verify"
```

---

### Task 8: Desktop e2e workflow

**Files:**
- Create: `.github/workflows/e2e-desktop.yml`

- [ ] **Step 1: Write the workflow (macOS + Windows, fetch gated electron binary)**

Create `.github/workflows/e2e-desktop.yml`:

```yaml
name: Desktop E2E
on:
  push:
    branches: [main]
  pull_request:
env:
  CI: true
  DO_NOT_TRACK: 1
jobs:
  test:
    name: on ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Setup environment
        uses: TairuFramework/kigu/setup@main
        with:
          node-version: 24

      - name: Cache electron binary
        uses: actions/cache@v4
        with:
          path: |
            ~/.cache/electron
            ~/AppData/Local/electron/Cache
          key: electron-${{ runner.os }}-${{ hashFiles('pnpm-lock.yaml') }}

      - name: Fetch electron binary
        run: pnpm rebuild electron

      - name: Package app
        working-directory: tests/e2e-electron
        run: pnpm run package

      - name: Run tests
        working-directory: tests/e2e-electron
        run: pnpm run test

      - name: Upload Playwright report
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-report-${{ matrix.os }}
          path: tests/e2e-electron/playwright-report/

      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: test-results-${{ matrix.os }}
          path: tests/e2e-electron/test-results/
```

- [ ] **Step 2: Validate**

Run: `actionlint .github/workflows/e2e-desktop.yml`
Expected: no output (exit 0).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/e2e-desktop.yml
git commit -m "ci(e2e-desktop): add electron e2e workflow (macos+windows)"
```

---

## Phase 3 — e2e-expo (`@kokuin/expo`)

### Task 9: Scaffold the trimmed expo e2e app

**Files:**
- Create: `tests/e2e-expo/package.json`
- Create: `tests/e2e-expo/app.json`
- Create: `tests/e2e-expo/tsconfig.json`
- Create: `tests/e2e-expo/.gitignore`
- Create: `tests/e2e-expo/index.ts`
- Create: `tests/e2e-expo/App.tsx`
- Create: `tests/e2e-expo/components/SignVerify.tsx`
- Create: `tests/e2e-expo/.maestro/sign-verify.yaml`
- Create: `tests/e2e-expo/assets/*` (copied from enkaku)

**Interfaces:**
- Produces: an Expo app rendering only `<SignVerify/>` (`@kokuin/expo` `provideFullIdentity` → sign → `@kokuin/token` `verifyToken`), with `@sozai/runtime-expo` `polyfillCrypto()` at entry. Maestro flow asserts `Verified token: OK`. App id `dev.kokuin.e2e`.

- [ ] **Step 1: Copy assets and the kept component/flow; do NOT copy native dirs**

```bash
mkdir -p tests/e2e-expo/components tests/e2e-expo/.maestro tests/e2e-expo/assets
cp /Users/paul/dev/yulsi/enkaku/tests/_ported/e2e-expo/assets/*           tests/e2e-expo/assets/
cp /Users/paul/dev/yulsi/enkaku/tests/_ported/e2e-expo/components/SignVerify.tsx tests/e2e-expo/components/SignVerify.tsx
cp /Users/paul/dev/yulsi/enkaku/tests/_ported/e2e-expo/.maestro/sign-verify.yaml tests/e2e-expo/.maestro/sign-verify.yaml
```

Do **not** copy `ios/`, `android/`, `.expo/`, `GroupEncryption.tsx`, or `group-e2ee.yaml`. `SignVerify.tsx` is kokuin-pure (imports `@kokuin/expo` + `@kokuin/token`) — leave it as-is.

- [ ] **Step 2: Set the kokuin app id in the maestro flow**

Edit `tests/e2e-expo/.maestro/sign-verify.yaml` — change the first line:

```yaml
appId: dev.kokuin.e2e
```

(Body stays: launchApp → tap "Sign token" → tap "Verify token" → assert "Verified token: OK".)

- [ ] **Step 3: Write `tests/e2e-expo/App.tsx` (only SignVerify)**

```tsx
import { StatusBar } from 'expo-status-bar'
import { StyleSheet, View } from 'react-native'

import SignVerify from './components/SignVerify'

export default function App() {
  return (
    <View style={styles.container}>
      <StatusBar style="auto" />
      <SignVerify />
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 10,
  },
})
```

- [ ] **Step 4: Write `tests/e2e-expo/index.ts` (keep crypto polyfill)**

```ts
import { polyfillCrypto } from '@sozai/runtime-expo'
import { registerRootComponent } from 'expo'

import App from './App'

polyfillCrypto()
registerRootComponent(App)
```

- [ ] **Step 5: Write `tests/e2e-expo/app.json`, `tsconfig.json`, `.gitignore`**

`app.json`:

```json
{
  "expo": {
    "name": "e2e-expo",
    "slug": "e2e-expo",
    "version": "1.0.0",
    "orientation": "portrait",
    "icon": "./assets/icon.png",
    "userInterfaceStyle": "light",
    "ios": {
      "supportsTablet": true,
      "bundleIdentifier": "dev.kokuin.e2e"
    },
    "android": {
      "adaptiveIcon": {
        "foregroundImage": "./assets/adaptive-icon.png",
        "backgroundColor": "#ffffff"
      },
      "predictiveBackGestureEnabled": false,
      "package": "dev.kokuin.e2e"
    }
  }
}
```

`tsconfig.json`:

```json
{
  "extends": "expo/tsconfig.base",
  "compilerOptions": {
    "strict": true
  }
}
```

`.gitignore`:

```gitignore
node_modules/
.expo/
dist/
web-build/
ios/
android/
*.log
.DS_Store
*.png.tmp
```

- [ ] **Step 6: Write `tests/e2e-expo/package.json` (drop @kumiai/mls; keep @sozai/runtime-expo)**

```json
{
  "name": "e2e-expo",
  "version": "1.0.0",
  "private": true,
  "main": "index.ts",
  "scripts": {
    "start": "expo start",
    "android": "expo run:android",
    "android:release": "expo run:android --no-bundler --variant release",
    "ios": "expo run:ios",
    "ios:release": "expo run:ios --no-bundler --configuration Release",
    "test": "MAESTRO_CLI_NO_ANALYTICS=true MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true maestro test .maestro/"
  },
  "dependencies": {
    "@kokuin/expo": "workspace:^",
    "@kokuin/token": "workspace:^",
    "@sozai/runtime-expo": "^0.1.0",
    "expo": "~56.0.0",
    "expo-status-bar": "~3.0.0",
    "react": "19.2.3",
    "react-native": "0.85.4"
  },
  "devDependencies": {
    "@types/react": "catalog:",
    "typescript": "catalog:"
  }
}
```

The `expo`/`expo-status-bar`/`react`/`react-native` versions above are provisional SDK-56 starting points; Step 7 pins them exactly via `expo install --fix`.

- [ ] **Step 7: Pin exact Expo SDK 56 versions via expo tooling**

```bash
pnpm install
cd tests/e2e-expo && pnpm exec expo install --fix; cd -
pnpm install
```
Expected: `expo install --fix` rewrites the four expo-managed versions in `tests/e2e-expo/package.json` to the SDK-56-correct values, then the second `pnpm install` relocks. Re-run `pnpm exec expo install --check` (in `tests/e2e-expo`) and confirm it reports no changes needed. If `--fix` flags `@types/react`, change it from `catalog:` to the explicit version it wants.

- [ ] **Step 8: Type-check the app**

Run: `cd tests/e2e-expo && pnpm exec tsc --noEmit; cd -`
Expected: no errors. (Imports resolve: `@kokuin/expo`, `@kokuin/token`, `@sozai/runtime-expo`, `expo`, `react-native`.)

- [ ] **Step 9: Commit**

```bash
git add tests/e2e-expo pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "test(e2e-expo): scaffold @kokuin/expo sign-verify (mls stripped, polyfill kept)"
```

---

### Task 10: Mobile e2e workflows (Android + iOS)

**Files:**
- Create: `.github/workflows/e2e-android.yml`
- Create: `.github/workflows/e2e-ios.yml`

**Interfaces:**
- Consumes: `tests/e2e-expo` `android:release` / `ios:release` build scripts + maestro `test` script from Task 9.

- [ ] **Step 1: Write the Android workflow**

Create `.github/workflows/e2e-android.yml`:

```yaml
name: Android E2E
on:
  push:
    branches: [main]
  pull_request:
env:
  CI: true
  DO_NOT_TRACK: 1
  MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED: true
  MAESTRO_CLI_NO_ANALYTICS: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Enable KVM
        run: |
          if [ -e /dev/kvm ]; then
            sudo mkdir -p /etc/udev/rules.d
            echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules
            sudo udevadm control --reload-rules
            sudo udevadm trigger --name-match=kvm
            sudo usermod -a -G kvm "$USER"
          else
            echo "KVM not available, continuing without hardware acceleration"
          fi

      - name: Setup environment
        uses: TairuFramework/kigu/setup@main
        with:
          node-version: 24

      - name: Cache Gradle
        uses: actions/cache@v4
        with:
          path: |
            ~/.gradle/caches
            ~/.gradle/wrapper
          key: gradle-${{ runner.os }}-${{ hashFiles('tests/e2e-expo/package.json') }}

      - name: Install Maestro
        shell: bash
        run: |
          curl -Ls "https://get.maestro.mobile.dev" | bash
          echo "$HOME/.maestro/bin" >> "$GITHUB_PATH"

      - name: Create and boot emulator
        run: |
          export ANDROID_AVD_HOME=$HOME/.config/.android/avd
          export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools
          echo y | sdkmanager "system-images;android-36;google_apis;x86_64"
          echo no | avdmanager create avd --force -n test-emulator --abi 'google_apis/x86_64' --package 'system-images;android-36;google_apis;x86_64'
          "$ANDROID_HOME/emulator/emulator" -avd test-emulator -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -memory 4096 -no-snapshot-save &
          adb wait-for-device
          timeout 300 bash -c 'while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d "\r")" != "1" ]; do sleep 5; done'
          adb shell settings put global window_animation_scale 0
          adb shell settings put global transition_animation_scale 0
          adb shell settings put global animator_duration_scale 0

      - name: Build Android app
        working-directory: tests/e2e-expo
        run: pnpm run android:release

      - name: Run Maestro tests
        working-directory: tests/e2e-expo
        run: pnpm run test

      - name: Upload screenshots on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: maestro-screenshots-android
          path: "*.png"
```

- [ ] **Step 2: Write the iOS workflow**

Create `.github/workflows/e2e-ios.yml`:

```yaml
name: iOS E2E
on:
  push:
    branches: [main]
  pull_request:
env:
  CI: true
  DO_NOT_TRACK: 1
  MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED: true
  MAESTRO_CLI_NO_ANALYTICS: true
jobs:
  test:
    runs-on: macos-26
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Setup environment
        uses: TairuFramework/kigu/setup@main
        with:
          node-version: 24

      - name: Cache CocoaPods
        uses: actions/cache@v4
        with:
          path: |
            ~/Library/Caches/CocoaPods
            tests/e2e-expo/ios/Pods
          key: pods-${{ runner.os }}-${{ hashFiles('tests/e2e-expo/package.json') }}

      - name: Install Maestro
        shell: bash
        run: |
          curl -Ls "https://get.maestro.mobile.dev" | bash
          echo "$HOME/.maestro/bin" >> "$GITHUB_PATH"

      - name: Build iOS app
        working-directory: tests/e2e-expo
        run: pnpm run ios:release

      - name: Run Maestro tests
        working-directory: tests/e2e-expo
        run: pnpm run test

      - name: Upload screenshots on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: maestro-screenshots-ios
          path: "*.png"
```

- [ ] **Step 3: Validate both workflows**

Run: `actionlint .github/workflows/e2e-android.yml .github/workflows/e2e-ios.yml`
Expected: no output (exit 0).

- [ ] **Step 4: (Optional, macOS local) smoke-build the iOS app**

Run: `cd tests/e2e-expo && pnpm run ios; cd -`
Expected: `expo prebuild` regenerates `ios/`, the app builds and launches in the iOS Simulator showing a "Sign token" button. This is slow (Pods install + xcodebuild); skip if iterating quickly — CI is the source of truth. Discard the generated `ios/` (gitignored).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/e2e-android.yml .github/workflows/e2e-ios.yml
git commit -m "ci(e2e-mobile): add android + ios maestro e2e workflows"
```

---

## Self-Review

**Spec coverage:**
- Part 1 base CI → Task 1. ✅
- Part 2 web/electron/expo apps reduced to kokuin scope → Tasks 3–4 (web), 6–7 (electron, vanilla IPC, `@enkaku` stripped), 9 (expo, `@kumiai/mls` stripped, `@sozai/runtime-expo` kept). ✅
- Part 3 e2e workflows (web/desktop/android/ios, kigu/setup, PR+main) → Tasks 5, 8, 10. ✅
- Part 4 workspace plumbing (`tests/*` glob, catalog merge, script-name separation) → Task 2 + each app's package.json. ✅
- Install-weight Lever 1 (electron postinstall gating via `allowBuilds`) → Task 2 Step 1 + Task 7 Step 6 / Task 8. Lever 2 (pnpm store cache via kigu/setup) → implicit in every e2e workflow's setup step. Lever 3 (Playwright/electron/Gradle/Pods caches) → Tasks 5, 8, 10. ✅
- Open notes: kigu/setup pnpm cache assumed; electron binary fetched post-gate (Task 7/8); Expo pins via `expo install --check` (Task 9 Step 7); tsconfig bases adapted (web uses self-contained configs, expo extends `expo/tsconfig.base`, electron self-contained). ✅

**Placeholder scan:** No "TBD/TODO/handle edge cases". The one deferred value (Expo SDK 56 pins) has an explicit resolution step (Task 9 Step 7) with the command that produces the values. ✅

**Type consistency:** `window.kokuin.sign(payload, keyID?) => Promise<string>` declared identically in `preload.ts`, `global.d.ts`, and consumed in `App.tsx` (Task 7). `provideFullIdentityAsync('KokuinKeystore', keyID ?? 'test')` matches the verified export signature. `verifyToken` / `stringifyToken` / `Token` / `provideSigningIdentity` / `provideFullIdentity` all match exports confirmed during brainstorming. ✅
