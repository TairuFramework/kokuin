# kokuin CI + e2e coverage — design

Date: 2026-06-23
Status: approved (design), pending implementation plan

## Goal

Add GitHub Actions CI to `kokuin`, mirroring `sozai`'s setup, plus end-to-end
coverage for the three platform keystore packages: `@kokuin/browser` (web),
`@kokuin/electron` (desktop), and `@kokuin/expo` (mobile). Tests are adapted
from `enkaku`'s e2e suites, reduced to **kokuin-only scope** — any code that is
purely `@enkaku` / `@kumiai` / `@sozai` is stripped, not ported.

## Non-goals

- Ledger / Speculos test import (deferred; the firmware lives in `apps/ledger`
  but is out of scope for this round).
- Porting `@enkaku`, `@kumiai`, or `@sozai`-specific test code.
- The `tests/integration` enkaku suite (it exercises `@enkaku` client/server;
  only incidentally touches `@kokuin/capability`+`token`).

## Part 1 — Base CI (mirror sozai)

Single file `.github/workflows/build-test.yml`, identical pattern to sozai —
delegates to the shared kigu reusable workflow:

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

Runs (Node 24 + 26): pnpm setup → build → `pnpm lint` → `pnpm test`
(`turbo run test:types test:unit` across `packages/*`) → TS-7 readiness check.
No `integration-tests-dir`. Trigger is already "PR + main".

Nothing is copied from `enkaku/.github`: enkaku's local `setup-environment`
action and inline `build-test.yml` are the hand-rolled predecessor of this same
kigu reusable workflow. kokuin (structurally identical to sozai) matches sozai.

## Part 2 — Three e2e apps under `tests/`, reduced to kokuin scope

Each app exercises exactly one keystore package + `@kokuin/token`
(sign a token in the keystore, verify it).

Scope rule follows the stack layering (kigu `repo-split-design.md`):
`@sozai ← @kokuin ← @enkaku ← @kumiai`, deps strictly downward, no cycles.

- **`@enkaku` / `@kumiai` deps are forbidden, not just out-of-scope** — they sit
  *above* `@kokuin` (enkaku already depends on `@kokuin/token`), so importing
  them from a kokuin test is an upward dep / cycle. Stripping enkaku IPC and
  kumiai mls is mandatory.
- **Any `@sozai` dep is allowed** — sozai sits *below* `@kokuin` (downward). Keep
  the ones the kokuin stack genuinely needs at runtime (e.g.
  `@sozai/runtime-expo`'s crypto polyfill). We just add no explicit coverage
  *for* sozai itself.

Maps:

| app                | keystore under test                  | stripped (other scope)                                            |
| ------------------ | ------------------------------------ | ----------------------------------------------------------------- |
| `tests/e2e-web`      | `@kokuin/browser` + `@kokuin/token`  | nothing — already kokuin-pure                                     |
| `tests/e2e-electron` | `@kokuin/electron` + `@kokuin/token` | all `@enkaku/*` (client/server/transport/protocol/electron IPC)   |
| `tests/e2e-expo`     | `@kokuin/expo` + `@kokuin/token`     | `@kumiai/mls`, `GroupEncryption` component                         |

Exports confirmed present in current kokuin packages: `provideSigningIdentity`
(browser), `provideFullIdentityAsync` (electron), `provideFullIdentity` (expo),
`stringifyToken` / `verifyToken` / `Token` / `SignedToken` (token).

### `tests/e2e-web`

Near-verbatim port from `enkaku/tests/e2e-web` (already kokuin-pure). Stack:
Vite + `react-native-web` + Playwright (chromium / firefox / webkit). In-page
flow: `provideSigningIdentity('test')` → `signToken({test:'OK'})` →
`verifyToken(...)` → asserts `Verified token: OK`. Files: `package.json`,
`vite.config.ts`, `playwright.config.ts`, `index.html`, `tsconfig*.json`,
`src/{App.tsx,main.tsx}`, `test/sign-verify.spec.ts`.

### `tests/e2e-electron`

Port from `enkaku/tests/e2e-electron`, but **rewrite the IPC layer to vanilla
electron** — drop `@enkaku/{client,server,electron,transport,protocol}`.

- `src/main.ts`: register one `ipcMain.handle('sign', ...)` that calls
  `provideFullIdentityAsync('KokuinKeystore', keyID ?? 'test')`, then
  `.signToken(payload)`, returns `stringifyToken(token)`. (Service name
  `EnkakuKeystore` → `KokuinKeystore`.) Keep the BrowserWindow / forge bits.
- `src/preload.ts`: `contextBridge.exposeInMainWorld('kokuin', { sign })`
  bridging to `ipcRenderer.invoke('sign', ...)`. Drop the `@enkaku/electron` and
  `react-native-electron` preload imports unless RN UI is retained (see below).
- `src/App.tsx`: call `window.kokuin.sign(...)` instead of the enkaku renderer
  client; verify with `@kokuin/token`.
- Drop `src/protocol.ts` (enkaku `ProtocolDefinition`).
- Keep electron-forge + Vite config + Playwright `_electron` test
  (`test/sign-verify.test.ts`) which launches the packaged app and drives the
  same Sign → Verify → assert flow.

UI: retain `react-native` + `react-native-web`/`react-native-electron` to match
the web app, OR simplify the renderer to plain `react-dom` (fewer deps). Either
is acceptable; default to plain `react-dom` for the electron renderer since the
IPC is already being rewritten and RN adds no test value here. (Final call at
implementation time; favor the lighter option.)

### `tests/e2e-expo`

Port from `enkaku/tests/_ported/e2e-expo`, keep only the `SignVerify` path:

- Keep `components/SignVerify.tsx` (`provideFullIdentity('test')` → sign →
  verify with `@kokuin/token`). **Delete** `components/GroupEncryption.tsx`.
- `App.tsx`: render only `<SignVerify/>` (+ `StatusBar`).
- `index.ts`: **keep** `polyfillCrypto()` from `@sozai/runtime-expo` — it
  installs `globalThis.crypto.getRandomValues` (via `expo-crypto`), which the
  `@noble/*` primitives inside `@kokuin/expo`/`@kokuin/token` require under
  Hermes. This is mls-independent; without it keystore signing throws.
- `package.json`: drop only `@kumiai/mls`; **keep** `@sozai/runtime-expo`
  (runtime polyfill, see above) plus `@kokuin/expo`, `@kokuin/token`, `expo`,
  `expo-status-bar`, `react`, `react-native`.
- `.maestro/`: keep `sign-verify.yaml`; delete `group-e2ee.yaml`. Change
  `appId: dev.enkaku.e2e` → a kokuin app id (e.g. `dev.kokuin.e2e`); update
  `app.json` slug/scheme to match.
- **Do not commit generated native dirs** (`ios/`, `android/`, Pods, Gradle).
  CI regenerates them via `expo prebuild` (`expo run:ios` / `run:android`).

## Part 3 — e2e CI workflows

Separate from build-test. Each uses `TairuFramework/kigu/setup@main` (not a
vendored `setup-environment` action — keeps kokuin consistent with sozai). All
trigger `pull_request` + `push: branches: [main]` (PR + main only).

- `e2e-web.yml` — `ubuntu-latest`: setup → `playwright install --with-deps` →
  build app → `playwright test` → upload `playwright-report/` artifact.
- `e2e-desktop.yml` — matrix `[macos-latest, windows-latest]`: setup →
  fetch electron binary (see Lever 1) → `electron-forge package` →
  `playwright test` (`_electron`) → upload report/results/screenshots on failure.
- `e2e-android.yml` — `ubuntu-latest` + timeout 30m: enable KVM → create/boot
  AVD (android-36, google_apis x86_64) → setup → install Maestro →
  `expo run:android --variant release` → `maestro test .maestro/` → upload
  screenshots on failure.
- `e2e-ios.yml` — `macos-26` + timeout 30m: setup → install Maestro →
  `expo run:ios --configuration Release` → `maestro test .maestro/` → upload
  screenshots on failure.

Maestro env on the mobile jobs: `MAESTRO_CLI_NO_ANALYTICS=true`,
`MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true`.

## Part 4 — Workspace plumbing

- `pnpm-workspace.yaml`: add `tests/*` to `packages`.
- Merge catalog entries from enkaku (exact versions): `react` 19.2.3,
  `react-dom` 19.2.3, `react-native-web` 0.21.2, `@playwright/test` 1.61.0,
  `vite` ^8.0.16, `@vitejs/plugin-react` ^6.0.2, `@electron-forge/cli` ^7.11.2,
  `@electron-forge/plugin-vite` ^7.11.2, `@types/react` ^19.2.17,
  `@types/react-dom` ^19.2.3. `electron` (^42.4.1), `@types/node`, `typescript`
  already covered. Add `react-native-electron` ^0.22.1 **only if** the electron
  renderer keeps RN UI (dropped under the default plain-`react-dom` renderer).
- **Expo SDK 56 deps** are NOT in enkaku's catalog (its `_ported` expo app was
  never installed). Add `expo` (~56.x), `expo-status-bar`, and `react-native`
  (0.85.x — per the Expo SDK 56 lockfile) pinned to SDK-56-compatible versions;
  resolve exact pins via `expo install --check`.
- e2e packages use scripts `test` / `build` / `start` — **not**
  `test:unit` / `test:types` / `build:js` — so turbo's base CI tasks never run
  them. They fire only in their own workflows. Clean separation.

## Install-weight mitigations (baked in)

Adding e2e apps to the workspace means `pnpm install` in build-test also sees
react/electron/expo/playwright. Three levers keep build-test lean without
forking the kigu reusable workflow (which runs a fixed
`pnpm install --frozen-lockfile`, no filter flag):

1. **Skip native binary postinstalls in the shared install.** The heavy item is
   `electron`'s postinstall (~100MB+ binary). kokuin already gates postinstalls
   via `allowBuilds` in `pnpm-workspace.yaml` (only `@swc/core` runs). Keep
   `electron` (and any expo native-fetching dep) OFF `allowBuilds` → pnpm skips
   the binary during the shared install. The `e2e-desktop` workflow fetches it
   explicitly (`pnpm rebuild electron` / approve-builds step) where it is needed.
2. **pnpm store cache, shared across workflows.** GitHub Actions cache is keyed
   per repo, not per workflow. `kigu/setup@main` uses `cache: 'pnpm'`
   (lockfile-keyed), so e2e deps download once per lockfile change and the store
   is restored on every later build-test + e2e run. Confirm kigu/setup enables
   it; if not, add an explicit `actions/cache` step for `~/.pnpm-store` in the
   e2e workflows.
3. **Targeted binary caches in the e2e workflows** (the real time sink, dwarfing
   install): Playwright browsers (`~/.cache/ms-playwright`), electron binary
   (`~/.cache/electron`), Gradle (`~/.gradle/caches`, `~/.gradle/wrapper`) + AVD
   snapshot for android, CocoaPods (`~/Library/Caches/CocoaPods`, `ios/Pods`)
   for ios. Key each by tool/lockfile version.

### Deferred fallback (do not build unless needed)

If build-test install is still too heavy: give `tests/` its own pnpm workspace +
lockfile, depending on local packages via `link:` instead of `workspace:`,
installed only in the e2e workflows. Fully removes e2e deps from build-test, at
the cost of a second lockfile and `link:` resolution. Documented escape hatch.

## Suggested kigu improvements (separate, optional)

kigu is meant to own the full-stack CI story, so the e2e workflows authored here
are candidates to fold back upstream. Out of scope for this change, but worth
filing against kigu:

1. **Reusable e2e workflows in kigu** — `e2e-web.yml`, `e2e-desktop.yml`,
   `e2e-mobile.yml` (android/ios), parameterized by `working-directory` (+ the
   browser/binary cache steps). kokuin's e2e workflows then collapse to ~5-line
   `uses:` calls, like build-test, and the caching logic is maintained once
   across kokuin / enkaku / sozai instead of copy-pasted.
2. **Install knobs on the reusable build-test / `kigu/setup`** — an
   `install-filter` input (passes pnpm `--filter`) and/or an `allow-builds`
   passthrough, so consumers can do lean installs generically instead of relying
   on `allowBuilds` tricks. This directly solves the "skip tests/* deps in the
   fast lane" need that currently can't be expressed against the reusable
   workflow.
3. **Cache passthrough on `kigu/setup`** — opt-in inputs for Playwright /
   electron binary caching, since those are recurring full-stack concerns.

These are framed as kigu enhancements; kokuin ships the vendored workflows now
and migrates to reusable calls if/when kigu gains them.

## Open implementation notes

- Confirm `kigu/setup@main` enables `cache: 'pnpm'` (assumed; add explicit cache
  step if not).
- `e2e-desktop` must trigger the electron binary fetch after the gated install
  (since `electron` is off `allowBuilds`).
- Pin exact Expo SDK 56 versions via `expo install --check`.
- Adjust ported tsconfigs whose `extends` pointed at enkaku paths
  (`../../tsconfig.build.json`) to kokuin's base (`@kigu/dev/tsconfig.json`).
