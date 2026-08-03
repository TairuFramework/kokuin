# Speed up e2e-web Playwright runs in CI

**Origin:** review of kigu's reusable `e2e-web` workflow against
https://endform.dev/blog/playwright-github-actions. The workflow-side caching is
already optimal (browsers cached, keyed on Playwright version). The remaining
wins live in this repo's `tests/e2e-web/playwright.config.ts`, not in kigu.
**Priority:** medium. Pure CI wall-clock; no behavior change.

## What

`tests/e2e-web/playwright.config.ts` currently throttles CI to a single worker:

```ts
fullyParallel: true,                        // already set
workers: process.env.CI ? 1 : undefined,    // forces ONE worker in CI
reporter: 'html',
```

`fullyParallel: true` is set but neutralized by `workers: 1` — no test-level
parallelism happens in CI. Change:

```ts
workers: process.env.CI ? '50%' : undefined,
reporter: process.env.CI ? [['html'], ['github']] : 'html',
```

- `workers: '50%'` scales to runner cores (2–4x on GitHub runners) instead of 1.
- The `github` reporter writes failures as inline annotations in the Actions UI,
  no artifact download needed. Keep `html` for the uploaded report.

## Watch out

- Verify tests are actually isolated before raising worker count — shared state
  (fixed ports, shared temp dirs, a single dev server, identity/keystore files)
  can flake under real parallelism. `fullyParallel` was on but never exercised in
  CI, so this is the first real concurrency. Fix isolation, don't just lower the
  count back.
- `'50%'` is a string literal — Playwright rejects a bare `50%`.
- Measure wall-clock before/after; don't assume. On a 2-core private runner 50%
  = 1 worker (no change) — bump to a larger runner or a fixed count if so.

## Not doing (yet)

- **Chromium-only on PRs, full 3-browser suite on main.** Config has chromium +
  firefox + webkit projects, all run every push. Cuts PR test count ~2/3 but
  needs an event-aware project filter and the caller passing the event into the
  reusable workflow — larger change, separate item.
- **Sharding.** Only worth it if one optimized runner can't finish in the PR
  window. Suite is small (15-min timeout, comfortably under); revisit only if it
  grows past ~5 min after the above.

## Applies to sibling repos too

Same `workers: 1` pattern is in every repo instantiating `e2e-web` (kokuin
confirmed). Roll the same edit across them, or lift a shared Playwright preset
into kigu so the config isn't copy-pasted per repo.
