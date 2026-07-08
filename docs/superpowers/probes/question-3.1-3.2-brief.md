# Probe brief — Questions 3.1 + 3.2 (Speculos auto-approval + reject/stale tests)

TypeScript test-harness work in `tests/ledger/`. The firmware consent gates are landed
and verified (SIGN + ECDH now require on-device Approve). Two coupled deliverables:

- **Q3.1:** make the existing suite pass **unattended** — the harness must auto-approve
  the NBGL review screens so `signToken` / `agreeKey` / `decrypt` / token cross-compat
  tests (which now block on a button prompt) go green without manual input.
- **Q3.2:** add three new negative tests — SIGN reject → `0x6985`, ECDH reject →
  `0x6985`, stray continuation after a completed sign → `0x6A80`.

## Current harness (read first)
- `tests/ledger/test/speculos.test.ts` — the whole suite. `createSpeculosTransport()`
  POSTs to `${SPECULOS_URL}/apdu` and **awaits the response synchronously**. For SIGN/ECDH
  that POST now blocks until the device is approved. The transport's comment claims it
  "auto-approves", but nothing actually presses buttons — that is the Q3.1 gap. The
  transport also `throw`s on any `sw !== 0x9000`, so reject tests (which expect `0x6985`)
  need a variant that returns/exposes the status word instead of throwing.
- `tests/ledger/test-speculos.sh` — build + `up -d speculos` + `vitest`. Speculos REST API
  on `http://127.0.0.1:9999` (env `SPECULOS_URL`): `/apdu`, `/button/{left,right,both}`,
  `/automation`, `/events?currentscreenonly=true`.
- Tests currently: version / pubkey / cross-compat DID pass; `signToken`, `agreeKey`,
  `decrypt`, and any token-signing cross-compat test now hang on approval.

## Q3.1 — auto-approval
- Preferred mechanism: post a Speculos **`/automation`** ruleset that drives the NBGL
  review to Approve automatically whenever a review screen appears (advance pages with a
  right-press as needed, press both on the confirm page). Confirm-page text is
  **"Sign message"** (SIGN) and **"Agree key"** (ECDH); intermediate pages include
  "Review message" / "Review key agreement" / "Account" / "Digest" / "Peer key". Do NOT
  match the idle home ("Kokuin" / "app is ready").
- Determine the exact working ruleset/format empirically against the running emulator —
  the NBGL-on-Nano automation format is the integration unknown this question resolves. If
  a global automation ruleset can't cleanly express "advance then confirm", an alternative
  is to fire the `/apdu` POST without awaiting, poll `/events`, and drive `/button` to
  approve, then read the response — but a `/automation` ruleset is cleaner if it works.
- **Done when:** `./tests/ledger/test-speculos.sh --build` runs the **full** suite green,
  unattended, no manual button presses.

## Q3.2 — negative tests (add to `speculos.test.ts`)
- **SIGN reject → 0x6985:** drive the SIGN review to "Reject message" (a distinct
  automation rule, or button-driving) and assert SW `0x6985`, no data.
- **ECDH reject → 0x6985:** drive the ECDH review to "Reject operation", assert `0x6985`.
- **Stale continuation → 0x6A80:** after a completed (approved) sign, send a **1-byte**
  continuation `e00380000141` (`CLA=e0 INS=03 P1=0x80 P2=0x00 Lc=01 data=0x41`) and assert
  SW `0x6A80`. **Do NOT use a bare `Lc=00` continuation** — `dispatcher.c`'s length guard
  rejects that earlier with `0x6700`, never reaching the `req_type` guard (verified).
- These need a transport/helper that returns the status word rather than throwing on
  non-9000. Reuse `INS` / `CLA` / `encodeDerivationPath` from `@kokuin/ledger-device`
  where possible; the raw continuation APDU can be posted directly to `/apdu`.
- The approve and reject flows need different automation; manage the ruleset per-test
  (post the approve ruleset for the green suite, swap to a reject ruleset for reject
  tests, and restore) or drive buttons directly for the negative cases. Keep it robust to
  test ordering.

## Conventions (TypeScript)
`kigu:conventions`: `type` not `interface`; `Array<T>` not `T[]`; never `any`; capital
`ID`/`HTTP`/`JWT`; ES `#fields`. **No test name / comment may reference a plan question /
decision / phase number.** Do not edit generated `lib/`. Machine note: an `rtk` shim
hijacks `pnpm run <script>` — run repo scripts as `rtk proxy pnpm run <script>` or invoke
tools directly (`pnpm exec biome …`, `pnpm exec vitest …`).

## Verify
- `./tests/ledger/test-speculos.sh --build` — full suite green unattended (paste the
  vitest summary showing all tests passed, including the 3 new ones).
- `pnpm exec biome check tests/ledger` — clean.
- `pnpm exec tsc -p tests/ledger/tsconfig.json --noEmit` — clean.
Paste ACTUAL output for all three.

## If it fails
Stop at the first hard failure, report **BLOCKED** with exact output (e.g. if the NBGL
automation format won't drive approval, show what you tried and the emulator response).
Difficulty is the finding.

## Report contract
Write `docs/superpowers/probes/question-3.1-3.2-report.md`: how auto-approval was achieved
(the working automation ruleset/approach), the new tests added, the full green vitest
summary, and biome/tsc output. Then return ONLY: status (DONE / DONE_WITH_CONCERNS /
NEEDS_CONTEXT / BLOCKED), files changed, one-line verify summary, concerns. Do NOT commit.
