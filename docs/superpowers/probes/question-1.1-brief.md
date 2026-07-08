# Probe brief — Question 1.1 (NBGL rewrite)

## Question
Does the async consent gate defer signing to an Approve callback? (SIGN only.)

## Framework decision (already made — do NOT re-litigate)
Nano uses **NBGL**, not BAGL. BAGL `ux_flow` segfaults Speculos (signal 11) on this SDK
(API_LEVEL_26). A prior probe proved this and proved the toolchain is healthy via the
LedgerHQ boilerplate positive control. **Build with `ENABLE_NBGL_FOR_NANO_DEVICES = 1`
and use `nbgl_use_case.h`.** Do not attempt BAGL / `ux_flow` / `UX_STEP`.

There is uncommitted BAGL code from the prior probe in the working tree
(`src/ui/display.{c,h}`, plus edits to `sign_message.{c,h}`, `crypto.{c,h}`, `types.h`).
**Rewrite `src/ui/display.c` for NBGL.** The `sign_message.c` / `crypto.c` / `types.h`
changes (non-static `sign_approved`/`sign_rejected`, `digest_sha256`, `message_digest`
field, deferred handoff) are mostly reusable — keep what fits, fix what doesn't.

## Reference implementation (READ THIS FIRST)
LedgerHQ app-boilerplate, NBGL review, cloned at:
`/private/tmp/claude-501/-Users-paul-dev-yulsi-kokuin/5016f4cf-1720-45ab-aced-f9300d5a5c09/scratchpad/app-boilerplate/`
- `src/ui/nbgl_display_transaction.c` — the exact pattern: static
  `nbgl_contentTagValue_t pairs[]` + `nbgl_contentTagValueList_t pairList`, a
  `review_choice(bool confirm)` callback, `nbgl_useCaseReview(TYPE_TRANSACTION, &pairList,
  &icon, review_text, NULL, sign_text, review_choice)` which returns immediately (0), and
  `nbgl_useCaseReviewStatus(STATUS_TYPE_..., ui_menu_main)` on completion.
- `src/ui/menu_nbgl.c` — home screen / `ui_menu_main` NBGL pattern.
- `Makefile` line ~101 — `ENABLE_NBGL_FOR_NANO_DEVICES = 1`.
NBGL reads the pair strings asynchronously, so the value buffers MUST be static/global,
not stack.

## Repo context
- Firmware: `apps/ledger` (BOLOS, Nano S+ — Speculos `--model nanosp`).
- Build/test: `./tests/ledger/test-speculos.sh --build` builds via
  `apps/ledger/docker-compose.yml` (`build` service, SDK `$NANOSP_SDK`), starts Speculos,
  runs `tests/ledger/test/speculos.test.ts`. `--keep` leaves Speculos up. Speculos REST
  API on host port 9999 (container 5000): `/apdu`, `/button/{left,right,both}`,
  `/automation`, `/events?currentscreenonly=true`, screenshots.
- Follow `kigu:conventions` + existing `apps/ledger` style. **Conventions rule: code,
  comments, and test names must NEVER reference plan questions / decision numbers / phase
  labels (no `// Q1.1:`). Capture the invariant directly.** Do not edit generated `lib/`.

## Current firmware state (read these)
- `apps/ledger/src/sign_message.c` — `handler_sign_message`; `sign_approved()` /
  `sign_rejected()` do crypto + `io_send_response*` / `io_send_sw`. Prior probe already
  made them non-static and moved the call site — verify and keep.
- `apps/ledger/src/menu.c` — `ui_menu_main()` (currently `UX_INIT()` only; may need an
  NBGL home screen like the boilerplate's `ui_menu_main` for Speculos to have an idle
  screen — mirror the boilerplate).
- `apps/ledger/src/app_main.c` — loop calls `io_recv_command()` then `apdu_dispatcher()`.
- `apps/ledger/src/crypto.{c,h}`, `types.h`, `dispatcher.c`, `constants.h`, `Makefile`.
- App icon: find the existing glyph (check `apps/ledger/glyphs` / `icons` / how `menu.c`
  or generated `glyphs.h` names it) and use it in the review, like `ICON_APP_BOILERPLATE`.

## Approved approach
1. `apps/ledger/Makefile`: add `ENABLE_NBGL_FOR_NANO_DEVICES = 1` (see boilerplate).
2. Rewrite `src/ui/display.c` (keep `src/ui/display.h` exposing `void ui_display_sign(void)`):
   NBGL review. Static `nbgl_contentTagValue_t pairs[2]` = {Account = `m/44'/876'/n'` via
   `bip32_path_format`, Digest = 64 hex of SHA-256(message)} into static char buffers.
   `nbgl_useCaseReview(...)` with a `review_choice(bool confirm)` callback that runs
   `sign_approved()` on confirm / `sign_rejected()` on reject, then
   `nbgl_useCaseReviewStatus(..., ui_menu_main)`.
3. Keep `digest_sha256(const uint8_t *in, size_t len, uint8_t out[32])` in `crypto.{c,h}`.
4. `handler_sign_message`: at both final-chunk paths (first-chunk `p2 != P2_MORE`, and
   `P2_LAST` continuation), compute the digest, call `ui_display_sign()`, `return 0`
   with NO status word. No inline `sign_approved()`.
5. If `ui_menu_main()` must become an NBGL home screen for Speculos to boot to an idle
   screen, mirror the boilerplate `menu_nbgl.c` (`nbgl_useCaseHomeAndSettings` or the
   simple home). Keep it minimal.

**Scope: SIGN only.** Do not touch ECDH. Do not add the `req_type` reset (separate
question) — but do not break the existing continuation guard.

## If the approach fails
Stop at the first failure and report **BLOCKED** with the exact compiler/emulator output.
Difficulty is the finding. Do not fall back to BAGL. Do not restructure the main loop.

## Verify
Run: `./tests/ledger/test-speculos.sh --build --keep`
- Confirm the firmware **builds** (build service, no errors).
- With Speculos up, send a SIGN APDU and confirm the NBGL review renders (text via
  `curl -s "localhost:9999/events?currentscreenonly=true"` — you should see the account
  path + digest as text events, like the boilerplate showed "Boilerplate / app is ready"),
  then drive Approve (navigate + confirm via `/button/*` or an `/automation` ruleset) and
  confirm a 64-byte signature + SW 0x9000.
- Test APDU (single-chunk SIGN, `m/44'/876'/0'`, message `"hello"`):
  `e003000012038000002c8000036c8000000068656c6c6f`
  expected digest = sha256("hello") =
  `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`.
- Paste the ACTUAL build output and the APDU/screen interaction (raw curl output).
- Pre-existing sign tests may now hang waiting for approval — expected, handled later.
  Build success + a manual Approve round-trip is the bar.

## Report contract
Overwrite `docs/superpowers/probes/question-1.1-report.md`:
- Confirm NBGL build works (`ENABLE_NBGL_FOR_NANO_DEVICES`), files changed each with a
  one-line description, the build output, and the manual Approve round-trip evidence
  (pasted: rendered screen text + signature + SW).
- Any concerns / surprises.
Then return ONLY: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), files
changed, a one-line verify summary, and concerns. Do NOT commit.
