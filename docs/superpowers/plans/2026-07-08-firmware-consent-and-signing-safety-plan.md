# Firmware consent and signing safety — plan

**Stage:** executing
**Mode:** learning-loop
**Spec:** docs/superpowers/specs/2026-07-08-firmware-consent-and-signing-safety-design.md

Each probe validates one assumption against the real firmware running in Speculos.
Firmware C + BOLOS async UX + emulator carry integration unknowns (NBGL `nbgl_use_case`
review API, async handoff correctness, Speculos automation format) — that is why
this runs as a learning loop, not a task list.

**Framework resolved (see Decision Log Q1.1a):** Nano uses **NBGL**, not BAGL — BAGL
`ux_flow` segfaults Speculos on this SDK. Build with `ENABLE_NBGL_FOR_NANO_DEVICES = 1`
and use `nbgl_use_case.h`.

**Verify command (all questions unless noted):** from repo root
`./tests/ledger/test-speculos.sh --build` — builds the firmware (requires the ledger Docker
toolchain / `BOLOS_SDK`) and runs the Speculos suite. Paste actual output. For
TypeScript-only changes also run `pnpm exec biome check tests/ledger` and
`pnpm exec tsc -p tests/ledger/tsconfig.json --noEmit`.

If any probe contradicts the design (e.g. this SDK exposes NBGL-on-Nano, not BAGL, or
the async handoff needs loop restructuring): **stop, update the spec, then continue.**
Do not work around a design problem in code.

---

## Phase 1: SIGN consent gate + review display

Exit criteria: a SIGN_MESSAGE APDU (single- and multi-chunk) shows an on-device review
flow (account path + full SHA-256 digest, paginated); Approve produces the same 64-byte
signature as before; Reject returns `SW_USER_REJECTED`; no signature is emitted without
Approve; `req_type` is reset so a stale continuation chunk is rejected.

### Question 1.1: Does the async consent gate defer signing to an Approve callback?

- **Assumption:** the SIGN handler can compute the message digest, hand off to an NBGL
  `nbgl_use_case` review, and `return 0` without sending a status word; the Approve
  callback then runs the existing `sign_approved()` (unchanged crypto + `io_send_response`)
  and returns to idle via `ui_menu_main()`. The `app_main` loop's `io_recv_command()` pumps
  the seproxyhal/UX events — no loop restructuring needed.
- **Done when:**
  - New `src/ui/display.{c,h}` renders a SIGN review via `nbgl_use_case`: title
    "Review message to sign", tag/value list (Account `m/44'/876'/n'` via
    `bip32_path_format`, Digest = SHA-256(message) full 64 hex), Approve / Reject.
  - `handler_sign_message` no longer calls `sign_approved()` inline; the final-chunk path
    (both `p2 != P2_MORE` first-chunk and `P2_LAST` continuation) calls
    `ui_display_sign()` and returns 0 with no SW.
  - New `digest_sha256(in, len, out[32])` helper wrapping `cx_hash_sha256`.
  - Approve path yields the identical signature the existing Speculos sign tests expect
    (auto-approval from Q3.1 may be needed to see this pass green; until then, validate
    via `--keep` + manual button press).
  - `apps/ledger/Makefile` sets `ENABLE_NBGL_FOR_NANO_DEVICES = 1`; UI uses
    `nbgl_use_case.h`.
- **Spec excerpt:** "Handler parses the path, accumulates the message / stores the
  ephemeral key (unchanged), then computes the display digest and calls a UI entry point
  (`ui_display_sign()` / `ui_display_ecdh()`), and `return 0` without sending any status
  word... The main loop in `app_main.c` already calls `io_recv_command()` each iteration,
  which pumps UX button events... For multi-chunk SIGN, the gate fires only at the final
  chunk, once the whole message is assembled and hashed."
- **Verify:** `./tests/ledger/test-speculos.sh --build --keep`, then drive Speculos manually /
  via automation to Approve and confirm signature matches.

### Question 1.2: Does Reject return `SW_USER_REJECTED`?

- **Assumption:** the Reject step calls the existing `sign_rejected()`, which scrubs the
  message buffer and sends `SW_USER_REJECTED` (0x6985); no signature is emitted.
- **Done when:** a SIGN APDU driven to Reject returns 0x6985 and no response data; the
  message buffer is zeroed (`explicit_bzero`, already present).
- **Spec excerpt:** "Reject callback → `sign_rejected()` / `ecdh_rejected()` (already
  exist; send `SW_USER_REJECTED`), then idle."
- **Verify:** covered by the new reject test in Q3.2; until then `--keep` + manual Reject.

### Question 1.3: Is `req_type` reset so a stale continuation chunk is rejected?

- **Assumption:** setting `G_context.req_type = REQ_NONE` on every terminal path
  (approved, rejected, and each error `return io_send_sw(...)`) makes a bare
  `P1_CONTINUATION` chunk after a completed sign hit the existing
  `req_type != REQ_SIGN_MESSAGE` guard and return `SW_INVALID_DATA` (0x6A80).
- **Done when:** `req_type` is reset in `sign_approved`, `sign_rejected`, and the SIGN
  error paths; a `P1_CONTINUATION` APDU sent after a completed sign returns 0x6A80.
- **Spec excerpt:** "Set `G_context.req_type = REQ_NONE` at the end of every terminal
  path... a stray `P1_CONTINUATION` chunk hits the existing `req_type != REQ_SIGN_MESSAGE`
  guard and returns `SW_INVALID_DATA`."
- **Verify:** covered by the stale-chunk test in Q3.2.

---

## Phase 2: ECDH consent gate + review display

Exit criteria: an ECDH_X25519 APDU shows a review flow (account path + SHA-256 of the
ephemeral pubkey, labelled "Peer key"); Approve returns the same 32-byte shared secret;
Reject returns `SW_USER_REJECTED`; `req_type` reset.

### Question 2.1: Does ECDH gate, display the peer-key digest, and reset state?

- **Assumption:** the same async pattern applies: `handler_ecdh_x25519` stores the
  ephemeral key (unchanged), calls `ui_display_ecdh()`, returns 0 with no SW; Approve runs
  `ecdh_approved()`, Reject runs `ecdh_rejected()`; the `// For now, auto-approve` line is
  gone.
- **Done when:**
  - `ui_display_ecdh()` renders: Review → Account → Peer key (SHA-256(ephemeral_pubkey),
    full 64 hex, paginated) → Approve → Reject, label "Key agreement".
  - `handler_ecdh_x25519` no longer calls `ecdh_approved()` inline; auto-approve comment
    removed.
  - `req_type` reset in `ecdh_approved`, `ecdh_rejected`, and ECDH error paths.
  - Approve yields the identical shared secret the existing `agreeKey` / `decrypt` tests
    expect; Reject returns 0x6985.
- **Spec excerpt:** "ECDH review flow steps: identical shape, label 'Key agreement',
  digest field labelled 'Peer key' = SHA-256(ephemeral_pubkey)."
- **Verify:** existing `agreeKey`/`decrypt` tests pass via auto-approval (Q3.1); reject
  test in Q3.2.

---

## Phase 3: Test harness + docs

Exit criteria: the full Speculos suite (existing 12 + new tests) passes unattended;
README reflects the approval flows.

### Question 3.1: Does Speculos auto-approval keep the existing suite green unattended?

- **Assumption:** posting a Speculos automation ruleset (or driving buttons in the
  transport) that presses through to Approve when a review screen appears lets the
  existing sign / ECDH / integration / cross-compat tests pass without manual input.
- **Done when:** the Speculos transport/harness auto-approves review screens; all
  pre-existing tests in `tests/ledger/test/speculos.test.ts` pass unattended via
  `./tests/ledger/test-speculos.sh --build`.
- **Spec excerpt:** "the Speculos transport / harness posts an automation ruleset that
  presses through to Approve when a review screen appears, so the existing sign / ECDH /
  integration / cross-compat tests continue to pass unattended."
- **Verify:** `./tests/ledger/test-speculos.sh --build` — full suite green.

### Question 3.2: Do the new reject and stale-chunk tests pass?

- **Assumption:** tests can drive the emulator to Reject (button nav or a distinct
  automation rule) and assert error status words.
- **Done when:** three new tests pass: SIGN reject → 0x6985, ECDH reject → 0x6985,
  stray `P1_CONTINUATION` after completed sign → 0x6A80.
- **Spec excerpt:** "New coverage: SIGN rejection → `SW_USER_REJECTED` (0x6985); ECDH
  rejection → `SW_USER_REJECTED`; stray `P1_CONTINUATION` after a completed sign →
  `SW_INVALID_DATA` (0x6A80). The rejection tests drive the emulator to the Reject step."
- **Verify:** `./tests/ledger/test-speculos.sh --build` — new tests green.

### Question 3.3: Does the README describe the approval screens?

- **Assumption:** the Confirmation = "Yes" table entries are now accurate; a short
  "Approval screens" subsection documents the SIGN and ECDH review flows.
- **Done when:** `apps/ledger/README.md` keeps Confirmation = "Yes" and adds an
  "Approval screens" subsection describing both flows and the digest field.
- **Spec excerpt:** "keep Confirmation = 'Yes' (now accurate); add a short 'Approval
  screens' subsection describing the SIGN and ECDH review flows."
- **Verify:** doc-only; no build.

---

## Decision Log

### Q1.1a — UX framework: BAGL is dead on Nano, pivot to NBGL

**Learned:** The spec assumed BAGL `ux_flow`. The first Q1.1 probe wrote a compiling BAGL
implementation but **could not render it** — Speculos exits with signal 11 at the first
display element of any BAGL flow (even a minimal 2-step flow).

Root cause isolated (not app logic, not images):
- Toolchain is a **matched current pair**, not skewed: `ledger-app-builder:latest` =
  nanosplus SDK `v26.4.0` / API_LEVEL 26; `speculos:latest` = 0.26.9 (2026-06-17).
- The BAGL crash reproduces **identically on every API_LEVEL_26-capable Speculos**
  (0.26.7 / 0.26.8 / 0.26.9). Not a Speculos regression; pinning Speculos cannot fix it.
  Cannot go below 0.26.7 (no API_26 support) without downgrading the SDK.
- Fonts are correctly embedded (`C_bagl_fonts` count = 3, valid pointers) — ruled out.
- **Positive control:** LedgerHQ `app-boilerplate`, built in the same image with
  `ENABLE_NBGL_FOR_NANO_DEVICES = 1` (NBGL, zero BAGL), **renders** in Speculos 0.26.9
  ("Boilerplate / app is ready"). So the toolchain and emulator are healthy; only BAGL
  is broken.

**Decision:** BAGL `ux_flow` is retired for Nano on this SDK. Pivot the whole feature to
**NBGL** (`nbgl_use_case.h` + `ENABLE_NBGL_FOR_NANO_DEVICES = 1`), matching the
boilerplate.

**Plan/spec change:** spec §1 framework note + §3 display rewritten BAGL → NBGL;
`apps/ledger/Makefile` gains `ENABLE_NBGL_FOR_NANO_DEVICES = 1`; Q1.1 assumption updated.
The async consent-gate architecture (defer to callback, `return 0` with no SW, `req_type`
reset) is **unchanged** — only the rendering API changes. The probe's uncommitted BAGL
`src/ui/display.{c,h}` must be rewritten for NBGL. Q1.1 re-runs against NBGL.

### Q1.1 — async consent gate defers SIGN to an NBGL Approve callback ✅

**Verified.** NBGL rewrite renders + round-trips in Speculos 0.26.9:
- Home: NBGL `nbgl_useCaseHomeAndSettings` → "Kokuin / app is ready".
- SIGN APDU (`m/44'/876'/0'`, "hello") → review renders: "Review message", Account
  `44'/876'/0'`, Digest (2 pages) = `2cf24dba…938b9824` = `sha256("hello")` exact,
  "Sign message" / "Reject message".
- Approve (`/button/both` on "Sign message") → status "Message signed", returns to home,
  and the blocked APDU returns 64-byte Ed25519 signature + SW `0x9000`.

**Real blocker found (not the NBGL code):** the app Makefile had `include Makefile.defines`
at the top where the boilerplate has `include Makefile.target`. The early `Makefile.defines`
pass ran before `ENABLE_NBGL_FOR_NANO_DEVICES`/`standard_app` set `USE_NBGL=1`, so it defined
`HAVE_BAGL`, which pulled the absent `ux_bagl.h` and broke the build. Fixed by switching the
top include to `Makefile.target` (mirroring the boilerplate). **Rule:** NBGL/BAGL-affecting
settings must precede the SDK includes that consume them.

**Scope note:** `menu.c` `ui_menu_main()` was upgraded to an NBGL home (not just `UX_INIT()`)
— required so Speculos boots to an idle screen and the post-review status page has a return
target. New app icon `icons/kokuin_app_14px.gif` is a **placeholder** boilerplate glyph, not
real branding (revisit). No `req_type` reset here (Q1.3). ECDH untouched (Phase 2).

### Q1.2 — SIGN Reject returns `SW_USER_REJECTED` (0x6985) ✅

**Verified, no code change needed.** Reject was already wired: `review_choice(false)` →
`sign_rejected()` → `explicit_bzero(message)` + `io_send_sw(SW_USER_REJECTED)`. SIGN driven
to "Reject message" returns `{"data":"6985"}`, no response data.

### Q1.3 — `req_type` reset so a stale continuation chunk is rejected ✅

**Verified after fix.** Added `G_context.req_type = REQ_NONE` at entry of `sign_approved()`
and `sign_rejected()` (cover all their exits) and before each aborting
`io_send_sw(SW_INVALID_DATA)` in `handler_sign_message`. `REQ_NONE = 0` already in `types.h`;
no enum change. `P1_CONTINUATION` guard and mid-op `SW_OK` returns untouched.

- After Approve (`9000` + 64-byte sig), a data-bearing stale continuation `e00380000141`
  (`P1=0x80`, `P2=0x00`, `Lc=01`) returns `6a80` (`SW_INVALID_DATA`) — hits the
  `req_type != REQ_SIGN_MESSAGE` guard. Fresh SIGN + Approve regression still returns
  `9000` + identical sig.

**Test-design finding (feeds Q3.2):** the stale-chunk test must send a **≥1-byte**
continuation. A bare `Lc=00` continuation (`e003800000`) is rejected earlier by the
`dispatcher.c` length guard with `SW_WRONG_DATA_LENGTH` (`6700`) and never reaches the
`req_type` guard. Assert `6a80` against a 1-byte continuation, not `Lc=00`.

**Phase 1 complete** (Q1.1–Q1.3). Known: 2 pre-existing `signToken` vitest tests now time
out (SIGN needs approval the auto-transport doesn't yet give) — expected, resolved in Q3.1.

### Q2.1 — ECDH gates, displays peer-key digest, resets state ✅

**Verified.** SIGN pattern mirrored onto `handler_ecdh_x25519`; SIGN code untouched.
- `// For now, auto-approve` removed; handler digests the ephemeral pubkey into a new
  `G_context.peer_key_digest[32]`, calls `ui_display_ecdh()`, returns 0 with no SW.
- `ui_display_ecdh()` NBGL review (`TYPE_OPERATION`, title "Review key agreement"):
  Account `44'/876'/0'`, "Peer key" = SHA-256(ephemeral_pubkey), finish "Agree key".
  Approve → `ecdh_approved()`; Reject → `ecdh_rejected()`.
- `ecdh_approved`/`ecdh_rejected` un-`static`'d (new `ecdh_x25519.h`), each resets
  `req_type = REQ_NONE`; both aborting `io_send_sw` error paths reset it too.
- Speculos round-trip: Approve returns the exact HD-keystore shared secret
  `7bcd1bb7…a3502` + `0x9000`; Reject → `0x6985` no data. Peer-key digest on screen
  matches SHA-256 of the ephemeral pubkey.

**Note:** ECDH is single-shot (no P1/P2 chunking), so there is no stale-continuation
vector for it; the `req_type` resets are defensive on all terminal paths. The old
`unused function 'ecdh_rejected'` warning is gone.

**Phase 2 complete.** Remaining: Phase 3 (Q3.1 auto-approval harness, Q3.2 reject +
stale-chunk tests, Q3.3 README) — TypeScript/docs, not firmware.
