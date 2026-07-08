# Firmware consent and signing safety — plan

**Stage:** executing
**Mode:** learning-loop
**Spec:** docs/superpowers/specs/2026-07-08-firmware-consent-and-signing-safety-design.md

Each probe validates one assumption against the real firmware running in Speculos.
Firmware C + BOLOS async UX + emulator carry integration unknowns (BAGL `ux_flow` API
at this SDK level, async handoff correctness, Speculos automation format) — that is why
this runs as a learning loop, not a task list.

**Verify command (all questions unless noted):** from repo root
`./tests/ledger/test.sh --build` — builds the firmware (requires the ledger Docker
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

- **Assumption:** the SIGN handler can compute the message digest, hand off to a BAGL
  `ux_flow`, and `return 0` without sending a status word; the Approve callback then runs
  the existing `sign_approved()` (unchanged crypto + `io_send_response`) and returns to
  idle via `ui_menu_main()`. The `app_main` loop's `io_recv_command()` pumps the button
  events — no loop restructuring needed.
- **Done when:**
  - New `src/ui/display.{c,h}` renders a SIGN review flow: Review → Account
    (`m/44'/876'/n'` via `bip32_path_format`) → Digest (SHA-256(message), full 64 hex,
    paginated) → Approve → Reject.
  - `handler_sign_message` no longer calls `sign_approved()` inline; the final-chunk path
    (both `p2 != P2_MORE` first-chunk and `P2_LAST` continuation) calls
    `ui_display_sign()` and returns 0 with no SW.
  - New `digest_sha256(in, len, out[32])` helper wrapping `cx_hash_sha256`.
  - Approve path yields the identical signature the existing Speculos sign tests expect
    (auto-approval from Q3.1 may be needed to see this pass green; until then, validate
    via `--keep` + manual button press).
  - UI code guarded for Nano S+/X BAGL.
- **Spec excerpt:** "Handler parses the path, accumulates the message / stores the
  ephemeral key (unchanged), then computes the display digest and calls a UI entry point
  (`ui_display_sign()` / `ui_display_ecdh()`), and `return 0` without sending any status
  word... The main loop in `app_main.c` already calls `io_recv_command()` each iteration,
  which pumps UX button events... For multi-chunk SIGN, the gate fires only at the final
  chunk, once the whole message is assembled and hashed."
- **Verify:** `./tests/ledger/test.sh --build --keep`, then drive Speculos manually /
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
  `./tests/ledger/test.sh --build`.
- **Spec excerpt:** "the Speculos transport / harness posts an automation ruleset that
  presses through to Approve when a review screen appears, so the existing sign / ECDH /
  integration / cross-compat tests continue to pass unattended."
- **Verify:** `./tests/ledger/test.sh --build` — full suite green.

### Question 3.2: Do the new reject and stale-chunk tests pass?

- **Assumption:** tests can drive the emulator to Reject (button nav or a distinct
  automation rule) and assert error status words.
- **Done when:** three new tests pass: SIGN reject → 0x6985, ECDH reject → 0x6985,
  stray `P1_CONTINUATION` after completed sign → 0x6A80.
- **Spec excerpt:** "New coverage: SIGN rejection → `SW_USER_REJECTED` (0x6985); ECDH
  rejection → `SW_USER_REJECTED`; stray `P1_CONTINUATION` after a completed sign →
  `SW_INVALID_DATA` (0x6A80). The rejection tests drive the emulator to the Reject step."
- **Verify:** `./tests/ledger/test.sh --build` — new tests green.

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

_(filled in during execution — one entry per completed question: what was learned, and
whether it changed the plan/spec)_
