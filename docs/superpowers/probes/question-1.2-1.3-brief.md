# Probe brief — Questions 1.2 + 1.3 (SIGN reject SW + req_type reset)

Two tightly-coupled terminal-path invariants on `apps/ledger/src/sign_message.c`,
both verified by asserting APDU status words. NBGL SIGN consent gate is already
landed (commit `8f325a5`): `handler_sign_message` defers to `ui_display_sign()`; the
NBGL `review_choice(bool)` callback runs `sign_approved()` on Approve / `sign_rejected()`
on Reject. Build with the existing `ENABLE_NBGL_FOR_NANO_DEVICES = 1` Makefile.

## Q1.2 — Does Reject return `SW_USER_REJECTED` (0x6985)?
- **Assumption:** the Reject path already runs the existing `sign_rejected()`, which
  scrubs the message buffer (`explicit_bzero`) and sends `SW_USER_REJECTED` (0x6985); no
  signature is emitted. This is likely already wired — this question is mostly
  **verification**, plus fixing anything found wrong.
- **Done when:** a SIGN APDU driven to Reject returns `0x6985` with no response data.

## Q1.3 — Is `req_type` reset so a stale continuation chunk is rejected?
- **Assumption:** `G_context.req_type` is never reset after a SIGN completes, so a bare
  `P1_CONTINUATION` chunk is processed against stale state. Setting
  `G_context.req_type = REQ_NONE` on **every terminal SIGN path** makes a stray
  continuation chunk hit the existing `req_type != REQ_SIGN_MESSAGE` guard and return
  `SW_INVALID_DATA` (0x6A80).
- **Change:** set `G_context.req_type = REQ_NONE` in:
  - `sign_approved()` — after the response is sent
  - `sign_rejected()`
  - every SIGN error path that terminates the op with `return io_send_sw(...)`
  Confirm `REQ_NONE` exists (check `types.h` / `constants.h`); if the enum lacks a "none"
  member, add one (value 0) rather than inventing an ad-hoc constant.
- **Done when:** after a completed sign (Approve or Reject), a bare `P1_CONTINUATION`
  APDU returns `0x6A80`; a normal fresh SIGN still works unchanged.

## Scope
SIGN only. Do NOT touch ECDH (Phase 2) — even though it has the same defect; that is a
separate question. Do not change the NBGL display code. Do not weaken the existing
`P1_CONTINUATION` guard.

## Conventions
Follow `kigu:conventions` + existing `apps/ledger` style. **Code/comments/tests must
NEVER reference plan question / decision / phase numbers.** Capture the invariant
directly. Do not edit generated `lib/`.

## Read first
- `apps/ledger/src/sign_message.c` — `handler_sign_message`, `sign_approved`,
  `sign_rejected`, the `P1_CONTINUATION` `req_type` guard, all `io_send_sw` error returns.
- `apps/ledger/src/types.h`, `apps/ledger/src/constants.h` — `req_type` enum, `REQ_*`.

## Verify
`./tests/ledger/test-speculos.sh --build --keep`, then via the Speculos REST API on host
port 9999 (`/apdu`, `/button/{left,right,both}`, `/events?currentscreenonly=true`):

Test APDU (single-chunk SIGN, `m/44'/876'/0'`, `"hello"`):
`e003000012038000002c8000036c8000000068656c6c6f`

1. **Reject (Q1.2):** send the SIGN APDU, navigate to "Reject message", press
   `/button/both`; assert the APDU response SW = `0x6985` and no data.
2. **Stale chunk (Q1.3):** complete a sign first (send SIGN, Approve → expect `…9000`),
   then send a bare continuation chunk with P1 = `P1_CONTINUATION` and no valid session;
   assert SW = `0x6A80`. Use the actual `P1_CONTINUATION` / `P2_LAST` values from
   `constants.h` — read them, do not guess. A minimal continuation APDU is
   `CLA=e0 INS=03 P1=<continuation> P2=<last> Lc=00`.
3. **Regression:** a fresh SIGN + Approve after all of the above still returns a 64-byte
   signature + `0x9000`.

The full APDU-send + button-drive + read-response must run in ONE shell process (a
backgrounded `/apdu` curl dies if its shell exits before you press Approve/Reject).

Paste the ACTUAL build output and every APDU/SW interaction (raw curl output).

## If it fails
Stop at the first hard failure, report **BLOCKED** with exact output. Difficulty is the
finding. Do not restructure the handler or main loop to force it.

## Report contract
Write `docs/superpowers/probes/question-1.2-1.3-report.md`: per-question result
(Q1.2, Q1.3), files changed each with a one-line description, build output, and each
APDU→SW interaction pasted. Then return ONLY: status (DONE / DONE_WITH_CONCERNS /
NEEDS_CONTEXT / BLOCKED), files changed, one-line verify summary, concerns. Do NOT commit.
