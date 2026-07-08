# Probe brief — Question 2.1 (ECDH consent gate + review + req_type reset)

Apply the now-proven SIGN consent-gate pattern to ECDH. The SIGN side is landed and
verified (commits `8f325a5`, `6eb52b2`): NBGL async gate, `ui_display_sign()`,
`review_choice(bool)` callback, `req_type = REQ_NONE` on terminal paths. **Mirror it for
ECDH.** NBGL only — build already has `ENABLE_NBGL_FOR_NANO_DEVICES = 1`.

## Question
Does ECDH gate, display the peer-key digest, and reset state?

## Assumption
`handler_ecdh_x25519` stores the ephemeral key (unchanged), computes the display digest,
calls a new `ui_display_ecdh()`, and `return 0` with no status word. An NBGL review shows
the account path + SHA-256 of the ephemeral pubkey ("Peer key"), title "Review key
agreement". Approve → `ecdh_approved()` (unchanged crypto + response), Reject →
`ecdh_rejected()`. The `// For now, auto-approve` inline call is gone. `req_type` is reset
on every terminal ECDH path.

## Done when
- New `ui_display_ecdh(void)` in `src/ui/display.{c,h}`, same NBGL shape as
  `ui_display_sign`: static `nbgl_contentTagValue_t pairs[2]` = {Account =
  `bip32_path_format`, Peer key = 64 hex of SHA-256(ephemeral_pubkey)},
  `nbgl_useCaseReview(TYPE_MESSAGE or the ECDH-appropriate type, ...)`, `review_choice`
  running `ecdh_approved()` / `ecdh_rejected()` then `nbgl_useCaseReviewStatus(..,
  ui_menu_main)`. Reuse `digest_sha256`. Store the digest where the UI reads it (mirror
  how SIGN stores `message_digest` on `G_context` — add an analogous field or reuse a
  shared display-digest buffer; keep it clean, don't clobber the SIGN field mid-op).
- `handler_ecdh_x25519` no longer calls `ecdh_approved()` inline; the `// For now,
  auto-approve` comment/line is removed; it calls `ui_display_ecdh()` and returns 0 with
  no SW.
- `G_context.req_type = REQ_NONE` reset in `ecdh_approved`, `ecdh_rejected`, and every
  aborting ECDH `io_send_sw(...)` error path. (This also silences the current
  `ecdh_x25519.c: unused function 'ecdh_rejected'` warning — Reject now uses it.)
- Approve yields the identical 32-byte shared secret the existing `agreeKey` / `decrypt`
  tests expect; Reject returns `SW_USER_REJECTED` (0x6985).

## Scope
ECDH only. Do not touch SIGN. Do not weaken any existing guard. Do not change the SIGN
display code (only add the ECDH entry point alongside it).

## Conventions
`kigu:conventions` + existing `apps/ledger` style. **No code/comment/test may reference a
plan question / decision / phase number.** Do not edit generated `lib/`.

## Read first
- `apps/ledger/src/ecdh_x25519.c` — `handler_ecdh_x25519`, `ecdh_approved`,
  `ecdh_rejected`, the `// For now, auto-approve` site, error `io_send_sw` paths, and how
  the ephemeral pubkey is received/stored. Note the APDU format (INS, P1/P2, whether ECDH
  is single-shot or chunked).
- `apps/ledger/src/ui/display.c` + `.h` — the landed SIGN NBGL pattern to mirror.
- `apps/ledger/src/sign_message.c` — the landed `req_type = REQ_NONE` reset pattern.
- `apps/ledger/src/types.h` — `G_context`, `req_type`, where SIGN stores its digest.
- Existing ECDH tests in `tests/ledger/test/speculos.test.ts` — for the exact ECDH APDU
  and the expected shared-secret value to assert against.

## Verify
`./tests/ledger/test-speculos.sh --build --keep`, then via the Speculos REST API on host
port 9999 (`/apdu`, `/button/{right,both}`, `/events?currentscreenonly=true`), each
blocking `/apdu` send + button drive + response read in ONE shell process:
1. Send an ECDH APDU (use the real format + a real ephemeral pubkey from the existing
   ECDH test). Confirm the NBGL review renders: "Review key agreement", Account
   `44'/876'/…`, "Peer key" = the SHA-256 of that ephemeral pubkey (paginated).
2. **Approve** → assert the 32-byte shared secret matches what the existing `agreeKey`
   test expects, + SW `0x9000`.
3. **Reject** (fresh ECDH, navigate to reject) → assert SW `0x6985`, no data.
4. Optionally confirm `req_type` reset the same way as SIGN (stale continuation → `6a80`)
   if ECDH is chunked; if ECDH is single-shot, note that and just confirm the reset lines
   are on the terminal paths.

Paste the ACTUAL build output and every APDU→SW/secret interaction (raw curl output).
Note: the existing `agreeKey`/`decrypt` vitest tests will now hang on approval (expected,
handled in Q3.1) — build + manual round-trip is the bar.

## If it fails
Stop at first hard failure, report **BLOCKED** with exact output. Difficulty is the
finding. Do not restructure the handler / main loop; do not fall back to BAGL.

## Report contract
Write `docs/superpowers/probes/question-2.1-report.md`: result, files changed each with a
one-line description, build output, and each APDU→SW/secret interaction pasted. Then
return ONLY: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), files changed,
one-line verify summary, concerns. Do NOT commit.
