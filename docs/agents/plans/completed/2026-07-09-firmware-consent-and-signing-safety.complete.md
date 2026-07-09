# Firmware consent and signing safety

**Status:** complete
**Date:** 2026-07-09
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #2)
**Branch:** `firmware-consent-signing-safety` (7 commits)

## Goal

Close the silent signing oracle in `apps/ledger` (on-device BOLOS firmware, Nano S+, paired
with `@kokuin/ledger-device` over APDU). `SIGN_MESSAGE` and `ECDH_X25519` executed with zero
user consent — any local process with HID access to an unlocked device could mint identity
JWTs and decrypt JWEs silently. Additionally, `G_context.req_type` was never reset after an
operation, so a stray continuation chunk could be signed against stale path state.

## What was built

Both flows now gate on an on-device review; no signature or shared secret leaves the device
without an Approve press.

1. **SIGN consent gate.** The final chunk (single-chunk and last-continuation alike) computes
   SHA-256 of the fully assembled message, calls `ui_display_sign()`, and returns 0 with **no
   status word**. The review's Approve callback runs the signing crypto and answers the pending
   APDU; Reject answers `SW_USER_REJECTED` (0x6985). For multi-chunk messages the gate fires
   only once the whole message is assembled and hashed, so there is no partial-message
   confirmation bypass.
2. **ECDH consent gate.** Same async pattern: the handler digests the peer's ephemeral X25519
   public key, shows it as "Peer key", and defers the key agreement to the Approve callback.
3. **`req_type` reset.** `G_context.req_type = REQ_NONE` on every terminal path (approve,
   reject, and each aborting error return). A stray `P1_CONTINUATION` after a completed sign now
   hits the pre-existing `req_type != REQ_SIGN_MESSAGE` guard and returns `SW_INVALID_DATA`
   (0x6A80).

## Key design decisions

**BAGL is retired on Nano at this SDK; the UI is NBGL.** The design originally assumed BAGL
`ux_flow`. A compiling BAGL implementation could not render: Speculos exits with signal 11 at
the first display element of any BAGL flow, even a minimal two-step one. Root-caused as a
framework problem, not app logic — the toolchain is a matched current pair
(`ledger-app-builder:latest` = nanosplus SDK v26.4.0 / API_LEVEL 26; `speculos:latest` =
0.26.9), the crash reproduces identically on every API_26-capable Speculos (0.26.7/8/9) so it
is not a Speculos regression and pinning cannot fix it, fonts are correctly embedded, and
LedgerHQ's `app-boilerplate` built NBGL-only in the same image renders fine. The whole feature
uses NBGL (`nbgl_use_case.h`, `ENABLE_NBGL_FOR_NANO_DEVICES = 1`). The async consent-gate
architecture was unchanged by the pivot — only the rendering API differs.

**Async handoff needs no main-loop restructuring.** `app_main`'s existing `io_recv_command()`
pumps the seproxyhal/UX events, so a handler may return 0 without a status word and let the UI
callback answer later.

**The digest is shown in full (32 bytes / 64 hex, paginated), never truncated** — a truncated
hash is grindable and gives false assurance. It is tamper-evidence for a trusted host to
compare against; the on-device screen alone is not a MITM defense.

**The displayed digest is over exactly the bytes used.** SIGN displays SHA-256 of the message
it signs; ECDH displays SHA-256 of the ephemeral key it uses as the u-coordinate. A digest over
different bytes than the operation consumes would be a consent bypass.

**Status screens report the outcome the host was given.** The approve callbacks return whether
the crypto succeeded, so an internal error cannot show a success screen while the host receives
an error status word. The SDK's built-in review statuses only speak of signed transactions,
messages and operations, so the key agreement states its own outcome via custom status text.

## Rules carried forward

- **NBGL/BAGL-affecting Makefile settings must precede the SDK includes that consume them.**
  The real build blocker was `include Makefile.defines` at the top of `apps/ledger/Makefile`:
  that early pass ran before `ENABLE_NBGL_FOR_NANO_DEVICES` / `standard_app` set `USE_NBGL=1`,
  so it defined `HAVE_BAGL` and pulled in an absent `ux_bagl.h`. The top include must be
  `Makefile.target`.
- **Any string handed to NBGL must have static lifetime.** NBGL reads tag/value buffers
  asynchronously while the review is on screen; a stack buffer is a use-after-return.
- **The Speculos automation ruleset is coupled to firmware screen wording.** Auto-approval
  matches on-screen page titles (`Review message`, `Review key`, `Account`, `Digest`,
  `Peer key`, `Sign message`, `Agree key`, `Reject message`, `Reject operation`). Re-wording any
  review page silently breaks the harness. Rules must use `regexp`, not `text`: the ECDH title
  wraps into two device events (`"Review key "` / `"agreement"`), so a full-string
  `"Review key agreement"` match matches neither and stalls the review.
- **A stale-continuation test must send a ≥1-byte continuation.** A bare `Lc=00` continuation
  (`e003800000`) is rejected earlier by the `dispatcher.c` length guard with
  `SW_WRONG_DATA_LENGTH` (0x6700) and never reaches the `req_type` guard. Assert 0x6A80 against
  `e00380000141`.
- **A custom `LedgerTransport` must not impose a short APDU timeout** on `SIGN_MESSAGE` (0x03)
  or `ECDH_X25519` (0x04) — `send()` now stays pending across the human approval window.
  Documented in `packages/ledger-device/README.md`.

## Coverage added

The Speculos suite (`tests/ledger/test/speculos.test.ts`) runs unattended via a
`POST /automation` ruleset that advances through each paginated info page (right-key
press-release) and confirms on the final page (both-key press). A top-level `beforeEach`
installs the approve ruleset; the reject tests override it in-body, so the harness is robust to
test ordering and self-restoring.

Three negative tests were added alongside the 12 pre-existing ones: SIGN reject → 0x6985, ECDH
reject → 0x6985, stale continuation after a completed signature → 0x6A80. These give the suite
real teeth — a firmware regression that silently signed without consent would return
0x9000 + signature where the reject tests expect 0x6985, and so would fail.

## Status

Complete. 15/15 Speculos tests green unattended against a freshly built ELF; firmware builds
with no warnings; `biome` and `tsc` clean. A whole-branch review found no Critical issues: no
path emits a signature or shared secret without an Approve press, no handler returns 0 without
an armed callback that will eventually answer (which would hang the host), callbacks answer
exactly once, and `req_type` is reset on every terminal path. All review findings were fixed on
the branch.

`apps/ledger/README.md` documents both approval screens and no longer overstates the SDK API
level. The app icon (`apps/ledger/icons/kokuin_app_14px.gif`) is still a placeholder boilerplate
glyph — see `backlog/2026-07-09-ledger-app-icon.md`.
