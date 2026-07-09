# Firmware consent and signing safety — design

**Date:** 2026-07-08
**Origin:** `docs/agents/plans/next/2026-07-02-firmware-consent-and-signing-safety.md`
(audit Critical #2)

## Problem

`apps/ledger` (BOLOS firmware, Nano S+/X, paired with `@kokuin/ledger-device` over
APDU) signs and does ECDH with **zero user consent** — a silent signing oracle.

- `handler_sign_message` calls `sign_approved()` inline the moment the final chunk
  arrives (`src/sign_message.c:73,97`).
- `handler_ecdh_x25519` has a literal `// For now, auto-approve` and calls
  `ecdh_approved()` inline (`src/ecdh_x25519.c:81-82`).
- `menu.c` is just `UX_INIT()` — no confirmation UX exists at all.

Any local process with HID access to an unlocked device can mint identity JWTs and
decrypt JWEs silently. This defeats the hardware keystore and contradicts
`apps/ledger/README.md:13`, which claims Confirmation = "Yes" for both flows.

Secondary defect: `G_context.req_type` is never reset after an operation completes, so
a bare `P1_CONTINUATION` chunk is processed against stale state — a real consent-bypass
vector once a confirmation gate exists.

## Goals

- No SIGN or ECDH result leaves the device without an explicit on-device Approve.
- Reject path returns `SW_USER_REJECTED` (0x6985).
- `req_type` reset after every completed op so stale continuation chunks are rejected.
- Existing Speculos integration tests pass unattended; add reject-path and
  stale-chunk coverage.
- README's Confirmation = "Yes" claim becomes true.

## Non-goals (out of scope)

- Host-side APDU protocol-version gate, firmware/package version duplication,
  derivation-path validation — see `backlog/2026-07-02-ledger-protocol-hardening.md`.
- CI build of the firmware — see `next/2026-07-02-ci-release-gating.md`.
- Host-side display of a matching digest (the real MITM defense). The on-device
  digest is tamper-evidence only; a trusted host comparison is app-level UX, not in
  this repo.

## Design

### 1. Asynchronous consent gate

BOLOS UX is asynchronous. The handlers must stop invoking `*_approved()` inline.

New control flow per operation:

1. Handler parses the path, accumulates the message / stores the ephemeral key
   (unchanged), then computes the display digest and calls a UI entry point
   (`ui_display_sign()` / `ui_display_ecdh()`), and `return 0` **without sending any
   status word**.
2. An NBGL `nbgl_use_case` review renders the account path + digest and ends in
   Approve / Reject.
3. **Approve** callback → `sign_approved()` / `ecdh_approved()` — unchanged crypto and
   `io_send_response*` — then returns to idle (`ui_menu_main()`).
4. **Reject** callback → `sign_rejected()` / `ecdh_rejected()` (already exist; send
   `SW_USER_REJECTED`), then idle.

The main loop in `app_main.c` already calls `io_recv_command()` each iteration, which
pumps UX / seproxyhal events until the next full APDU arrives, so no loop restructuring
is needed — the reply is sent asynchronously from the NBGL review callback.

**Framework note (Nano = NBGL, not BAGL).** On this SDK (API_LEVEL_26, nanosplus
`v26.4.0`) BAGL `ux_flow` is retired for Nano: an app that renders any BAGL flow
segfaults Speculos (signal 11) at the first display element, verified against every
API_LEVEL_26-capable Speculos (0.26.7 – 0.26.9). LedgerHQ's own app-boilerplate builds
Nano with `ENABLE_NBGL_FOR_NANO_DEVICES = 1` and NBGL-only UI; that build renders in the
same Speculos. So this app uses NBGL (`nbgl_use_case.h`) on Nano S+/X.

For multi-chunk SIGN, the gate fires only at the **final** chunk, once the whole
message is assembled and hashed. There is therefore no first-chunk-only-confirmation
bypass: the user approves the complete message digest, not a partial one.

The `sign_approved` / `ecdh_approved` bodies keep their existing key derivation,
crypto, `explicit_bzero` scrubbing, and response sending unchanged. Only the *call
site* moves from the handler into the Approve callback.

### 2. `req_type` reset

Set `G_context.req_type = REQ_NONE` at the end of every terminal path in both
handlers and their approved/rejected callbacks:

- after `io_send_response*` in `sign_approved` / `ecdh_approved`
- in `sign_rejected` / `ecdh_rejected`
- on every error `return io_send_sw(...)` that terminates an operation

With `req_type` cleared, a stray `P1_CONTINUATION` chunk hits the existing
`G_context.req_type != REQ_SIGN_MESSAGE` guard (`sign_message.c:81`) and returns
`SW_INVALID_DATA`.

### 3. Display

New UI module (`src/ui/display.c` + header) using `nbgl_use_case.h`, built with
`ENABLE_NBGL_FOR_NANO_DEVICES = 1`.

Shared helper: `digest_sha256(const uint8_t *in, size_t len, uint8_t out[32])` wrapping
the SDK `cx_hash_sha256`. Path formatting uses the standard-app-lib
`bip32_path_format(path, path_len, char *out, size_t out_len)`.

Each flow is an NBGL review presenting a tag/value pair list, ending in an Approve /
Reject choice. `nbgl_useCaseReview` (or `nbgl_useCaseReviewLight`) drives it; the
Approve callback runs `sign_approved()` / `ecdh_approved()`, the Reject callback runs
`sign_rejected()` / `ecdh_rejected()`, both returning to idle via `ui_menu_main()`.

**SIGN review — tag/value list:**

| Field | Content |
|-------|---------|
| Title | "Review message" |
| Account | `m/44'/876'/n'` (formatted path) |
| Digest | 64 hex chars = SHA-256(message) |
| Confirm | Approve → `sign_approved()`; Reject → `sign_rejected()` |

**ECDH review:** identical shape, title "Review key agreement", digest field labelled
"Peer key" = SHA-256(ephemeral_pubkey).

Design note: the digest is shown **full** (32 bytes / 64 hex), not truncated — a
truncated hash is grindable and gives false assurance. NBGL wraps long values across the
Nano screen automatically.

### 4. Tests (`tests/ledger/`)

- **Auto-approval:** the Speculos transport / harness posts an automation ruleset that
  presses through to Approve when a review screen appears, so the existing sign / ECDH /
  integration / cross-compat tests continue to pass unattended.
- **New coverage:**
  - SIGN rejection → `SW_USER_REJECTED` (0x6985)
  - ECDH rejection → `SW_USER_REJECTED`
  - stray `P1_CONTINUATION` after a completed sign → `SW_INVALID_DATA` (0x6A80)

The rejection tests drive the emulator to the Reject step (button navigation or a
distinct automation rule) rather than auto-approving.

### 5. Docs

`apps/ledger/README.md`: keep Confirmation = "Yes" (now accurate); add a short
"Approval screens" subsection describing the SIGN and ECDH review flows.

## Files touched

- `apps/ledger/src/sign_message.c` — move `sign_approved` call into Approve callback;
  compute digest; reset `req_type`.
- `apps/ledger/src/ecdh_x25519.c` — move `ecdh_approved` call into Approve callback;
  compute digest; reset `req_type`.
- `apps/ledger/src/ui/display.{c,h}` (new) — NBGL review flows for SIGN and ECDH.
- `apps/ledger/Makefile` — `ENABLE_NBGL_FOR_NANO_DEVICES = 1`.
- `apps/ledger/src/crypto.{c,h}` — `digest_sha256` helper (or inline in display).
- `apps/ledger/README.md` — approval-screens note.
- `tests/ledger/test/speculos.test.ts` + harness — auto-approval automation, reject
  and stale-chunk tests.

## Verification

- `./tests/ledger/test-speculos.sh --build` — builds firmware, runs the full Speculos
  suite (existing 12 + new reject/stale tests) unattended, all pass.
- Manual: on Speculos, a SIGN/ECDH APDU shows the review flow; Reject yields 0x6985;
  no result is emitted without pressing Approve.
