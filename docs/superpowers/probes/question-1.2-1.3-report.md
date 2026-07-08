# Probe report — Questions 1.2 + 1.3 (SIGN reject SW + req_type reset)

**Status:** DONE_WITH_CONCERNS
(one concern, non-blocking: the brief's suggested minimal continuation APDU — `Lc=00` —
is rejected earlier than the guard it was meant to exercise; see Q1.3 below.)

## Q1.2 — Does Reject return `SW_USER_REJECTED` (0x6985)?

**Result: PASS (verification only — no code change needed).**

The reject path was already correctly wired before this probe:
`ui/display.c::review_choice(false)` → `sign_rejected()` → scrubs `G_context.message`
with `explicit_bzero` and calls `io_send_sw(SW_USER_REJECTED)`. No signature is emitted.

A single-chunk SIGN APDU driven to "Reject message" returned `6985` with **no response
data** (see TEST 1 below).

## Q1.3 — Is `req_type` reset so a stale continuation chunk is rejected?

**Result: PASS after fix.**

`G_context.req_type` was never reset once a SIGN operation concluded, so after a completed
sign the context still read `REQ_SIGN_MESSAGE`. A later `P1_CONTINUATION` chunk would pass
the existing `req_type != REQ_SIGN_MESSAGE` guard and be processed against stale state
(appended to the just-emptied message buffer, and — because the chunk carried `P2_LAST` —
re-triggering a fresh signing review). The fix sets `G_context.req_type = REQ_NONE` on every
terminal SIGN path so a stray continuation now hits the guard and returns
`SW_INVALID_DATA` (0x6A80).

`REQ_NONE` already exists in `types.h` (`request_type_e { REQ_NONE = 0, ... }`) — no enum
change was required. Real constant values read from source (not guessed):
`P1_CONTINUATION = 0x80`, `P2_LAST = 0x00` (`constants.h`);
`SW_USER_REJECTED = 0x6985`, `SW_INVALID_DATA = 0x6A80`, `SW_WRONG_DATA_LENGTH = 0x6700`
(`sw.h`).

**Concern / finding.** The brief's suggested minimal continuation APDU (`CLA=e0 INS=03
P1=<continuation> P2=<last> Lc=00`) does **not** reach the `req_type` guard. `dispatcher.c`
rejects any `INS_SIGN_MESSAGE` with `cmd->lc == 0` up front with `SW_WRONG_DATA_LENGTH`
(0x6700) before `handler_sign_message` runs. To exercise the guard the continuation must
carry at least one payload byte. Verified both: the bare `Lc=00` form returns `6700` (early
length guard), and a one-byte continuation `e00380000141` returns `6a80` (the `req_type`
guard). Both are hard rejections; the invariant holds. Nothing was weakened.

## Files changed

- `apps/ledger/src/sign_message.c` — reset `G_context.req_type = REQ_NONE` on every terminal
  SIGN path: at entry of `sign_approved()` and `sign_rejected()` (both always conclude the
  op, covering all their exits) and before the aborting `io_send_sw(SW_INVALID_DATA)` returns
  in `handler_sign_message` (bad BIP32 path, oversized first chunk, continuation overflow).
  The `P1_CONTINUATION` `req_type` guard and all mid-operation `SW_OK` returns are unchanged.

No other files changed. `types.h` already defined `REQ_NONE = 0`. ECDH left untouched.

## Build output

`./tests/ledger/test-speculos.sh --build --keep` — build + link (nanos2 / Nano S+):

```
[CC]   build/nanos2/obj/app/src/sign_message.o
[CC]   build/nanos2/obj/app/src/ui/display.o
...
[LINK] build/nanos2/bin/app.elf
[CP] build/nanos2/bin/app.elf => bin/app.elf
Starting Speculos emulator on port 9999...
Waiting for Speculos API..... ready
```

`sign_message.o` compiled cleanly (no warnings). The only compiler warning in the whole
build is pre-existing and unrelated: `ecdh_x25519.c:59: unused function 'ecdh_rejected'`
(ECDH, out of scope).

The bundled vitest suite that the script runs afterward reported `2 failed | 10 passed`.
Both failures are the `signToken`-based tests timing out (`Test timed out in 15000ms`)
because, post consent-gate, SIGN now requires a physical button approval that the test's
auto-transport does not provide. This is expected and independent of this change — all
non-SIGN tests (version, pubkey, ECDH, cross-compat) passed.

## APDU → SW interactions

Driven via the Speculos REST API on host port 9999 (`/apdu`, `/button/{right,both}`,
`/events?currentscreenonly=true`), each blocking `/apdu` send + button drive + response read
in one shell process, against a freshly-restarted (clean-boot) Speculos.

Test SIGN APDU (single chunk, `m/44'/876'/0'`, `"hello"`):
`e003000012038000002c8000036c8000000068656c6c6f`
NBGL review pages observed (nanosp): `Review message` → `Account` (`44'/876'/0'`) →
`Digest (1/2)` / `(2/2)` (`2cf24dba…62938b9824`, = SHA-256 of "hello") → `Sign message` →
`Reject message`.

### TEST 1 — SIGN → Reject  (expect 0x6985, no data)
```
SIGN e003000012038000002c8000036c8000000068656c6c6f  (navigate to "Reject message", button/both)
RESPONSE: {"data": "6985"}
```
→ `6985`, no response data. PASS.

### TEST 2 — SIGN → Approve, then stale continuation  (expect 0x9000+sig, then 0x6A80)
```
SIGN e003000012038000002c8000036c8000000068656c6c6f  (navigate to "Sign message", button/both)
APPROVE RESPONSE: {"data": "c1e70a337312560b6c87b0b197ecbda802f3ec36655a51e79599f06f0e7917b2b8fa026547f4731a32eee2a9a72a8ca8e8bdd359da3b3df8e45fae2c5ccd02099000"}
  -> 64-byte Ed25519 signature + 9000

bare Lc=00 continuation  e003800000
BARE-CONTINUATION RESPONSE: {"data": "6700"}
  -> 6700 SW_WRONG_DATA_LENGTH (rejected by dispatcher length guard, never reaches handler)

data-bearing stale continuation  e00380000141   (P1=0x80, P2=0x00, Lc=01, data=0x41)
CONTINUATION RESPONSE: {"data": "6a80"}
  -> 6a80 SW_INVALID_DATA (req_type == REQ_NONE, hits the P1_CONTINUATION guard). PASS.
```

### TEST 3 — fresh SIGN → Approve regression  (expect 0x9000 + 64-byte signature)
```
SIGN e003000012038000002c8000036c8000000068656c6c6f  (navigate to "Sign message", button/both)
RESPONSE: {"data": "c1e70a337312560b6c87b0b197ecbda802f3ec36655a51e79599f06f0e7917b2b8fa026547f4731a32eee2a9a72a8ca8e8bdd359da3b3df8e45fae2c5ccd02099000"}
```
→ `9000` + identical 64-byte signature (deterministic Ed25519 for the same key/message).
The signing path is fully functional after the reject + stale-continuation exchanges above.
PASS.

## Summary line
```
T1 reject          : {"data": "6985"}
T2 approve         : {"data": "c1e70a33...ccd02099000"}  (64-byte sig + 9000)
T2 bare-cont(Lc=0) : {"data": "6700"}
T2 stale-cont      : {"data": "6a80"}
T3 regression      : {"data": "c1e70a33...ccd02099000"}  (64-byte sig + 9000)
```
