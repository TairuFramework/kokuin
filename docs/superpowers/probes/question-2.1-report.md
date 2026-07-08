# Probe report — ECDH consent gate + review + req_type reset

**Result: DONE**

ECDH now gates on an NBGL review, displays the peer-key digest, and resets
`req_type` on every terminal path. The SIGN consent-gate pattern was mirrored
for ECDH; SIGN code was left untouched (only a new ECDH entry point was added
alongside it). NBGL only, no BAGL fallback.

## Files changed

- `apps/ledger/src/types.h` — added `uint8_t peer_key_digest[32]` to `global_ctx_t`,
  the SHA-256 of the peer's ephemeral key shown during the ECDH review (mirrors
  `message_digest`; does not clobber it).
- `apps/ledger/src/ecdh_x25519.h` — **new**; declares `ecdh_approved(void)` /
  `ecdh_rejected(void)` so the UI callback can reach them (mirrors `sign_message.h`).
- `apps/ledger/src/ecdh_x25519.c` — `ecdh_approved`/`ecdh_rejected` are no longer
  `static` and each resets `G_context.req_type = REQ_NONE` up front; the handler
  no longer calls `ecdh_approved()` inline (the `// For now, auto-approve` line is
  gone) — it digests the ephemeral key into `peer_key_digest`, calls
  `ui_display_ecdh()`, and returns 0 with no status word; both aborting
  `io_send_sw` error paths now reset `req_type`.
- `apps/ledger/src/ui/display.c` — added `ui_display_ecdh()` and the
  `agreement_choice(bool)` callback (Approve → `ecdh_approved()` +
  `STATUS_TYPE_OPERATION_SIGNED`; Reject → `ecdh_rejected()` +
  `STATUS_TYPE_OPERATION_REJECTED`), plus a static `g_peer_key` hex buffer.
  Review uses `TYPE_OPERATION`, title "Review key agreement", pairs
  {Account = `bip32_path_format`, Peer key = 64 hex of the SHA-256 digest},
  finish button "Agree key". Reuses `format_hex`, `g_account`, `pairs`,
  `pairList`. SIGN display code unchanged.
- `apps/ledger/src/ui/display.h` — declared `ui_display_ecdh(void)`.

## Notes

- ECDH is single-shot (no P1/P2 chunking; the dispatcher passes the whole cdata
  to `handler_ecdh_x25519`), so the "stale continuation → 6a80" check in the
  brief's Verify step 4 is N/A. The `req_type` reset lines are present on every
  terminal ECDH path (approve, reject, both aborting error paths).
- The previously-noted `ecdh_x25519.c: unused function 'ecdh_rejected'` warning
  is gone — Reject now uses it. No app-source warnings in the build.
- Probe vector used a fixed ephemeral private key (bytes 0x01..0x20) for a
  reproducible run. The expected shared secret was computed independently via
  `HDKeyStore.fromMnemonic(MNEMONIC).provideIdentity('0').agreeKey(ephPub)`
  (same underlying key as the ledger), matching the existing `agreeKey` /
  ECDH cross-compat tests.

## Build output (docker compose run --rm build)

App sources compiled clean, ELF linked:

```
[CC]   build/nanos2/obj/app/src/ecdh_x25519.o
[CC]   build/nanos2/obj/app/src/sign_message.o
[CC]   build/nanos2/obj/app/src/ui/display.o
...
[LINK] build/nanos2/bin/app.elf
[CP] build/nanos2/bin/app.elf => bin/app.elf
```

`bin/app.elf` = 147.1K. No warnings or errors on app sources.

Build ran via `docker compose run --rm build` + `docker compose up -d speculos`
(the meaningful half of `test-speculos.sh --build --keep`); the script's final
vitest step was skipped because, as the brief notes, the `agreeKey`/`decrypt`
vitest tests now block on the approval button prompt (handled in Q3.1). The
manual REST round-trip below is the bar.

## Probe vector

- Ephemeral pubkey: `07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c`
- SHA-256(ephemeral pubkey) ("Peer key"): `aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041`
- Expected shared secret (HD keystore `agreeKey`): `7bcd1bb7bbd218c4f8fafac5d98a2fbf592218e155aad3382d26836a297a3502`
- ECDH APDU: `e00400002d038000002c8000036c8000000007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c`
  (CLA e0, INS 04, P1 00, P2 00, Lc 2d = path `m/44'/876'/0'` + 32-byte ephemeral pubkey)

## Interaction 1 — review renders

`POST /apdu` (blocks on the button prompt); `GET /events?currentscreenonly=true`
across pages:

```
title:        "Review key " / "agreement"        -> "Review key agreement"
Account:      "44'/876'/0'"
Peer key 1/2: aaa8fff703b50b2297f 4f6e13508f72420d96 fd01ebb84cb074449
Peer key 2/2: caaef64041
              => aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041  (matches digest)
confirm:      "Agree key"
reject:       "Reject operation"
```

## Interaction 2 — Approve

Navigate to "Agree key", `POST /button/both`, read the blocked `/apdu` response:

```
{"data": "7bcd1bb7bbd218c4f8fafac5d98a2fbf592218e155aad3382d26836a297a35029000"}
```

Shared secret `7bcd1bb7bbd218c4f8fafac5d98a2fbf592218e155aad3382d26836a297a3502`
== expected. SW `9000`. Post-approve screen: "Operation signed". PASS.

## Interaction 3 — Reject

Fresh ECDH APDU, navigate to "Reject operation", `POST /button/both`:

```
{"data": "6985"}
```

SW `0x6985` (SW_USER_REJECTED), no data. Post-reject screen: "Operation rejected". PASS.
