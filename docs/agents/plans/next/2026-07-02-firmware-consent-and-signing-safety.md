# Firmware consent and signing safety

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #2)

## Context

`apps/ledger` (on-device BOLOS firmware, paired with `@kokuin/ledger-device` over APDU)
signs and does ECDH with zero user consent — a silent signing oracle. Critical severity;
hardware/firmware-bound so it floats independently of the fixed release group, but must
land before the Ledger keystore is trusted.

## Work

### Firmware signs and does ECDH with zero user consent (Critical #2)

`sign_approved()` is called straight from the APDU handler
(`apps/ledger/src/sign_message.c:72`); ECDH has a literal `// For now, auto-approve`
(`apps/ledger/src/ecdh_x25519.c:81`). No confirmation UX exists — `menu.c` is just
`UX_INIT()`. Any local process with HID access to an unlocked device can mint identity
JWTs and decrypt JWEs silently. Defeats the hardware keystore and contradicts
`apps/ledger/README.md:13` which claims Confirmation = "Yes" for both flows.

- Fix: add a BAGL/NBGL approval flow before `sign_approved`/`ecdh_approved`.

### `req_type` never reset after signing

Firmware never resets `G_context.req_type` after signing (`sign_message.c`), so a bare
continuation chunk is signed with the stale path — becomes a real consent-bypass once
first-chunk-only confirmation is added. Reset after each completed operation.

## Out of scope

- Host-side protocol version gate, firmware/package version duplication, derivation-path
  validation — see `backlog/2026-07-02-ledger-protocol-hardening.md`.
- CI build of the firmware — see `next/2026-07-02-ci-release-gating.md`.
