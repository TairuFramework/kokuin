# Ledger protocol hardening

**Status:** next — promoted from backlog on 2026-08-03 (triage)
**Origin:** `completed/2026-07-02-audit.complete.md` (Medium: protocol version, path encoding)

## Context

Host↔firmware APDU protocol has no version gate and encodes malformed derivation paths as a
valid-looking key. Should land before the Ledger keystore is widely used. The APDU protocol
versions in lockstep with `@kokuin/ledger-device`.

Promoted because the path-encoding defect derives the **wrong key silently**, with no error at
any layer. Re-verified on 2026-08-03, still live: `encodeDerivationPath` validates only that
each component ends in `'`, so `m/abc'` reaches `Number.parseInt('abc')` → `NaN`, and
`(NaN | HARDENED_BIT) >>> 0` → `0x80000000` — indistinguishable from a legitimate `m/0'`.

## Work

### Host never checks protocol version

`GET_APP_VERSION` is defined (`packages/ledger-device/src/apdu.ts:6`) but never called; no
compat gate before signing. Firmware version is duplicated in `apps/ledger/Makefile:13` and
`apps/ledger/src/constants.h:46` with nothing tying them (0.1.0 vs package 0.1.1). Call the
version APDU and gate; single-source the firmware version.

### `encodeDerivationPath` encodes garbage as `0'`

`packages/ledger-device/src/apdu.ts:38` — `parseInt("abc'")` → NaN → `0x80000000`, deriving
a wrong key silently. No `index < 2^31` range check. Add validation.

### Deterministic HD path validation late/partial

`packages/deterministic/src/derivation.ts:6` validates similarly late/partially. Validate the
path up front, consistent with the ledger-device fix.

## Out of scope

- Firmware consent UX and `req_type` reset — done, see
  `completed/2026-07-09-firmware-consent-and-signing-safety.complete.md`.
