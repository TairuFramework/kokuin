# @kokuin/ledger-device

## 0.2.0

### Minor Changes

- 7eec1ce: Gate SIGN and ECDH behind on-device consent in the paired BOLOS firmware. The device now displays the message digest (SIGN) or the counterparty public key (ECDH) and waits for a physical approve/reject before returning a result, so a compromised host can no longer sign or derive a shared secret silently. Rejection returns `0x6985`.

  The APDU protocol versions in lockstep with the firmware: this package expects a device running the matching firmware, and `checkStatusWord` now reports `0x6a80` as `Invalid data` rather than `Invalid derivation path`, which the firmware also raises for malformed SIGN/ECDH payloads.

### Patch Changes

- Updated dependencies [bcfb386]
- Updated dependencies [1ecca02]
  - @kokuin/token@0.2.0
