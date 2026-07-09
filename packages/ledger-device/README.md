# @kokuin/ledger-device

## Installation

```sh
npm install @kokuin/ledger-device
```

## Transport timeouts

`signToken()` and `agreeKey()` (and `decrypt()`, which agrees a key) require explicit
approval on the device. The APDU response only arrives once the user presses Approve, so
`LedgerTransport.send()` stays pending for as long as the person takes to read the review
screens — potentially minutes.

Transports built on `@ledgerhq/hw-transport-*` have no APDU timeout by default and work as
is. If you supply your own `LedgerTransport`, do not impose a short timeout on
`SIGN_MESSAGE` (`0x03`) or `ECDH_X25519` (`0x04`) — a transport that gives up after a few
seconds will abort every signature before it can be approved.

Rejecting a review throws `LedgerUserRejectedError` (status word `0x6985`).
