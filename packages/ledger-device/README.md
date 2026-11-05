# @kokuin/ledger-device

## Installation

```sh
npm install @kokuin/ledger-device
```

## Transport timeouts

`signToken()` and `agreeKey()` require explicit approval on the device. The APDU response
only arrives once the user presses Approve, so `LedgerTransport.send()` stays pending for as
long as the person takes to read the review screens — potentially minutes.

Transports built on `@ledgerhq/hw-transport-*` have no APDU timeout by default and work as
is. If you supply your own `LedgerTransport`, do not impose a short timeout on
`SIGN_MESSAGE` (`0x03`) or `ECDH_X25519` (`0x04`) — a transport that gives up after a few
seconds will abort every signature before it can be approved.

Rejecting a review throws `LedgerUserRejectedError` (status word `0x6985`).

## Verification dependency update to 0.7.0

This dependency patch joins the strict-token cutover. Hardware APDU signing, construction options and the device protocol remain unchanged.
Ledger construction gains no crypto option. Verification selects providers through token, capability or controller options.
The default verifier rejects crafted ZIP-215-only signatures on reverification, without a historical rescan or version gate.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new LedgerError` | `LedgerErrorParams` | `message, statusCode` |
| `new LedgerDisconnectedError` | `LedgerDisconnectedErrorParams` | `cause?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `encodeSignMessageChunks` | `EncodeSignMessageChunksParams` | `encodeSignMessageChunks(pathBytes: Uint8Array, message: Uint8Array)` |
| `createLedgerIdentityProvider` | `CreateLedgerIdentityProviderParams` | `createLedgerIdentityProvider(params: CreateLedgerIdentityProviderParams)` |
