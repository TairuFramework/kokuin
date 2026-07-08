# Kokuin Ledger App

BOLOS application for Ledger Nano S+ providing Ed25519 signing and X25519 ECDH key agreement for Kokuin identity.

## APDU Protocol

**CLA**: `0xE0`

| INS | Command | Input | Output | Confirmation |
|-----|---------|-------|--------|-------------|
| `0x01` | `GET_APP_VERSION` | none | 3 bytes (major, minor, patch) | No |
| `0x02` | `GET_PUBLIC_KEY` | encoded path | 32-byte Ed25519 public key | No |
| `0x03` | `SIGN_MESSAGE` | encoded path + chunked message | 64-byte Ed25519 signature | Yes |
| `0x04` | `ECDH_X25519` | encoded path + 32-byte ephemeral key | 32-byte shared secret | Yes |

### Derivation Path Encoding

```
[component_count: 1 byte] [components: 4 bytes each, big-endian with hardened bit]
```

All components must be hardened (SLIP-0010 Ed25519). Example: `m/44'/876'/0'` encodes as `03 8000002C 8000036C 80000000`.

### SIGN_MESSAGE Chunking

| P1 | P2 | Meaning |
|----|-----|---------|
| `0x00` | `0x00` | First and only chunk — includes path + message, triggers signing |
| `0x00` | `0x80` | First chunk of multi-chunk — includes path + message start, more to come |
| `0x80` | `0x80` | Continuation chunk — message data, more to come |
| `0x80` | `0x00` | Last continuation chunk — triggers signing |

### Status Words

| Code | Meaning |
|------|---------|
| `0x9000` | Success |
| `0x6700` | Wrong data length |
| `0x6985` | User rejected |
| `0x6A80` | Invalid data |
| `0x6A82` | App not open |
| `0x6D00` | Unknown INS |
| `0x6E00` | Unknown CLA |
| `0x6F00` | Internal error |

### Approval screens

`SIGN_MESSAGE` and `ECDH_X25519` require explicit on-device approval — no signature or
shared secret leaves the device without pressing Approve. The confirmation is rendered
with NBGL (the Nano S+ SDK retired BAGL at this API level).

**Sign message** review: title *"Review message"*, then **Account** (the derivation path,
e.g. `44'/876'/0'`), then **Digest** — the full SHA-256 of the message shown as 64 hex
chars (paginated), then *"Sign message"* (Approve) / *"Reject message"*.

**Key agreement** review: title *"Review key agreement"*, then **Account**, then
**Peer key** — the full SHA-256 of the peer's ephemeral X25519 public key (64 hex,
paginated), then *"Agree key"* (Approve) / *"Reject operation"*.

The digest is shown in full rather than truncated — a truncated hash is grindable. It is
tamper-evidence for a trusted host to compare against; the on-device screen alone is not a
MITM defense. Rejecting either review returns `0x6985` (User rejected).

## Build

Requires Docker.

```bash
cd apps/ledger

# Build only
docker compose run --rm build

# Build output: bin/app.elf
```

The build uses `ghcr.io/ledgerhq/ledger-app-builder` targeting the Nano S+ SDK (API level 25) with SLIP-0010 Ed25519 derivation.

## Test

Integration tests run against the Speculos emulator using a deterministic mnemonic seed.

```bash
# From repo root — builds if needed, starts Speculos, runs the suite, stops emulator
./tests/ledger/test-speculos.sh

# Force rebuild
./tests/ledger/test-speculos.sh --build

# Keep Speculos running after tests (for debugging)
./tests/ledger/test-speculos.sh --keep
```

Speculos exposes port 9999 (configurable via `SPECULOS_PORT`) for its REST API.

### What the tests verify

15 integration tests in `tests/ledger/test/speculos.test.ts`:

- **APDU protocol**: version, public key derivation (deterministic, path-dependent)
- **IdentityProvider**: `provideIdentity()` returns `FullIdentity` with `did:key:z...` DID
- **Signing**: `signToken()` produces JWTs verifiable by standard Ed25519 verification
- **ECDH**: `agreeKey()` performs X25519 key agreement, `decrypt()` decrypts JWE
- **Review rejection and guards**: rejecting the SIGN or ECDH review returns `0x6985`; a stray continuation chunk after a completed signature returns `0x6A80`
- **Cross-compatibility**: same mnemonic produces identical DIDs, signatures, and shared secrets as `@kokuin/deterministic`

The suite runs unattended: the harness posts a Speculos automation ruleset that drives the NBGL review to Approve (and, for the rejection tests, to Reject).

Tests auto-skip if Speculos is not available.

## TypeScript Client

The `@kokuin/ledger-device` package provides the TypeScript client. See `packages/ledger-device/`.

```ts
import TransportNodeHID from '@ledgerhq/hw-transport-node-hid'
import { createLedgerIdentityProvider } from '@kokuin/ledger-device'

const transport = await TransportNodeHID.create()
const provider = createLedgerIdentityProvider(transport)
const identity = await provider.provideIdentity('0')
// identity.id → "did:key:z6Mk..."
// identity.signToken(payload) → signed JWT
// identity.agreeKey(ephemeralPubkey) → X25519 shared secret
// identity.decrypt(jwe) → decrypted plaintext
```

## SDK Implementation Notes

### Ed25519 Public Key Compression

The BOLOS SDK returns Ed25519 public keys in 65-byte uncompressed format: `0x04 || X(32, big-endian) || Y(32, big-endian)`. Converting to the standard 32-byte compressed format (RFC 8032) requires reversing Y from big-endian to little-endian and encoding the sign of X in the MSB — the same approach used by the Solana and Stellar Ledger apps.

### X25519 ECDH

Uses the `cx_x25519` SDK syscall for direct Montgomery scalar multiplication. The Ed25519 private key seed is converted to an X25519 scalar via SHA-512 + clamp (RFC 7748). `cx_x25519` accepts the u-coordinate and scalar in little-endian (standard X25519), but its output is big-endian (from `cx_bn_export`) and must be reversed. The SDK applies RFC 7748 clamping internally.

### SDK Functions

| Function | Purpose |
|----------|---------|
| `bip32_derive_with_seed_init_privkey_256(HDW_ED25519_SLIP10, ...)` | SLIP-10 Ed25519 key derivation |
| `bip32_derive_with_seed_get_pubkey_256(HDW_ED25519_SLIP10, ...)` | Ed25519 public key (65-byte uncompressed) |
| `cx_eddsa_sign_no_throw` | Ed25519 signing |
| `cx_hash_sha512` | SHA-512 for Ed25519→X25519 scalar conversion |
| `cx_x25519` | X25519 scalar multiplication |
