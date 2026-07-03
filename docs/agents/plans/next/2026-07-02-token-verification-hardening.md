# Token verification hardening

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #3, Medium: nullish guards, peer4 DoS)

## Context

`verifyToken` and its type guards have safety gaps that let a direct consumer be spoofed
or DoS'd. The capability layer is partly shielded, but the token package is a public
primitive and must be safe standalone.

## Work

### `verifyToken` accepts `alg: none` tokens (Critical #3)

`packages/token/src/token.ts:207` (string path) and `:171` (object path) return the
unsigned payload with attacker-chosen claims and skip `exp`/`nbf` validation entirely. The
capability layer is shielded by an `isVerifiedToken` check, but any direct consumer that
does not re-check `isSignedToken`/`mode` is spoofable.

- Fix: reject `alg:none` unless the caller explicitly opts in.
- Document the requirement to check `isVerifiedToken` after `verifyToken`.

### Type guards throw on nullish input (Medium)

`isSignedToken(null)` (`packages/token/src/token.ts:84`) throws `TypeError` instead of
returning `false`, propagating to `assertCapabilityToken(null)`. Guards must be
total — return `false` for nullish.

### peer:4 base58 decode DoS (Medium)

`packages/token/src/peer4.ts:102` allows an encoded doc up to `maxDocSize * 2` = 128 KiB →
O(n²) base58 decode per inbound token. Drop the default `maxDocSize` to a few KiB.

## Out of scope

- Capability authorization model (#1, kid, aud, revocation) — see
  `next/2026-07-02-capability-authorization-fixes.md`.
