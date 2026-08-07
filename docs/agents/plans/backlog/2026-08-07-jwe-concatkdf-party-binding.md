# The JWE path binds no party identity into its Concat KDF

**Status:** backlog
**Priority:** low. Not a vulnerability, and not blocking anything — this is a
standards-alignment question, raised because the behaviour was surprising when written down.
**Origin:** surfaced while documenting the raw key agreement API, 2026-08-07 — see
`completed/2026-08-07-derive-shared-secret.complete.md`.

## What was found

`encryptWithX25519` derives the content encryption key with:

- `algorithmID: 'A256GCM'` — a fixed constant equal to the JWE `enc` value, not a per-message or
  per-party identifier
- `partyUInfo` and `partyVInfo` both hardcoded to an empty `Uint8Array`

It also never sets `apu` or `apv` on the protected header, so `decryptToken`'s
`header.apu != null ? ... : new Uint8Array(0)` reads always take the empty branch. Sender and
recipient agree, because both sides derive from the same empty inputs.

The consequence is that no party identity — not the ephemeral public key, not the recipient DID —
reaches the Concat KDF. RFC 7518 §4.6.2 permits empty `PartyUInfo`/`PartyVInfo`, so this is
conformant; NIST SP 800-56A §5.8.1.2 calls for party identities in OtherInfo, so it is not aligned
with that recommendation.

## Why it is not a vulnerability today

The ephemeral public key is still bound per-message, just not through the KDF: it travels in the
protected header, and the encoded header is the AES-GCM AAD (RFC 7516 §5.1 step 14). A ciphertext
therefore cannot be replayed under a different ephemeral key without the tag failing. Each message
also derives a fresh content key from a fresh ephemeral scalar, so there is no cross-message key
reuse to exploit.

## What a change would involve

Setting `apu` to the ephemeral public key and `apv` to the recipient DID, then feeding both into
`concatKDF`, is the conventional shape. Note this is a **wire-format change**: a token encrypted by
a new sender derives a different content key than an old recipient would compute, so old and new
would not interoperate. That is what makes it a considered change rather than a quiet hardening,
and it is why this is filed rather than fixed.

Worth checking against `@enkaku` and `@kumiai` before touching, since both consume the JWE path.
