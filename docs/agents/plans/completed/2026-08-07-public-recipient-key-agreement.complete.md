# No public path to a recipient's X25519 key

**Status:** complete — resolved by `completed/2026-08-07-derive-shared-secret.complete.md`.
**Priority:** low. A consumer needing this had a working alternative; the ask was to remove a
cost, not to unblock anything.
**Origin:** kubun's credential store, 2026-08-07. Filed from kubun; no changes were made here at
filing time.

## Context

Resolving a recipient DID to the X25519 public key you encrypt to has two branches, and
picking the wrong one produces a key that encrypts cleanly and silently never decrypts:

- A **peer:4** identity carries an independent agreement key in its document, and the sender
  MUST use the published key. `getAgreementKey` (`did.ts:210`) reads it.
- A **did:key** EdDSA identity publishes none — `getAgreementKey` returns `null` — and the
  sender derives one from the signing key via the birational map.

`did.ts:202-208` states the hazard outright. `resolveX25519Key` (`jwe.ts:136`) is the function
that picks, and it is **module-private**: `createTokenEncrypter` is its only caller. It also
refuses a peer:4 short form, which is correct and worth keeping — the document lives in the
long form.

Measured on both branches from kubun (probe, 2026-08-07): for one peer:4 identity, the
published agreement key and the birationally derived one differ (`4b1f36cc…` vs `43269842…`),
and so do the resulting shared secrets (`ab6ad0e9…` vs `48005768…`). Nothing throws on either
side. `getAgreementKey` on a did:key document returns `null`, as documented.

## What a consumer wanting raw key agreement has to do

Kubun's credential store needs a 32-byte secret that only a named recipient can recover, then
combines it with other factor secrets via HKDF. A raw ECDH would be the direct route, and
there is no public way to get the right public key for one.

The two options were: copy the branch logic into kubun, or go through the JWE. Copying was
rejected — a second implementation of a rule whose failure mode is silent, in a different
repo, on a different release cadence. So kubun generates a random 32-byte secret and ships it
to the recipient with `encryptToken(createTokenEncrypter(did), secret)`, recovering it with
`decryptToken`. `createTokenEncrypter` calls `resolveX25519Key` internally, so there is still
exactly one implementation of the branch rule and it is this package's.

That works and kubun is not blocked. The cost is a JWE (~200 bytes and a second AEAD pass) per
`did` factor per wrapping, to obtain a secret the recipient could have derived.

## The ask

Export something that yields a recipient's agreement key, or a shared secret with it, without
going through a JWE. Any of these would do:

- `resolveX25519Key` itself, or a narrower `getRecipientAgreementKey(did): Uint8Array` — same
  two branches, same refusal on a peer:4 short form.
- A `deriveSharedSecret(did, ephemeralPrivateKey)` that keeps the branch choice inside this
  package, which is the safer shape: a consumer never holds the resolved key and cannot use
  the wrong branch by accident.

The second is preferable if you want the rule to stay unleakable. The first is a one-line
export.

## Not part of this

`getAgreementKey` is already public and already correct. The gap is only the **branch
selection** around it — a caller holding a DID string, rather than a resolved document, has no
supported way to reach the right key.

Also worth noting for whoever takes it: `pickAgreementSecret` (`identity.ts:330`) is the
recipient-side mirror and already handles both branches, including refusing the birational
fallback for a peer identity (`identity.ts:348`) — so a peer:4 identity built with no KEM key
throws `No KEM key in identity` from `agreeKey`. That asymmetry is correct, but it means "this
identity can decrypt" is not inferable from its type, only from `isDecryptingIdentity`.
