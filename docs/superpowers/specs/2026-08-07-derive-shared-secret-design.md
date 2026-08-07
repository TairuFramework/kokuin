# Public key agreement to a recipient DID

**Date:** 2026-08-07
**Package:** `@kokuin/token`
**Origin plan:** `docs/agents/plans/next/2026-08-07-public-recipient-key-agreement.md`

## Problem

Resolving a recipient DID to the X25519 public key you encrypt to has two branches, and picking
the wrong one produces a key that encrypts cleanly and silently never decrypts:

- A **did:peer:4** identity carries an independent agreement key in its document, and the sender
  MUST use the published key. `getAgreementKey` (`did.ts`) reads it.
- A **did:key** EdDSA identity publishes none — `getAgreementKey` returns `null` — and the sender
  derives one from the signing key via the birational map.

`resolveX25519Key` (`jwe.ts`) is the function that picks between them, and it is module-private:
`createTokenEncrypter` is its only caller. A consumer holding a DID string has no supported way to
reach the right public key, so a consumer wanting a plain ECDH shared secret must either
reimplement the branch rule or route through a JWE it does not need.

Kubun's credential store hit this. It needs a 32-byte secret only a named recipient can recover,
which it then combines with other factor secrets via HKDF. Reimplementing the branch rule in
kubun was rejected — a second implementation of a rule whose failure mode is silent, in a
different repo on a different release cadence — so kubun ships a random secret inside a JWE via
`createTokenEncrypter`/`encryptToken` and recovers it with `decryptToken`. That works; the cost is
roughly 200 bytes and a second AEAD pass per `did` factor per wrapping, to transport a secret the
recipient could have derived.

## Goal

Export a supported way to perform key agreement with a recipient DID, without going through a JWE
and without exposing the branch choice to the caller.

## API

A new export from `@kokuin/token`, defined in `jwe.ts` alongside `resolveX25519Key`:

```ts
export type SharedSecretResult = {
  /** Raw X25519 ECDH output. Not uniform bytes — pass through a KDF before use as a key. */
  sharedSecret: Uint8Array
  /** Send to the recipient; they recover the secret via `identity.agreeKey(ephemeralPublicKey)`. */
  ephemeralPublicKey: Uint8Array
}

export function deriveSharedSecret(recipient: string): SharedSecretResult
```

Usage, sender and recipient:

```ts
const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipientDID)
// ship ephemeralPublicKey alongside whatever the secret protects

// recipient, using the existing DecryptingIdentity API
const sharedSecret = await identity.agreeKey(ephemeralPublicKey)
```

### Decisions

**Full encapsulation.** The function generates the ephemeral X25519 pair internally and returns
only the public half. The ephemeral private key never leaves the function, and the caller never
holds the resolved recipient key. Both halves of the hazard — the branch choice and ephemeral key
hygiene — stay inside the package. This is stricter than the origin plan's
`deriveSharedSecret(did, ephemeralPrivateKey)`, which still made the caller generate and manage
the ephemeral key.

**Raw shared secret, no KDF.** The return value is the raw ECDH output, byte-identical to what
`DecryptingIdentity#agreeKey(ephemeralPublicKey)` returns on the recipient side. This means zero
new recipient-side API: the existing `agreeKey` is already the exact mirror. Applying a KDF inside
would produce a value `agreeKey` cannot reproduce, forcing a second new export to mirror it, and
consumers such as kubun already run their own KDF downstream with their own domain separation. The
JSDoc states plainly that the output is not uniformly random and must be run through a KDF before
use as a key.

**DID strings only.** No `Uint8Array` overload, unlike `createTokenEncrypter`. A caller who
already holds a raw X25519 public key has resolved the branch themselves and can call
`x25519.getSharedSecret` directly; adding the overload would only widen the surface.

**Synchronous.** `resolveX25519Key` is synchronous and deliberately refuses a did:peer:4 short
form rather than resolving it, since resolution would need an awaitable `DIDResolver`. That
refusal is correct and is inherited unchanged.

### Errors

All error behavior is inherited from `resolveX25519Key`, so the new export and
`createTokenEncrypter` fail identically on the same input:

- did:peer:4 short form: `Cannot encrypt to a did:peer:4 short form: <did>. Pass the long form,
  which carries the document.`
- did:peer:4 long form whose document publishes no usable X25519 `keyAgreement` entry:
  `Recipient publishes no X25519 keyAgreement key: <short form>`
- Any non-EdDSA, non-peer:4 DID: `Unsupported DID algorithm for encryption: <algorithm>`

No additional low-order-point check is needed. `noble/curves` already throws
`invalid private or public key received` from `scalarMult` when the ECDH result is the identity
(`@noble/curves/abstract/montgomery.js`), which covers the small-subgroup case.

## Implementation

`encryptWithX25519` currently generates the ephemeral pair and performs the ECDH inline before
running Concat KDF. That is the same three lines `deriveSharedSecret` needs, so extract them into
a module-private helper rather than writing the ECDH twice in one file:

```ts
function agreeWithKey(recipientPublicKey: Uint8Array): SharedSecretResult {
  const ephemeralPrivateKey = x25519.utils.randomSecretKey()
  return {
    ephemeralPublicKey: x25519.getPublicKey(ephemeralPrivateKey),
    sharedSecret: x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey),
  }
}
```

`encryptWithX25519` calls it and continues into Concat KDF unchanged. `deriveSharedSecret` is then
`resolveX25519Key` followed by `agreeWithKey`. One ECDH implementation in the file, and the
sender-side path the JWE uses is the path the new export uses.

Export `deriveSharedSecret` and the `SharedSecretResult` type from `index.ts`, in the existing
`./jwe.js` export blocks. `resolveX25519Key` stays private.

## Testing

New cases in the token package's test suite, covering both branches and the refusals:

1. **peer:4 round trip.** For a peer:4 identity with a published KEM key, `deriveSharedSecret` on
   the long form and `identity.agreeKey(ephemeralPublicKey)` produce identical bytes.
2. **did:key round trip.** Same equality for a did:key EdDSA identity, exercising the birational
   branch on both sides.
3. **Branch guard.** For a peer:4 identity, the shared secret differs from the one a birational
   derivation off the signing key would produce. This is the kubun probe reproduced as a
   regression test: it is the assertion that fails if the branch rule is ever inverted, and
   neither round-trip test above would catch that on its own.
4. **Short form refused.** A peer:4 short form throws, with the message naming the long form.
5. **No agreement key.** A peer:4 long form whose document publishes no usable X25519
   `keyAgreement` entry throws.
6. **Unsupported algorithm.** A non-EdDSA, non-peer:4 DID throws.

## Release and follow-up

- Changeset: minor bump for `@kokuin/token`. It is in the fixed release group, so token,
  capability, browser, node, and deterministic bump together.
- Move `docs/agents/plans/next/2026-08-07-public-recipient-key-agreement.md` to `completed/` per
  the repo plan lifecycle.
- Kubun swapping its JWE-wrapped random secret for `deriveSharedSecret` is a kubun change, tracked
  there, not part of this work.

## Out of scope

- `getAgreementKey` is already public and already correct; it is untouched.
- `pickAgreementSecret` (`identity.ts`) is the recipient-side mirror and already handles both
  branches, including refusing the birational fallback for a peer identity. A peer:4 identity
  built with no KEM key therefore throws `No KEM key in identity` from `agreeKey`. That asymmetry
  is intentional and unchanged here; it does mean "this identity can decrypt" is not inferable
  from its DID method, only from `isDecryptingIdentity`.
- Resolving a peer:4 short form through a `DIDResolver` — an async variant of this API — is not
  needed by any consumer today.
