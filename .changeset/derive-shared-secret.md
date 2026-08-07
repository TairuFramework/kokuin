---
'@kokuin/token': patch
---

New `deriveSharedSecret(did)` performs X25519 key agreement with a recipient DID directly, without
building a JWE to carry a secret that the recipient could have derived.

Resolving a recipient DID to the key you encrypt to has two branches — a `did:peer:4` identity
publishes an independent `keyAgreement` key that the sender MUST use, while an EdDSA `did:key`
publishes none and the sender derives one from the signing key via the birational map. Picking the
wrong branch produces a key that encrypts cleanly and silently never decrypts. Until now that rule
lived in a module-private function reachable only through `createTokenEncrypter`, so a consumer
wanting a plain ECDH secret had to either reimplement it or ship a random secret inside a JWE it
did not otherwise need.

`deriveSharedSecret` generates the ephemeral key pair internally and returns
`{ sharedSecret, ephemeralPublicKey }`. The ephemeral private key never leaves the function and
the caller never holds the resolved recipient key, so neither the branch choice nor ephemeral key
hygiene can be got wrong from outside. The recipient recovers the identical bytes with the existing
`identity.agreeKey(ephemeralPublicKey)`.

```ts
const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipientDID)
// recipient, unchanged API:
const sharedSecret = await identity.agreeKey(ephemeralPublicKey)
```

`sharedSecret` is the raw ECDH output, not a key — it is not uniformly random, so run it through a
KDF with your own domain separation before use. It is returned raw precisely so that it mirrors
`agreeKey` byte for byte.

Errors are inherited unchanged from the resolution `createTokenEncrypter` already performs: a
`did:peer:4` short form is refused (the document lives in the long form), as is a long form
publishing no usable X25519 `keyAgreement` entry, as is any non-EdDSA `did:key`.
