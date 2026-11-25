# @kokuin/oauth

Generic OAuth 2.0 client primitives for kokuin: PKCE, hardened HTTP with
structured OAuth errors, the authorization-code and refresh-token exchanges, and
a pending-authorization orchestration + store port.

A true leaf package — depends only on `@sozai/runtime`, `@noble/hashes`, and
`@sozai/codec`. It owns no application-specific concern (no DID/credential
wrapping, no connector registry, no MCP resource discovery, no provider-specific
authorization policy).

## Client credentials (private_key_jwt)

`createClientAssertion` builds a signed JWT client assertion (EdDSA or ES256) and
`requestClientCredentialsToken` sends it to the token endpoint with the
`client_credentials` grant. The assertion `audience` is the authorisation
server's `issuer`. `createWebCryptoAssertionSigner` provides a signer backed by
`crypto.subtle`; any `ClientAssertionSigner` works. Algorithms other than `EdDSA`
and `ES256` are rejected at runtime with `Unsupported client assertion algorithm`.

```ts
import {
  createClientAssertion,
  createWebCryptoAssertionSigner,
  requestClientCredentialsToken,
} from '@kokuin/oauth'

const signer = createWebCryptoAssertionSigner({ alg: 'ES256', privateKey, kid: 'key-1' })
const assertion = await createClientAssertion({
  signer,
  clientID: 'my-client',
  audience: 'https://auth.example.com', // the authorisation server issuer
  runtime, // optional, source of randomness for `jti`, defaults to `globalThis.crypto`
})
const token = await requestClientCredentialsToken({
  runtime,
  tokenEndpoint: 'https://auth.example.com/token',
  clientID: 'my-client',
  assertion,
  scope: 'read',
  extraParams: { resource: 'https://mcp.example.com/' },
})
```

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new OAuthTokenError` | `OAuthTokenErrorParams` | `status, code?, description?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
