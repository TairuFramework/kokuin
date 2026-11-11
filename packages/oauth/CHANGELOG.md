# @kokuin/oauth

## 0.7.4

### Patch Changes

- `buildAuthorizationURL` omits the `scope` parameter when no scopes are requested, rather than sending an empty `scope=` that strict authorization servers reject (RFC 6749 makes `scope` optional).

## 0.7.3

### Patch Changes

- `fetchOAuthJSON` resolves `undefined` for an empty (or whitespace-only) success body by default, as RFC 7009 token revocation answers `200` with no content. Pass `allowEmpty: false` to reject it as invalid JSON. Token endpoints that answer empty now fail with `OAuth token response was not an object`.

## 0.7.2

### Patch Changes

- `exchangeCode` and `refreshToken` accept `extraParams` (for example `resource` per RFC 8707, or `scope`), which never override the grant's own fields. `fetchOAuthJSON` accepts `method: 'GET'` for metadata reads with no body. The loopback rule now also accepts `http` on `*.localhost` hosts.

## 0.7.1

### Patch Changes

- Device authorization grant (RFC 8628): `startDeviceAuthorization` requests a device and user code, and `pollDeviceToken` polls the token endpoint, honouring `interval`, `slow_down`, `authorization_pending`, `expires_in` and an abort signal.

  Broker mode: a provider can route authorize, code exchange and refresh through an `OAuthBrokerTransport` instead of calling the provider directly, so a server holds the client secret. `createHTTPBrokerTransport` implements the HTTP contract (`POST {baseURL}/oauth/{provider}/authorize` and `/token`). The pending authorization record keeps the broker's `transactionToken`. `StartAuthorizationParams`, `CompleteAuthorizationParams` and `RefreshTokenParams` are exported.

## 0.7.0

### Minor Changes

- Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

  All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
