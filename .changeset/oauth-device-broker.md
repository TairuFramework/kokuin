---
"@kokuin/oauth": minor
---

Device authorization grant (RFC 8628): `startDeviceAuthorization` requests a device and user code, and `pollDeviceToken` polls the token endpoint, honouring `interval`, `slow_down`, `authorization_pending`, `expires_in` and an abort signal.

Broker mode: a provider can route authorize, code exchange and refresh through an `OAuthBrokerTransport` instead of calling the provider directly, so a server holds the client secret. `createHTTPBrokerTransport` implements the HTTP contract (`POST {baseURL}/oauth/{provider}/authorize` and `/token`). The pending authorization record keeps the broker's `transactionToken`. `StartAuthorizationParams`, `CompleteAuthorizationParams` and `RefreshTokenParams` are exported.
