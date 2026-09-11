# `@kokuin/oauth` — React Native fetch transport defeats two hardening guarantees

**Priority:** high — both are credential-disclosure / memory-exhaustion risks on the exact
React Native / expo targets the package was routed through `@sozai/runtime` to support. Neither is a
logic bug in the package; both are cases where the installed RN `fetch` transport silently does not
honour the semantics `fetchOAuthJSON` relies on.
**Origin:** Codex adversarial review of `@kokuin/oauth` (see
`completed/2026-09-11-kokuin-oauth-package.complete.md`). Traced through installed RN source, not
device-tested.

## 1. `redirect: 'error'` is dropped by React Native's `whatwg-fetch`, so a redirect can exfiltrate credentials

`fetchOAuthJSON` (`packages/oauth/src/http.ts`) sends the authorization code + PKCE verifier, the
refresh token, and (confidential mode) the client secret in the POST body, and relies on
`redirect: 'error'` to stop the transport following a redirect. React Native's installed
`whatwg-fetch` polyfill discards the `redirect` option, and the native iOS transport
(`RCTHTTPRequestHandler`) follows redirects. A token endpoint returning a cross-origin 307/308 would
therefore forward those credentials to another host. This reaches the RN fetch path, including Expo's
explicit RN-fetch opt-in; Expo's default fetch uses a different transport that does support redirect
control.

Checking the final response URL after the fact is too late — the body is already sent. The fix must
guarantee the request never follows a redirect: require a transport that rejects redirects (assert /
document the requirement for native runtimes, and/or route native OAuth through a redirect-rejecting
fetch), and fail closed when that guarantee is absent rather than silently trusting `redirect:
'error'`.

## 2. The response-size cap does not bound memory on a non-streaming (XHR) transport

`readCappedText` (`packages/oauth/src/http.ts`) enforces the 1 MB cap by streaming the response body
and re-checking a running total per chunk. When `response.body` has no reader — React Native's
XHR-backed fetch resolves only after the whole response is already buffered — the code falls back to
`response.text()` and checks the length **after** the full body is in memory, then allocates a second
buffer through `TextEncoder`. An oversized token-endpoint response can exhaust application memory
before the advertised limit rejects it; the request deadline does not bound bytes received within the
interval.

A post-buffer check cannot provide a memory bound. The fix needs either a hard requirement for a
streaming transport on these runtimes, or a byte limit enforced inside the transport while it
receives data (e.g. an XHR-level abort once a running byte count is exceeded).

## Shared shape of the fix

Both stem from the leaf package trusting `runtime.fetch` to honour WHATWG-`fetch` semantics that the
RN transport does not. Options to weigh: (a) define and assert a transport-capability contract on the
`Runtime`'s fetch (redirects rejected, streaming body available) and fail closed on native when it is
not met; (b) document the requirement and push the redirect-rejecting / streaming transport choice to
the consumer (kubun / a future mokei adopter) at the point they wire `Runtime`; (c) provide a small
native-safe fetch wrapper in the package. Decide during kubun Phase B adoption, when a real native
consumer exists to test against on-device — the findings above were traced through source, not run on
hardware.
