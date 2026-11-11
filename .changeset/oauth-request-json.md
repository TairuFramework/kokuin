---
"@kokuin/oauth": minor
---

Add `requestOAuthJSON`, which returns the status and parsed body, accepts custom headers and does not throw on a non-2xx status (`fetchOAuthJSON` now wraps it). `buildAuthorizationURL` takes an optional `codeChallenge`. The loopback check now comes from `@sozai/http-util`, so `*.localhost` no longer counts as loopback.
