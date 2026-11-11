---
"@kokuin/oauth": minor
---

`createHTTPBrokerTransport` accepts `baseURL` as a string or a function (sync or async) that runs on every request, so the broker address can be resolved lazily.
