# @kokuin/keystore-conformance

Framework-agnostic conformance suite for `KeyStore` / `KeyEntry` backends.

Private — every `@kokuin` keystore backend runs it in its own tests. Each case is a
plain function that throws on violation, so any runner can drive it:

```ts
import { mutableKeyStoreConformanceCases } from '@kokuin/keystore-conformance'

const cases = mutableKeyStoreConformanceCases({
  createStore: () => new MyKeyStore('service'),
  isSameKey: sameBytes,
  createKey: () => crypto.getRandomValues(new Uint8Array(32)),
})

for (const conformanceCase of cases) {
  test(conformanceCase.name, () => conformanceCase.run())
}
```

The suite itself is meta-tested (`test/index.test.ts`) against deliberately-broken
stores, so its checks are proven to have teeth rather than merely asserted.
