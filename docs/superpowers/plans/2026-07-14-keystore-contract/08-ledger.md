# Ledger — document identity-only conformance

Task 12. The smallest task in the plan, and the one that proves the contract is right.

`@kokuin/ledger-device` implements **neither** `KeyStore` nor `KeyEntry` — it only implements `IdentityProvider`. That is already true today, and under the old contract it read as a gap: the one backend that couldn't fake `setAsync` simply didn't participate. Under the faceted contract it is the intended shape. A backend whose key never leaves the device is first-class (spec invariant 4), and this task writes that down and pins it.

**Files:**
- Modify: `packages/ledger-device/src/provider.ts` (JSDoc on `createLedgerIdentityProvider`)
- Create: `packages/ledger-device/test/contract.test.ts`

**Interfaces:**
- Consumes: `IdentityProvider`, `KeyEntry`, `KeyStore` (types only) from `@kokuin/token`.
- Produces: nothing new. This task changes no runtime behavior.

- [ ] **Step 1: Write the test**

Create `packages/ledger-device/test/contract.test.ts`. Reuse `createMockTransport` from `packages/ledger-device/test/provider.test.ts:13-50` — copy it verbatim (it is not exported) rather than inventing a second mock. It answers `GET_PUBLIC_KEY`, `SIGN_MESSAGE`, and `ECDH_X25519` from a fixed Ed25519 test key.

```ts
import type { FullIdentity, IdentityProvider } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createLedgerIdentityProvider } from '../src/provider.js'

// ... paste createMockTransport() from provider.test.ts:13-50 verbatim, with its
// TEST_PRIVATE_KEY / TEST_PUBLIC_KEY constants and the CLA / INS / ed25519 / x25519 imports ...

describe('ledger implements IdentityProvider and neither storage type', () => {
  test('conforms to IdentityProvider structurally', () => {
    // A compile-time assertion: if the return type ever stops satisfying IdentityProvider,
    // test:types fails. The runtime check below is the belt to that suspenders.
    const provider: IdentityProvider<FullIdentity> = createLedgerIdentityProvider(createMockTransport())
    expect(typeof provider.provideIdentity).toBe('function')
  })

  test('exposes no KeyStore or KeyEntry surface — the key never leaves the device', () => {
    const provider = createLedgerIdentityProvider(createMockTransport()) as Record<string, unknown>

    // This is the contract working, not an omission. There is no key material to get, set,
    // or remove: the private key is generated on-device and never leaves it. Under the old
    // contract this backend would have had to "conform" by throwing from setAsync — which is
    // exactly the lie the faceted contract exists to remove.
    expect(provider.entry).toBeUndefined()
    expect(provider.getAsync).toBeUndefined()
    expect(provider.setAsync).toBeUndefined()
    expect(provider.provideAsync).toBeUndefined()
    expect(provider.removeAsync).toBeUndefined()
  })

  test('provideIdentity yields a did:key EdDSA FullIdentity', async () => {
    const provider = createLedgerIdentityProvider(createMockTransport())
    const identity = await provider.provideIdentity('0')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(typeof identity.signToken).toBe('function')
    expect(typeof identity.decrypt).toBe('function')
    expect(typeof identity.agreeKey).toBe('function')
  })
})
```

- [ ] **Step 2: Run it**

Run from `packages/ledger-device`: `pnpm exec vitest run test/contract.test.ts`

Expected: PASS immediately. Nothing in the source changes — this task pins existing behavior so a future refactor cannot quietly bolt a fake storage surface onto it.

If it fails, the mock transport was pasted wrong; fix the test, not the source.

- [ ] **Step 3: Document the intent on the provider**

In `packages/ledger-device/src/provider.ts`, extend the JSDoc on `createLedgerIdentityProvider` (currently undocumented, at line 60):

```ts
/**
 * An {@link IdentityProvider} backed by a Ledger device.
 *
 * Implements `IdentityProvider` and **deliberately neither `KeyStore` nor `KeyEntry`**. The
 * private key is generated on-device from the seed and never leaves it: there is nothing to
 * `getAsync`, nothing to `setAsync`, and `removeAsync` would be meaningless. Signing and ECDH
 * happen on the device, behind on-device user consent.
 *
 * This is the storage contract working as designed, not a gap in this package — a backend that
 * cannot expose key material implements the identity contract and skips the storage one. See
 * `KeyEntry` in `@kokuin/token` for the invariants the storage-backed keystores hold instead.
 *
 * Identities are cached per resolved derivation path, so repeated `provideIdentity` calls for
 * one keyID hit the device once.
 */
```

- [ ] **Step 4: Commit**

```bash
git add packages/ledger-device
git commit -m "$(cat <<'EOF'
docs(ledger-device): document IdentityProvider-only conformance

Ledger implements neither KeyStore nor KeyEntry, and that is the faceted contract
working: a backend whose key never leaves the device implements the identity
contract and skips the storage one. Pinned with a test so a future refactor cannot
bolt a fake storage surface onto it.
EOF
)"
```
