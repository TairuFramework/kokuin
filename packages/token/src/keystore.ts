/**
 * A single key slot in a {@link KeyStore}, identified by `keyID`.
 *
 * This is the **read/provide** facet — the floor every backend can honor, including ones
 * that derive keys rather than store them (HD) or never expose key material at all.
 * A backend that can also write and delete implements {@link MutableKeyEntry}.
 *
 * ## Invariants
 *
 * Enforced by `keyStoreConformanceCases`. A backend that cannot satisfy these does not
 * implement this type — it exposes a different surface instead.
 *
 * 1. **keyID round-trips.** `store.entry(x).keyID === x`, always.
 * 2. **Absent means `null`.** {@link getAsync} resolves `null` when no key exists. Never
 *    `undefined`, never a throw. A *derived* backend may never return `null` at all —
 *    it can always produce a key — and that is contract-legal.
 * 3. **{@link provideAsync} is idempotent under concurrency.** Two concurrent calls on one
 *    keyID resolve to the *same* key. Never two keys; never a key that is generated,
 *    returned to a caller, and then overwritten by a racer.
 */
export type KeyEntry<PrivateKeyType> = {
  /** The keyID this entry was created for. Identical to the string passed to `entry()`. */
  readonly keyID: string
  /** The stored key, or `null` when none exists. Never `undefined`; never throws for absence. */
  getAsync(): Promise<PrivateKeyType | null>
  /**
   * The stored key, generating and persisting one if absent.
   *
   * Idempotent under concurrency: racing callers converge on a single key. Backends that
   * share storage across processes need a cross-process lock to hold this (see `lockPath`
   * on `NodeKeyStore` / `ElectronKeyStore`); an in-process promise chain is not enough.
   */
  provideAsync(): Promise<PrivateKeyType>
}

/**
 * A {@link KeyEntry} on a backend that can also **write and delete** key material.
 *
 * HD and ledger backends deliberately do NOT implement this: an HD key is derived (there is
 * nothing to set, and removing it does not stop it being derivable), and a ledger key never
 * leaves the device. Previously they "conformed" by throwing from `setAsync` and silently
 * no-op'ing `removeAsync` — the type now says what the substrate can do, so there is nothing
 * to throw from.
 */
export type MutableKeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType> & {
  /** Persist `privateKey` under this entry's keyID, replacing any existing key. */
  setAsync(privateKey: PrivateKeyType): Promise<void>
  /** Delete this entry's key. Idempotent — removing an absent key resolves, it does not throw. */
  removeAsync(): Promise<void>
}

/**
 * A keyed collection of {@link KeyEntry}s.
 *
 * Parameterized by entry type, so a writable backend is `KeyStore<T, MutableKeyEntry<T>>`
 * and a derived one is `KeyStore<T, KeyEntry<T>>`. No separate mutable store type is needed.
 *
 * Most consumers should NOT be generic over this — they should be generic over
 * `IdentityProvider`, which is what "give me an identity for this keyID" actually needs.
 * `KeyStore` is the *storage* contract, useful to backend authors and to the conformance
 * suite. A backend whose key never leaves the device (ledger) implements `IdentityProvider`
 * and neither storage type; that is the contract working, not a gap.
 */
export type KeyStore<
  PrivateKeyType,
  EntryType extends KeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType>,
> = {
  /**
   * The entry for `keyID`.
   *
   * Must be **cached**: `store.entry(x) === store.entry(x)`. Entries carry per-entry
   * concurrency state (the `provideAsync` lock), so handing out a fresh entry per call
   * silently defeats it.
   */
  entry(keyID: string): EntryType
}
