/**
 * Key store for React Native.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/expo
 * ```
 *
 * @module expo-keystore
 */

export { ExpoKeyEntry, type ExpoKeyEntryParams, type StoreEntryOptions } from './entry.js'
export type { ExpoKeyStoreParams } from './store.js'
export { ExpoKeyStore } from './store.js'
export { randomPrivateKey, randomPrivateKeyAsync } from './utils.js'
