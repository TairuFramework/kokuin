/**
 * HD keystore with SLIP-0010 Ed25519 derivation.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/deterministic
 * ```
 *
 * @module hd-keystore
 */

export { derivePrivateKey, resolveDerivationPath } from './derivation.js'
export { HDKeyEntry, type HDKeyEntryParams } from './entry.js'
export { HDKeyStore, type HDKeyStoreParams } from './store.js'
