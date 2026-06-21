/**
 * Key store for browser.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/browser
 * ```
 *
 * @module browser-keystore
 */

export { BrowserKeyEntry } from './entry.js'
export { provideSigningIdentity } from './identity.js'
export { BrowserKeyStore } from './store.js'
export { getPublicKey, randomKeyPair } from './utils.js'
