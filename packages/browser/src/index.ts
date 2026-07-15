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

export { BrowserKeyEntry, type GetStore } from './entry.js'
export { BrowserKeyStore } from './store.js'
export {
  assertEd25519Available,
  type BrowserKeyRecord,
  generateKeyRecord,
  isLegacyES256Record,
  type LegacyES256Record,
  type StoredKeyRecord,
} from './utils.js'
