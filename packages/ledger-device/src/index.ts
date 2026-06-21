/**
 * Ledger hardware wallet identity provider.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/ledger-device
 * ```
 *
 * @module ledger-identity
 */

export { type APDUChunk, CLA, encodeDerivationPath, encodeSignMessageChunks, INS } from './apdu.js'
export {
  LedgerAppNotOpenError,
  LedgerDisconnectedError,
  LedgerError,
  LedgerUserRejectedError,
} from './errors.js'
export { createLedgerIdentityProvider, type LedgerIdentityProviderOptions } from './provider.js'
export type { LedgerTransport } from './types.js'
