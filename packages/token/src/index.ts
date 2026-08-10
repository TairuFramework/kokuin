/**
 * JWT signing and verification.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/token
 * ```
 *
 * @module token
 */

export {
  type CreateInMemoryDIDCacheOptions,
  createInMemoryDIDCache,
  type DIDCache,
  type DIDResolver,
} from './cache.js'
export {
  CODECS,
  getAgreementKey,
  getAlgorithmAndPublicKey,
  getDID,
  getSignatureInfo,
  isUnresolvableIssuerError,
  normalizeDID,
  type ResolveIssuerHeader,
  type ResolveIssuerWithDocResult,
  resolveIssuer,
  resolveIssuerWithDoc,
  UnresolvableIssuerError,
} from './did.js'
export {
  type CreateIdentityInput,
  createFullIdentity,
  createIdentity,
  createKeyAgreementIdentity,
  createSigningIdentity,
  createSigningIdentityForDID,
  type FullIdentity,
  type Identity,
  type IdentityKeySpec,
  type IdentityProvider,
  isFullIdentity,
  isKeyAgreementIdentity,
  isOwnIdentity,
  isSigningIdentity,
  type KeyAgreementIdentity,
  type KeyAlg,
  type KeyPurpose,
  type MultiKeyIdentity,
  type OwnIdentity,
  type ResolvedKey,
  randomIdentity,
  type SigningIdentity,
  type SignTokenOptions,
} from './identity.js'
export type { KeyEntry, KeyStore, MutableKeyEntry } from './keystore.js'
export {
  type AgreementAlgorithm,
  type DIDMethodResolver,
  findMethodResolver,
  type MethodRegistry,
  type ResolvedAgreementKey,
  type ResolvedSigningKey,
} from './method.js'
export {
  decodeMultibase,
  encodeMultibase,
  multihashSHA256,
  verifyMultihash,
} from './multibase.js'
export {
  type DecodePeer4Options,
  type DIDDoc,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  isPeer4,
  type VerificationMethod,
  validateDIDDoc,
} from './peer4.js'
export {
  capabilitySchema,
  type SignatureAlgorithm,
  type SignedHeader,
  type SignedPayload,
  type SupportedHeader,
  signedHeaderSchema,
  signedPayloadSchema,
  supportedHeaderSchema,
  type UnsignedHeader,
  unsignedHeaderSchema,
  validateAlgorithm,
  validateSignedHeader,
  validateSignedPayload,
  validateUnsignedHeader,
} from './schemas.js'
export {
  decodePrivateKey,
  encodePrivateKey,
  randomPrivateKey,
} from './signer.js'
export {
  assertTimeClaimsValid,
  now,
  type TimeClaimsPayload,
  type TimeValidationOptions,
} from './time.js'
export {
  createUnsignedToken,
  isSignedToken,
  isUnsignedToken,
  isVerifiedToken,
  signToken,
  type VerifyTokenOptions,
  verifyToken,
} from './token.js'
export type * from './types.js'
export { concatBytes, stringifyToken } from './utils.js'
export {
  getVerifier,
  type Verifier,
  type Verifiers,
} from './verifier.js'
