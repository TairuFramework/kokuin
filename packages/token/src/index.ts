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

export type { DIDCacheSetParams } from './cache.js'
export {
  type CreateInMemoryDIDCacheOptions,
  createInMemoryDIDCache,
  type DIDCache,
  type DIDResolver,
} from './cache.js'
export type {
  GetDIDParams,
  IssuerKeyNotFoundErrorParams,
  ResolveIssuerParams,
  UnresolvableIssuerErrorParams,
} from './did.js'
export {
  CODECS,
  getAgreementKey,
  getAlgorithmAndPublicKey,
  getDID,
  getSignatureInfo,
  IssuerKeyNotFoundError,
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  normalizeDID,
  type ResolveIssuerHeader,
  type ResolveIssuerMode,
  type ResolveIssuerWithDocResult,
  resolveIssuer,
  resolveIssuerWithDoc,
  signingKeysOf,
  UnresolvableIssuerError,
} from './did.js'
export type {
  CreateFullIdentityParams,
  CreateKeyAgreementIdentityForDIDParams,
  CreateSigningIdentityForDIDParams,
  CreateSigningIdentityParams,
  KeyAgreementIdentityAgreeKeyParams,
  MultiKeyIdentityAgreeKeyParams,
  MultiKeyIdentitySignTokenParams,
  SigningIdentitySignTokenParams,
} from './identity.js'
export {
  type CreateIdentityInput,
  type CryptoOptions,
  createFullIdentity,
  createIdentity,
  createKeyAgreementIdentity,
  createKeyAgreementIdentityForDID,
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
export type {
  DIDMethodResolverResolveHistoricParams,
  DIDMethodResolverResolveMemberHistoricParams,
  DIDMethodResolverResolveMemberParams,
  DIDMethodResolverResolveParams,
  FindMethodResolverParams,
} from './method.js'
export {
  type AgreementAlgorithm,
  type DIDMethodResolver,
  findMethodResolver,
  type MemberQuery,
  type MethodRegistry,
  type ResolvedAgreementKey,
  type ResolvedHistoricMember,
  type ResolvedMember,
  type ResolvedSigningKey,
} from './method.js'
export type { VerifyMultihashParams } from './multibase.js'
export {
  decodeMultibase,
  encodeMultibase,
  multihashSHA256,
  verifyMultihash,
} from './multibase.js'
export type { DecodePeer4Params } from './peer4.js'
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
export type { AssertTimeClaimsValidParams } from './time.js'
export {
  assertTimeClaimsValid,
  now,
  type TimeClaimsPayload,
  type TimeValidationOptions,
} from './time.js'
export type { CreateUnsignedTokenParams, SignTokenParams, VerifyTokenParams } from './token.js'
export {
  createUnsignedToken,
  isSignedToken,
  isUnsignedToken,
  isVerifiedToken,
  signToken,
  type VerifySignedPayloadInput,
  type VerifyTokenOptions,
  verifySignedPayload,
  verifyToken,
} from './token.js'
export type * from './types.js'
export type { ConcatBytesParams } from './utils.js'
export { concatBytes, decodeSignedToken, stringifyToken } from './utils.js'
export type { GetVerifierParams, VerifierParams } from './verifier.js'
export {
  getVerifier,
  type Verifier,
  type Verifiers,
} from './verifier.js'
