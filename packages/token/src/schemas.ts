import { createValidator, type FromSchema, type Schema } from '@sozai/schema'

/** @internal */
export const SUPPORTED_ALGORITHMS = ['EdDSA', 'ES256'] as const

/** @internal */
export const signatureAlgorithmSchema = {
  type: 'string',
  enum: SUPPORTED_ALGORITHMS,
} as const satisfies Schema
/** @internal */
export type SignatureAlgorithm = FromSchema<typeof signatureAlgorithmSchema>

/** @internal */
export const validateAlgorithm = createValidator(signatureAlgorithmSchema)

/**
 * The header of a signed token.
 *
 * Supported rather than internal: `@enkaku/protocol` composes its own message schemas out of this,
 * `unsignedHeaderSchema` and `signedPayloadSchema` — a protocol built on kokuin tokens has to
 * describe them in its own wire schema, and it cannot do that from a type alone.
 */
export const signedHeaderSchema = {
  type: 'object',
  properties: {
    typ: { type: 'string', const: 'JWT' },
    alg: signatureAlgorithmSchema,
    kid: { type: 'string' },
  },
  required: ['typ', 'alg'],
  additionalProperties: true,
} as const satisfies Schema
/** @internal */
export type SignedHeader = FromSchema<typeof signedHeaderSchema>

/** @internal */
export const validateSignedHeader = createValidator(signedHeaderSchema)

/**
 * The header of an unsigned token. See {@link signedHeaderSchema} for why this is supported.
 */
export const unsignedHeaderSchema = {
  type: 'object',
  properties: {
    typ: { type: 'string', const: 'JWT' },
    alg: { type: 'string', const: 'none' },
  },
  required: ['typ', 'alg'],
  additionalProperties: true,
} as const satisfies Schema
/** @internal */
export type UnsignedHeader = FromSchema<typeof unsignedHeaderSchema>

/** @internal */
export const validateUnsignedHeader = createValidator(unsignedHeaderSchema)

/** @internal */
export const supportedHeaderSchema = {
  anyOf: [signedHeaderSchema, unsignedHeaderSchema],
} as const satisfies Schema
/** @internal */
export type SupportedHeader = FromSchema<typeof supportedHeaderSchema>

/** @internal */
export const capabilitySchema = {
  anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
} as const satisfies Schema

/**
 * The registered claims a signed token carries. `additionalProperties` is open, so a consumer
 * spreads `properties` into its own object schema and concatenates `required`.
 *
 * Supported rather than internal — see {@link signedHeaderSchema}.
 */
export const signedPayloadSchema = {
  type: 'object',
  properties: {
    iss: { type: 'string' },
    sub: { type: 'string' },
    aud: { type: 'string' },
    cap: capabilitySchema,
    exp: { type: 'number' },
    nbf: { type: 'number' },
    iat: { type: 'number' },
  },
  required: ['iss'],
  additionalProperties: true,
} as const satisfies Schema
/**
 * The registered claims of a signed token, inferred from {@link signedPayloadSchema}.
 *
 * Supported rather than internal, and the most widely used of these: it is what a consumer
 * intersects its own payload type with to describe a token it issues or verifies.
 */
export type SignedPayload = FromSchema<typeof signedPayloadSchema>

/** @internal */
export const validateSignedPayload = createValidator(signedPayloadSchema)
