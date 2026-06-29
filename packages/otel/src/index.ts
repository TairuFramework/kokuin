import { createTracerFactory } from '@sozai/otel'

export const createTracer = createTracerFactory('kokuin')

export const KokuinSpanNames = {
  TOKEN_SIGN: 'kokuin.token.sign',
  TOKEN_VERIFY: 'kokuin.token.verify',
  KEYSTORE_GET_OR_CREATE: 'kokuin.keystore.get_or_create',
} as const

export const KokuinAttributeKeys = {
  AUTH_DID: 'kokuin.auth.did',
  AUTH_ALGORITHM: 'kokuin.auth.algorithm',
  KEYSTORE_KEY_CREATED: 'kokuin.keystore.key_created',
  KEYSTORE_STORE_TYPE: 'kokuin.keystore.store_type',
} as const
