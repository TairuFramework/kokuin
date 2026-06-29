import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import { createFullIdentity, type FullIdentity } from '@kokuin/token'
import { getLogger } from '@sozai/log'
import { withSpan, withSyncSpan } from '@sozai/otel'

import { ExpoKeyStore } from './store.js'

const tracer = createTracer('keystore.expo')
const logger = getLogger(['kokuin', 'expo'])

export function provideFullIdentity(keyID: string): FullIdentity {
  return withSyncSpan(
    tracer,
    KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
    { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
    (span) => {
      const entry = ExpoKeyStore.entry(keyID)
      const existing = entry.get()
      if (existing != null) {
        const identity = createFullIdentity(existing)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, false)
        return identity
      }
      const key = entry.provide()
      const identity = createFullIdentity(key)
      span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
      span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, true)
      logger.info('New identity generated: {did}', { did: identity.id })
      return identity
    },
  )
}

export async function provideFullIdentityAsync(keyID: string): Promise<FullIdentity> {
  return withSpan(
    tracer,
    KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
    { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
    async (span) => {
      const entry = ExpoKeyStore.entry(keyID)
      const existing = await entry.getAsync()
      if (existing != null) {
        const identity = createFullIdentity(existing)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, false)
        return identity
      }
      const key = await entry.provideAsync()
      const identity = createFullIdentity(key)
      span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
      span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, true)
      logger.info('New identity generated: {did}', { did: identity.id })
      return identity
    },
  )
}
