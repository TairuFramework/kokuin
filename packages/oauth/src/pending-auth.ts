import type { Runtime } from '@sozai/runtime'

import { buildAuthorizationURL } from './authorization.js'
import { exchangeCode } from './exchange.js'
import { deriveCodeChallenge, generateCodeVerifier, generateState } from './pkce.js'
import type { OAuthProviderDefinition, RequestOptions, TokenResponse } from './types.js'

export type PendingAuthRecord<TExtra> = {
  state: string
  codeVerifier: string
  provider: string
  redirectURL: string
  scopes: Array<string>
  createdAt: number
  extra: TExtra
}

export type PendingAuthStore<TExtra> = {
  create(record: PendingAuthRecord<TExtra>): Promise<void>
  consume(state: string): Promise<PendingAuthRecord<TExtra> | null>
  deleteExpired(cutoffMs: number): Promise<void>
}

export const DEFAULT_TTL_MS = 10 * 60 * 1000

export function createMemoryPendingAuthStore<TExtra>(): PendingAuthStore<TExtra> {
  const records = new Map<string, PendingAuthRecord<TExtra>>()
  return {
    async create(record) {
      if (records.has(record.state)) {
        throw new Error('duplicate authorization state')
      }
      records.set(record.state, structuredClone(record))
    },
    async consume(state) {
      const record = records.get(state)
      if (record == null) {
        return null
      }
      records.delete(state)
      return structuredClone(record)
    },
    async deleteExpired(cutoffMs) {
      for (const [state, record] of records) {
        if (record.createdAt < cutoffMs) {
          records.delete(state)
        }
      }
    },
  }
}

export async function startAuthorization<TExtra>(params: {
  runtime: Runtime
  definition: OAuthProviderDefinition
  store: PendingAuthStore<TExtra>
  redirectURL: string
  scopes: Array<string>
  extra: TExtra
  ttlMs?: number
  authorizationParams?: Record<string, string>
}): Promise<{ url: string; state: string }> {
  const { runtime, definition, store, redirectURL, scopes, extra, authorizationParams } = params
  const ttlMs = params.ttlMs ?? DEFAULT_TTL_MS
  const now = Date.now()

  await store.deleteExpired(now - ttlMs)

  const state = generateState(runtime)
  const codeVerifier = generateCodeVerifier(runtime)
  const codeChallenge = deriveCodeChallenge(codeVerifier)

  await store.create({
    state,
    codeVerifier,
    provider: definition.name,
    redirectURL,
    scopes,
    createdAt: now,
    extra,
  })

  const url = buildAuthorizationURL({
    definition,
    redirectURL,
    scopes,
    state,
    codeChallenge,
    authorizationParams,
  })
  return { url, state }
}

export async function completeAuthorization<TExtra>(
  params: {
    runtime: Runtime
    definition: OAuthProviderDefinition
    store: PendingAuthStore<TExtra>
    state: string
    code: string
    redirectURL: string
    ttlMs?: number
  } & RequestOptions,
): Promise<{ tokens: TokenResponse; record: PendingAuthRecord<TExtra> }> {
  const { runtime, definition, store, state, code, redirectURL, signal, timeoutMs, maxBytes } =
    params
  const ttlMs = params.ttlMs ?? DEFAULT_TTL_MS

  const record = await store.consume(state)
  if (record == null) {
    throw new Error('unknown or already-used authorization state')
  }
  if (record.createdAt + ttlMs < Date.now()) {
    throw new Error('authorization state expired')
  }
  if (record.provider !== definition.name) {
    throw new Error('authorization provider mismatch')
  }
  if (record.redirectURL !== redirectURL) {
    throw new Error('redirect URI mismatch')
  }

  const tokens = await exchangeCode({
    definition,
    runtime,
    code,
    redirectURL: record.redirectURL,
    codeVerifier: record.codeVerifier,
    signal,
    timeoutMs,
    maxBytes,
  })
  return { tokens, record }
}
