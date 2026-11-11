import type { Runtime } from '@sozai/runtime'

import { buildAuthorizationURL } from './authorization.js'
import { exchangeCode, validateTokenResponse } from './exchange.js'
import { deriveCodeChallenge, generateCodeVerifier, generateState } from './pkce.js'
import type {
  OAuthBrokerTransport,
  OAuthProviderDefinition,
  RequestOptions,
  TokenResponse,
} from './types.js'

export type PendingAuthRecord<TExtra> = {
  state: string
  codeVerifier: string
  transactionToken?: string
  provider: string
  redirectURL: string
  scopes: Array<string>
  createdAt: number
  expiresAt: number
  extra: TExtra
}

export type PendingAuthStore<TExtra> = {
  create(record: PendingAuthRecord<TExtra>): Promise<void>
  consume(state: string): Promise<PendingAuthRecord<TExtra> | null>
  /** Deletes records whose stored `expiresAt` is at or before `nowMs`. */
  deleteExpired(nowMs: number): Promise<void>
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
    async deleteExpired(nowMs) {
      for (const [state, record] of records) {
        if (record.expiresAt <= nowMs) {
          records.delete(state)
        }
      }
    },
  }
}

export type StartAuthorizationParams<TExtra> = {
  runtime: Runtime
  definition: OAuthProviderDefinition
  store: PendingAuthStore<TExtra>
  redirectURL: string
  scopes: Array<string>
  extra: TExtra
  ttlMs?: number
  authorizationParams?: Record<string, string>
  broker?: OAuthBrokerTransport
} & RequestOptions

export async function startAuthorization<TExtra>(
  params: StartAuthorizationParams<TExtra>,
): Promise<{ url: string; state: string }> {
  const { runtime, definition, store, redirectURL, scopes, extra, authorizationParams, broker } =
    params
  if (definition.mode === 'broker' && !broker) {
    throw new Error('broker mode requires a broker transport')
  }
  const ttlMs = params.ttlMs ?? DEFAULT_TTL_MS
  const now = Date.now()
  const expiresAt = now + ttlMs

  try {
    await store.deleteExpired(now)
  } catch {
    // best-effort cleanup: a sweep failure must not block starting a new flow
  }

  const codeVerifier = generateCodeVerifier(runtime)
  const codeChallenge = deriveCodeChallenge(codeVerifier)
  let state: string
  let url: string
  let transactionToken: string | undefined
  if (definition.mode === 'broker' && broker) {
    const authorization = await broker.authorize({
      provider: definition.name,
      appRedirect: redirectURL,
      codeChallenge,
      scopes,
      authorizationParams,
      signal: params.signal,
      timeoutMs: params.timeoutMs,
      maxBytes: params.maxBytes,
    })
    state = authorization.state
    url = authorization.url
    transactionToken = authorization.transactionToken
  } else {
    state = generateState(runtime)
    // Validate the endpoint before persisting a pending flow.
    url = buildAuthorizationURL({
      definition,
      redirectURL,
      scopes,
      state,
      codeChallenge,
      authorizationParams,
    })
  }

  await store.create({
    state,
    codeVerifier,
    ...(transactionToken === undefined ? {} : { transactionToken }),
    provider: definition.name,
    redirectURL,
    scopes,
    createdAt: now,
    expiresAt,
    extra,
  })

  return { url, state }
}

export type CompleteAuthorizationParams<TExtra> = {
  runtime: Runtime
  definition: OAuthProviderDefinition
  store: PendingAuthStore<TExtra>
  state: string
  code: string
  redirectURL: string
  broker?: OAuthBrokerTransport
} & RequestOptions

export async function completeAuthorization<TExtra>(
  params: CompleteAuthorizationParams<TExtra>,
): Promise<{ tokens: TokenResponse; record: PendingAuthRecord<TExtra> }> {
  const {
    runtime,
    definition,
    store,
    state,
    code,
    redirectURL,
    signal,
    timeoutMs,
    maxBytes,
    broker,
  } = params

  if (definition.mode === 'broker' && !broker) {
    throw new Error('broker mode requires a broker transport')
  }

  const record = await store.consume(state)
  if (record == null) {
    throw new Error('unknown or already-used authorization state')
  }
  if (record.expiresAt < Date.now()) {
    throw new Error('authorization state expired')
  }
  if (record.provider !== definition.name) {
    throw new Error('authorization provider mismatch')
  }
  if (record.redirectURL !== redirectURL) {
    throw new Error('redirect URI mismatch')
  }

  if (definition.mode === 'broker' && broker) {
    if (!record.transactionToken) {
      throw new Error('broker authorization requires a transactionToken')
    }
    const raw = await broker.token({
      provider: definition.name,
      body: {
        grant_type: 'authorization_code',
        code,
        code_verifier: record.codeVerifier,
        transactionToken: record.transactionToken,
        state,
      },
      signal,
      timeoutMs,
      maxBytes,
    })
    return { tokens: validateTokenResponse(raw), record }
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
