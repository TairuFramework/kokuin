import { fetchOAuthJSON } from './http.js'
import type { BrokerAuthorizeResult, OAuthBrokerTransport } from './types.js'

export type CreateHTTPBrokerTransportParams = {
  /** A resolver runs on every request, so the URL can change after the transport is created. */
  baseURL: string | (() => string | Promise<string>)
  fetch: typeof globalThis.fetch
}

export function createHTTPBrokerTransport(
  params: CreateHTTPBrokerTransportParams,
): OAuthBrokerTransport {
  const resolveBaseURL = async (): Promise<string> => {
    const value = typeof params.baseURL === 'function' ? await params.baseURL() : params.baseURL
    return value.replace(/\/+$/, '')
  }
  const runtime = { fetch: params.fetch }
  return {
    async authorize({
      provider,
      appRedirect,
      codeChallenge,
      scopes,
      authorizationParams,
      ...options
    }) {
      const baseURL = await resolveBaseURL()
      const raw = await fetchOAuthJSON({
        runtime,
        url: `${baseURL}/oauth/${encodeURIComponent(provider)}/authorize`,
        body: JSON.stringify({ appRedirect, codeChallenge, scopes, authorizationParams }),
        contentType: 'application/json',
        ...options,
      })
      return validateBrokerAuthorizeResult(raw)
    },
    async token({ provider, body, ...options }) {
      const baseURL = await resolveBaseURL()
      return fetchOAuthJSON({
        runtime,
        url: `${baseURL}/oauth/${encodeURIComponent(provider)}/token`,
        body: JSON.stringify(body),
        contentType: 'application/json',
        ...options,
      })
    },
  }
}

function validateBrokerAuthorizeResult(value: unknown): BrokerAuthorizeResult {
  if (typeof value !== 'object' || value === null) {
    throw new Error('OAuth broker authorization response was not an object')
  }
  const record = value as Record<string, unknown>
  for (const key of ['url', 'state', 'transactionToken']) {
    if (typeof record[key] !== 'string' || record[key].length === 0) {
      throw new Error(`OAuth broker authorization response has an invalid ${key}`)
    }
  }
  return value as BrokerAuthorizeResult
}
