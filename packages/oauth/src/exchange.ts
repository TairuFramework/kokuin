import type { Runtime } from '@sozai/runtime'

import { fetchOAuthJSON } from './http.js'
import type { OAuthProviderDefinition, RequestOptions, TokenResponse } from './types.js'

export async function exchangeCode(
  params: {
    definition: OAuthProviderDefinition
    runtime: Runtime
    code: string
    redirectURL: string
    codeVerifier: string
  } & RequestOptions,
): Promise<TokenResponse> {
  const { definition, runtime, code, redirectURL, codeVerifier, signal, timeoutMs, maxBytes } =
    params

  if (definition.mode === 'broker') {
    throw new Error('broker token exchange is not implemented')
  }
  assertExchangeableConfig(definition)

  const form = new URLSearchParams()
  form.set('grant_type', 'authorization_code')
  form.set('code', code)
  form.set('redirect_uri', redirectURL)
  form.set('client_id', definition.clientID)
  form.set('code_verifier', codeVerifier)
  if (definition.clientSecret != null) {
    form.set('client_secret', definition.clientSecret)
  }

  const raw = await fetchOAuthJSON({
    runtime,
    url: definition.tokenEndpoint,
    body: form.toString(),
    contentType: 'application/x-www-form-urlencoded',
    signal,
    timeoutMs,
    maxBytes,
  })
  return validateTokenResponse(raw)
}

export async function refreshToken(
  params: {
    definition: OAuthProviderDefinition
    runtime: Runtime
    refreshToken: string
  } & RequestOptions,
): Promise<TokenResponse> {
  const { definition, runtime, refreshToken, signal, timeoutMs, maxBytes } = params

  if (definition.mode === 'broker') {
    throw new Error('broker token refresh is not implemented')
  }
  assertExchangeableConfig(definition)

  const form = new URLSearchParams()
  form.set('grant_type', 'refresh_token')
  form.set('refresh_token', refreshToken)
  form.set('client_id', definition.clientID)
  if (definition.clientSecret != null) {
    form.set('client_secret', definition.clientSecret)
  }

  const raw = await fetchOAuthJSON({
    runtime,
    url: definition.tokenEndpoint,
    body: form.toString(),
    contentType: 'application/x-www-form-urlencoded',
    signal,
    timeoutMs,
    maxBytes,
  })
  return validateTokenResponse(raw)
}

function assertExchangeableConfig(definition: OAuthProviderDefinition): void {
  if (definition.mode !== 'confidential' && definition.mode !== 'native') {
    throw new Error(
      `unsupported OAuth client mode: ${String((definition as { mode?: unknown }).mode)}`,
    )
  }
  if (typeof definition.clientID !== 'string' || definition.clientID.length === 0) {
    throw new Error('OAuth definition requires a non-empty clientID')
  }
  if (definition.mode === 'confidential') {
    if (typeof definition.clientSecret !== 'string' || definition.clientSecret.length === 0) {
      throw new Error('confidential OAuth client requires a non-empty clientSecret')
    }
  }
}

function validateTokenResponse(value: unknown): TokenResponse {
  if (typeof value !== 'object' || value === null) {
    throw new Error('OAuth token response was not an object')
  }
  const record = value as Record<string, unknown>
  if (typeof record.access_token !== 'string' || record.access_token.length === 0) {
    throw new Error('OAuth token response is missing a valid access_token')
  }
  if (typeof record.token_type !== 'string') {
    throw new Error('OAuth token response is missing a valid token_type')
  }
  if (record.expires_in !== undefined) {
    if (
      typeof record.expires_in !== 'number' ||
      !Number.isFinite(record.expires_in) ||
      record.expires_in < 0
    ) {
      throw new Error('OAuth token response has an invalid expires_in')
    }
  }
  if (record.refresh_token !== undefined && typeof record.refresh_token !== 'string') {
    throw new Error('OAuth token response has an invalid refresh_token')
  }
  if (record.scope !== undefined && typeof record.scope !== 'string') {
    throw new Error('OAuth token response has an invalid scope')
  }
  return value as TokenResponse
}
