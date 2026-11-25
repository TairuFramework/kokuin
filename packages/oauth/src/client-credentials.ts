import type { Runtime } from '@sozai/runtime'

import { CLIENT_ASSERTION_TYPE } from './client-assertion.js'
import { extraForm, validateTokenResponse } from './exchange.js'
import { fetchOAuthJSON } from './http.js'
import type { RequestOptions, TokenResponse } from './types.js'

const CLIENT_CREDENTIALS_FIELDS = new Set([
  'grant_type',
  'client_id',
  'client_assertion_type',
  'client_assertion',
  'scope',
])

/** Request an access token with the client credentials grant, authenticating via `private_key_jwt`. */
export async function requestClientCredentialsToken(
  params: {
    runtime: Runtime
    tokenEndpoint: string
    clientID: string
    /** Signed client assertion, see `createClientAssertion`. */
    assertion: string
    scope?: string
    /**
     * Additional form fields, such as `resource` (RFC 8707). They never override the grant's own
     * fields (`grant_type`, `client_id`, `client_assertion_type`, `client_assertion`, `scope`).
     */
    extraParams?: Record<string, string>
  } & RequestOptions,
): Promise<TokenResponse> {
  const {
    runtime,
    tokenEndpoint,
    clientID,
    assertion,
    scope,
    extraParams,
    signal,
    timeoutMs,
    maxBytes,
  } = params

  const form = extraForm(extraParams, CLIENT_CREDENTIALS_FIELDS)
  form.set('grant_type', 'client_credentials')
  form.set('client_id', clientID)
  form.set('client_assertion_type', CLIENT_ASSERTION_TYPE)
  form.set('client_assertion', assertion)
  if (scope != null) {
    form.set('scope', scope)
  }

  const raw = await fetchOAuthJSON({
    runtime,
    url: tokenEndpoint,
    body: form.toString(),
    contentType: 'application/x-www-form-urlencoded',
    signal,
    timeoutMs,
    maxBytes,
  })
  return validateTokenResponse(raw)
}
