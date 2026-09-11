import { assertSecureURL } from './secure-url.js'
import type { OAuthProviderDefinition } from './types.js'

const PROTECTED_PARAMS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'scope',
  'state',
  'code_challenge',
  'code_challenge_method',
])

export function buildAuthorizationURL(params: {
  definition: OAuthProviderDefinition
  redirectURL: string
  scopes: Array<string>
  state: string
  codeChallenge: string
  authorizationParams?: Record<string, string>
}): string {
  const { definition, redirectURL, scopes, state, codeChallenge, authorizationParams } = params

  assertSecureURL(definition.authorizationEndpoint)

  const url = new URL(definition.authorizationEndpoint)
  const search = url.searchParams

  if (authorizationParams != null) {
    for (const [key, value] of Object.entries(authorizationParams)) {
      if (!PROTECTED_PARAMS.has(key)) {
        search.set(key, value)
      }
    }
  }

  search.set('client_id', definition.clientID)
  search.set('redirect_uri', redirectURL)
  search.set('response_type', 'code')
  search.set('scope', scopes.join(' '))
  search.set('state', state)
  search.set('code_challenge', codeChallenge)
  search.set('code_challenge_method', 'S256')

  return url.toString()
}
