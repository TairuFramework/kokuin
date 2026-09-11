import { describe, expect, test } from 'vitest'

import { buildAuthorizationURL, type OAuthProviderDefinition } from '../src/index.js'

const definition: OAuthProviderDefinition = {
  name: 'google',
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  mode: 'native',
  clientID: 'cid',
}

describe('buildAuthorizationURL()', () => {
  test('sets the generic core parameters', () => {
    const url = new URL(
      buildAuthorizationURL({
        definition,
        redirectURL: 'https://app/callback',
        scopes: ['openid', 'email'],
        state: 'STATE',
        codeChallenge: 'CHALLENGE',
      }),
    )
    const params = url.searchParams

    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth')
    expect(params.get('client_id')).toBe('cid')
    expect(params.get('redirect_uri')).toBe('https://app/callback')
    expect(params.get('response_type')).toBe('code')
    expect(params.get('scope')).toBe('openid email')
    expect(params.get('state')).toBe('STATE')
    expect(params.get('code_challenge')).toBe('CHALLENGE')
    expect(params.get('code_challenge_method')).toBe('S256')
  })

  test('merges provider-specific authorizationParams', () => {
    const url = new URL(
      buildAuthorizationURL({
        definition,
        redirectURL: 'https://app/callback',
        scopes: ['openid'],
        state: 'STATE',
        codeChallenge: 'CHALLENGE',
        authorizationParams: { access_type: 'offline', prompt: 'select_account consent' },
      }),
    )
    expect(url.searchParams.get('access_type')).toBe('offline')
    expect(url.searchParams.get('prompt')).toBe('select_account consent')
  })

  test('authorizationParams cannot override a protected core field', () => {
    const url = new URL(
      buildAuthorizationURL({
        definition,
        redirectURL: 'https://app/callback',
        scopes: ['openid'],
        state: 'STATE',
        codeChallenge: 'CHALLENGE',
        authorizationParams: {
          client_id: 'attacker',
          redirect_uri: 'https://evil',
          response_type: 'token',
          code_challenge_method: 'plain',
        },
      }),
    )
    const params = url.searchParams
    expect(params.get('client_id')).toBe('cid')
    expect(params.get('redirect_uri')).toBe('https://app/callback')
    expect(params.get('response_type')).toBe('code')
    expect(params.get('code_challenge_method')).toBe('S256')
  })

  test('rejects a non-https authorization endpoint', () => {
    expect(() =>
      buildAuthorizationURL({
        definition: { ...definition, authorizationEndpoint: 'http://provider.example/auth' },
        redirectURL: 'https://app/callback',
        scopes: ['openid'],
        state: 'STATE',
        codeChallenge: 'CHALLENGE',
      }),
    ).toThrow(/https/i)
  })

  test('allows a loopback http authorization endpoint', () => {
    const url = buildAuthorizationURL({
      definition: { ...definition, authorizationEndpoint: 'http://127.0.0.1:9000/auth' },
      redirectURL: 'https://app/callback',
      scopes: ['openid'],
      state: 'STATE',
      codeChallenge: 'CHALLENGE',
    })
    expect(url).toEqual(expect.any(String))
  })
})
