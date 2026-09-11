import { describe, expect, test } from 'vitest'

import { type OAuthProviderDefinition, OAuthTokenError, type TokenResponse } from '../src/index.js'

describe('OAuthProviderDefinition', () => {
  test('confidential carries a required clientSecret', () => {
    const definition: OAuthProviderDefinition = {
      name: 'google',
      authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenEndpoint: 'https://oauth2.googleapis.com/token',
      mode: 'confidential',
      clientID: 'cid',
      clientSecret: 'secret',
    }
    expect(definition.mode).toBe('confidential')
  })

  test('native may omit clientSecret', () => {
    const definition: OAuthProviderDefinition = {
      name: 'google',
      authorizationEndpoint: 'https://a',
      tokenEndpoint: 'https://t',
      mode: 'native',
      clientID: 'cid',
    }
    expect('clientSecret' in definition).toBe(false)
  })

  test('broker carries only clientID (no wire shape)', () => {
    const definition: OAuthProviderDefinition = {
      name: 'google',
      authorizationEndpoint: 'https://a',
      tokenEndpoint: 'https://t',
      mode: 'broker',
      clientID: 'cid',
    }
    expect(definition.mode).toBe('broker')
  })

  test('TokenResponse minimal shape', () => {
    const response: TokenResponse = { access_token: 'AT', token_type: 'Bearer' }
    expect(response.access_token).toBe('AT')
  })

  test('OAuthTokenError carries status, code, description', () => {
    const error = new OAuthTokenError(400, 'invalid_grant', 'bad code')
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('OAuthTokenError')
    expect(error.status).toBe(400)
    expect(error.code).toBe('invalid_grant')
    expect(error.description).toBe('bad code')
  })
})
