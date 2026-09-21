import { describe, expect, test } from 'vitest'

import { exchangeCode, type OAuthProviderDefinition, refreshToken } from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

const base = {
  name: 'google',
  authorizationEndpoint: 'https://a',
  tokenEndpoint: 'https://token',
}

const confidential: OAuthProviderDefinition = {
  ...base,
  mode: 'confidential',
  clientID: 'cid',
  clientSecret: 'secret',
}
const native: OAuthProviderDefinition = { ...base, mode: 'native', clientID: 'cid' }
const broker: OAuthProviderDefinition = { ...base, mode: 'broker', clientID: 'cid' }

type Captured = { url?: string; body?: string; signal?: unknown }

function tokenRuntime(
  captured: Captured,
  tokenBody: unknown = { access_token: 'AT', token_type: 'Bearer' },
) {
  return fakeRuntime({
    fetch: async (url, init) => {
      captured.url = String(url)
      captured.body = String(init?.body)
      captured.signal = init?.signal
      return new Response(JSON.stringify(tokenBody), {
        headers: { 'content-type': 'application/json' },
      })
    },
  })
}

function throwingRuntime() {
  return fakeRuntime({
    fetch: async () => {
      throw new Error('fetch must not be called')
    },
  })
}

describe('exchangeCode()', () => {
  test('confidential sends client_secret and code_verifier, forwards a signal', async () => {
    const captured: Captured = {}
    await exchangeCode({
      definition: confidential,
      runtime: tokenRuntime(captured),
      code: 'CODE',
      redirectURL: 'https://app/cb',
      codeVerifier: 'CV',
    })
    const form = new URLSearchParams(captured.body)
    expect(captured.url).toBe('https://token')
    expect(form.get('grant_type')).toBe('authorization_code')
    expect(form.get('code')).toBe('CODE')
    expect(form.get('redirect_uri')).toBe('https://app/cb')
    expect(form.get('client_id')).toBe('cid')
    expect(form.get('code_verifier')).toBe('CV')
    expect(form.get('client_secret')).toBe('secret')
    expect(captured.signal).toBeInstanceOf(AbortSignal)
  })

  test('native omits client_secret but always sends code_verifier', async () => {
    const captured: Captured = {}
    await exchangeCode({
      definition: native,
      runtime: tokenRuntime(captured),
      code: 'CODE',
      redirectURL: 'https://app/cb',
      codeVerifier: 'CV',
    })
    const form = new URLSearchParams(captured.body)
    expect(form.get('code_verifier')).toBe('CV')
    expect(form.has('client_secret')).toBe(false)
  })

  test('broker throws not implemented', async () => {
    await expect(
      exchangeCode({
        definition: broker,
        runtime: throwingRuntime(),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/not implemented/i)
  })

  test('confidential with empty secret is rejected before HTTP', async () => {
    const badConfidential = { ...confidential, clientSecret: '' }
    await expect(
      exchangeCode({
        definition: badConfidential,
        runtime: throwingRuntime(),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/clientSecret/i)
  })

  test('unknown mode is rejected before HTTP', async () => {
    const bogus = { ...base, mode: 'weird', clientID: 'cid' } as unknown as OAuthProviderDefinition
    await expect(
      exchangeCode({
        definition: bogus,
        runtime: throwingRuntime(),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/mode/i)
  })

  test('a malformed success body is rejected', async () => {
    const captured: Captured = {}
    await expect(
      exchangeCode({
        definition: native,
        runtime: tokenRuntime(captured, {}),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/access_token/i)
  })

  test('a wrongly-typed expires_in is rejected', async () => {
    const captured: Captured = {}
    await expect(
      exchangeCode({
        definition: native,
        runtime: tokenRuntime(captured, {
          access_token: 'AT',
          token_type: 'Bearer',
          expires_in: 'soon',
        }),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/expires_in/i)
  })

  test('a valid response surfaces the id_token', async () => {
    const captured: Captured = {}
    const tokens = await exchangeCode({
      definition: native,
      runtime: tokenRuntime(captured, {
        access_token: 'AT',
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: 'JWT',
      }),
      code: 'CODE',
      redirectURL: 'https://app/cb',
      codeVerifier: 'CV',
    })
    expect(tokens.access_token).toBe('AT')
    expect(tokens.id_token).toBe('JWT')
  })

  test('a wrongly-typed id_token is rejected', async () => {
    const captured: Captured = {}
    await expect(
      exchangeCode({
        definition: native,
        runtime: tokenRuntime(captured, {
          access_token: 'AT',
          token_type: 'Bearer',
          id_token: 123,
        }),
        code: 'CODE',
        redirectURL: 'https://app/cb',
        codeVerifier: 'CV',
      }),
    ).rejects.toThrow(/id_token/i)
  })
})

describe('refreshToken()', () => {
  test('confidential sends client_secret', async () => {
    const captured: Captured = {}
    await refreshToken({
      definition: confidential,
      runtime: tokenRuntime(captured),
      refreshToken: 'RT',
    })
    const form = new URLSearchParams(captured.body)
    expect(form.get('grant_type')).toBe('refresh_token')
    expect(form.get('refresh_token')).toBe('RT')
    expect(form.get('client_id')).toBe('cid')
    expect(form.get('client_secret')).toBe('secret')
  })

  test('native omits client_secret', async () => {
    const captured: Captured = {}
    await refreshToken({
      definition: native,
      runtime: tokenRuntime(captured),
      refreshToken: 'RT',
    })
    const form = new URLSearchParams(captured.body)
    expect(form.get('refresh_token')).toBe('RT')
    expect(form.has('client_secret')).toBe(false)
  })

  test('broker throws not implemented', async () => {
    await expect(
      refreshToken({ definition: broker, runtime: throwingRuntime(), refreshToken: 'RT' }),
    ).rejects.toThrow(/not implemented/i)
  })
})
