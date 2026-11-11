import { describe, expect, test, vi } from 'vitest'

import {
  completeAuthorization,
  createHTTPBrokerTransport,
  createMemoryPendingAuthStore,
  deriveCodeChallenge,
  exchangeCode,
  type OAuthBrokerTransport,
  type OAuthProviderDefinition,
  OAuthTokenError,
  refreshToken,
  startAuthorization,
} from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

const definition: OAuthProviderDefinition = {
  name: 'example',
  mode: 'broker',
  clientID: 'app-client',
  authorizationEndpoint: 'https://provider.example/authorize',
  tokenEndpoint: 'https://provider.example/token',
}
const authorization = {
  url: 'https://provider.example/authorize?state=broker-state',
  state: 'broker-state',
  transactionToken: 'transaction-token',
}
const tokens = { access_token: 'access-token', token_type: 'Bearer', refresh_token: 'rotated' }

function setup() {
  const broker = {
    authorize: vi.fn<OAuthBrokerTransport['authorize']>().mockResolvedValue(authorization),
    token: vi.fn<OAuthBrokerTransport['token']>().mockResolvedValue(tokens),
  }
  const runtime = fakeRuntime({ fetch: vi.fn().mockRejectedValue(new Error('direct HTTP')) })
  const store = createMemoryPendingAuthStore<{ accountID: string }>()
  const start = {
    runtime,
    definition,
    store,
    broker,
    redirectURL: 'app://callback',
    scopes: ['read'],
    extra: { accountID: 'account' },
    authorizationParams: { prompt: 'consent' },
  }
  return { broker, runtime, store, start }
}

describe('broker authorization', () => {
  test('start calls authorize with appRedirect and local PKCE and stores broker state and transaction', async () => {
    const { broker, store, start, runtime } = setup()
    expect(await startAuthorization(start)).toEqual({
      url: authorization.url,
      state: authorization.state,
    })
    const record = await store.consume(authorization.state)
    expect(record).toMatchObject({
      state: authorization.state,
      transactionToken: authorization.transactionToken,
      provider: definition.name,
      redirectURL: start.redirectURL,
      scopes: start.scopes,
      extra: start.extra,
    })
    expect(record?.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/)
    expect(broker.authorize).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        provider: definition.name,
        appRedirect: start.redirectURL,
        scopes: start.scopes,
        authorizationParams: start.authorizationParams,
        codeChallenge: deriveCodeChallenge(record?.codeVerifier ?? ''),
      }),
    )
    expect(runtime.fetch).not.toHaveBeenCalled()
  })

  test('complete posts authorization_code with verifier, state and transaction, and prevents replay', async () => {
    const { broker, start, runtime } = setup()
    const { state } = await startAuthorization(start)
    const signal = new AbortController().signal
    const complete = { ...start, state, code: 'code', signal, timeoutMs: 1234, maxBytes: 1024 }
    const result = await completeAuthorization(complete)
    expect(result.tokens).toEqual(tokens)
    expect(broker.token).toHaveBeenCalledExactlyOnceWith({
      provider: definition.name,
      signal,
      timeoutMs: 1234,
      maxBytes: 1024,
      body: {
        grant_type: 'authorization_code',
        code: 'code',
        code_verifier: result.record.codeVerifier,
        state,
        transactionToken: authorization.transactionToken,
      },
    })
    expect(runtime.fetch).not.toHaveBeenCalled()
    await expect(completeAuthorization(complete)).rejects.toThrow(/unknown|used/)
  })

  test('complete validates broker token responses', async () => {
    const { broker, start } = setup()
    const { state } = await startAuthorization(start)
    broker.token.mockResolvedValue({ token_type: 'Bearer' })
    await expect(completeAuthorization({ ...start, state, code: 'code' })).rejects.toThrow(
      /access_token/,
    )
  })

  test('refresh posts only refresh_token grant fields and returns rotated tokens', async () => {
    const { broker, runtime } = setup()
    const signal = new AbortController().signal
    expect(
      await refreshToken({
        definition,
        runtime,
        broker,
        refreshToken: 'refresh',
        signal,
        timeoutMs: 1234,
        maxBytes: 1024,
      }),
    ).toEqual(tokens)
    expect(broker.token).toHaveBeenCalledExactlyOnceWith({
      provider: definition.name,
      body: { grant_type: 'refresh_token', refresh_token: 'refresh' },
      signal,
      timeoutMs: 1234,
      maxBytes: 1024,
    })
    expect(runtime.fetch).not.toHaveBeenCalled()
    broker.token.mockResolvedValue({ access_token: 'access', token_type: 123 })
    await expect(
      refreshToken({ definition, runtime, broker, refreshToken: 'refresh' }),
    ).rejects.toThrow(/token_type/)
  })

  test('broker mode without transport throws at start, complete and refresh', async () => {
    const { start, store, runtime } = setup()
    await expect(startAuthorization({ ...start, broker: undefined })).rejects.toThrow(
      'broker mode requires a broker transport',
    )
    const { state } = await startAuthorization(start)
    await expect(
      completeAuthorization({ ...start, broker: undefined, state, code: 'code' }),
    ).rejects.toThrow('broker mode requires a broker transport')
    expect(await store.consume(state)).not.toBeNull()
    await expect(refreshToken({ definition, runtime, refreshToken: 'refresh' })).rejects.toThrow(
      'broker mode requires a broker transport',
    )
  })

  test.each(['native', 'confidential'] as const)(
    '%s paths continue to use direct provider HTTP',
    async (mode) => {
      const { broker, start } = setup()
      const nativeDefinition: OAuthProviderDefinition = {
        ...definition,
        mode,
        clientSecret: 'secret',
      }
      const fetch = vi
        .fn<typeof globalThis.fetch>()
        .mockImplementation(async () => Response.json(tokens))
      const runtime = fakeRuntime({ fetch })
      const { state, url } = await startAuthorization({
        ...start,
        runtime,
        definition: nativeDefinition,
      })
      expect(new URL(url).origin).toBe('https://provider.example')
      expect(state).not.toBe(authorization.state)
      await completeAuthorization({
        ...start,
        runtime,
        definition: nativeDefinition,
        state,
        code: 'code',
      })
      await exchangeCode({
        definition: nativeDefinition,
        runtime,
        code: 'code',
        codeVerifier: 'verifier',
        redirectURL: start.redirectURL,
      })
      await refreshToken({ definition: nativeDefinition, runtime, broker, refreshToken: 'refresh' })
      expect(fetch).toHaveBeenCalledTimes(3)
      expect(broker.authorize).not.toHaveBeenCalled()
      expect(broker.token).not.toHaveBeenCalled()
    },
  )
})

describe('HTTP broker transport', () => {
  test('maps routes and JSON bodies, returning authorization and raw token JSON', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json(authorization))
      .mockResolvedValueOnce(Response.json({ custom: 'raw' }))
    const broker = createHTTPBrokerTransport({ baseURL: 'https://broker.example/base/', fetch })
    const params = {
      provider: 'example',
      appRedirect: 'app://callback',
      codeChallenge: 'challenge',
      scopes: ['read'],
      authorizationParams: { prompt: 'consent' },
    }
    expect(await broker.authorize(params)).toEqual(authorization)
    const body = { grant_type: 'refresh_token', refresh_token: 'refresh' }
    expect(await broker.token({ provider: 'example', body })).toEqual({ custom: 'raw' })
    const [authorizeCall, tokenCall] = fetch.mock.calls
    expect(authorizeCall?.[0]).toBe('https://broker.example/base/oauth/example/authorize')
    expect(JSON.parse(String(authorizeCall?.[1]?.body))).toEqual({
      appRedirect: params.appRedirect,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes,
      authorizationParams: params.authorizationParams,
    })
    expect(tokenCall?.[0]).toBe('https://broker.example/base/oauth/example/token')
    expect(JSON.parse(String(tokenCall?.[1]?.body))).toEqual(body)
    expect(authorizeCall?.[1]).toMatchObject({
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
    })
  })

  test.each(['authorize', 'token'] as const)(
    '%s maps 4xx responses to OAuthTokenError',
    async (method) => {
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        Response.json(
          {
            error: 'invalid_grant',
            error_description: 'expired transaction',
          },
          { status: 400 },
        ),
      )
      const broker = createHTTPBrokerTransport({ baseURL: 'https://broker.example', fetch })
      const request =
        method === 'authorize'
          ? broker.authorize({ provider: 'example', appRedirect: 'app://callback' })
          : broker.token({ provider: 'example', body: {} })
      await expect(request).rejects.toBeInstanceOf(OAuthTokenError)
      await expect(request).rejects.toMatchObject({
        status: 400,
        code: 'invalid_grant',
        description: 'expired transaction',
      })
    },
  )

  test('enforces response bounds and forwards abort signals', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async () => Response.json(tokens))
    const broker = createHTTPBrokerTransport({ baseURL: 'https://broker.example', fetch })
    const controller = new AbortController()
    await expect(
      broker.token({ provider: 'example', body: {}, maxBytes: 1, signal: controller.signal }),
    ).rejects.toThrow(/exceeded/)
    const signal = fetch.mock.calls[0]?.[1]?.signal
    controller.abort()
    expect(signal?.aborted).toBe(true)
  })

  test('baseURL resolver is called per request', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation(async () => Response.json({ ok: true }))
    const resolver = vi
      .fn<() => string | Promise<string>>()
      .mockReturnValueOnce('https://one.example/')
      .mockResolvedValueOnce('https://two.example')
    const broker = createHTTPBrokerTransport({ baseURL: resolver, fetch })
    await broker.token({ provider: 'example', body: {} })
    await broker.token({ provider: 'example', body: {} })
    expect(resolver).toHaveBeenCalledTimes(2)
    expect(fetch.mock.calls[0]?.[0]).toBe('https://one.example/oauth/example/token')
    expect(fetch.mock.calls[1]?.[0]).toBe('https://two.example/oauth/example/token')
  })

  test('baseURL resolver rejection propagates', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
    const failure = new Error('no hub')
    const broker = createHTTPBrokerTransport({
      baseURL: async () => {
        throw failure
      },
      fetch,
    })
    await expect(broker.token({ provider: 'example', body: {} })).rejects.toBe(failure)
    await expect(
      broker.authorize({ provider: 'example', appRedirect: 'app://callback' }),
    ).rejects.toBe(failure)
    expect(fetch).not.toHaveBeenCalled()
  })

  test('rejects malformed authorize responses', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ url: authorization.url, state: 'state' }))
    const broker = createHTTPBrokerTransport({ baseURL: 'https://broker.example', fetch })
    await expect(
      broker.authorize({ provider: 'example', appRedirect: 'app://callback' }),
    ).rejects.toThrow(/transactionToken/)
  })
})
