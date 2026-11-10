import { afterEach, describe, expect, test, vi } from 'vitest'

import {
  type DeviceAuthorization,
  type OAuthProviderDefinition,
  OAuthTokenError,
  pollDeviceToken,
  refreshToken,
  startDeviceAuthorization,
} from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

const definition: OAuthProviderDefinition = {
  name: 'example',
  mode: 'native',
  clientID: 'cid',
  authorizationEndpoint: 'https://provider.test/authorize',
  deviceAuthorizationEndpoint: 'https://provider.test/device',
  tokenEndpoint: 'https://provider.test/token',
}
const tokens = { access_token: 'AT', token_type: 'Bearer', refresh_token: 'RT' }

function authorization(): DeviceAuthorization {
  return {
    deviceCode: 'DEVICE',
    userCode: 'USER',
    verificationURI: 'https://provider.test/verify',
    expiresAt: Date.now() + 600_000,
    intervalMS: 5000,
  }
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

afterEach(() => vi.useRealTimers())

describe('startDeviceAuthorization()', () => {
  test('starts device authorization with client_id and scope', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(1_000_000)
    const runtime = fakeRuntime({
      fetch: async (url, init) => {
        expect(String(url)).toBe('https://provider.test/device')
        expect(init?.method).toBe('POST')
        expect(init?.headers).toMatchObject({
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        })
        expect(String(init?.body)).toBe('client_id=cid&scope=a+b')
        return json({
          device_code: 'DEVICE',
          user_code: 'USER',
          verification_uri: 'https://provider.test/verify',
          expires_in: 600,
        })
      },
    })
    expect(await startDeviceAuthorization({ definition, runtime, scopes: ['a', 'b'] })).toEqual({
      deviceCode: 'DEVICE',
      userCode: 'USER',
      verificationURI: 'https://provider.test/verify',
      expiresAt: 1_600_000,
      intervalMS: 5000,
    })
  })

  test('maps an explicit interval and verification_uri_complete', async () => {
    const result = await startDeviceAuthorization({
      definition,
      runtime: fakeRuntime({
        fetch: async () =>
          json({
            device_code: 'DEVICE',
            user_code: 'USER',
            verification_uri: 'https://provider.test/verify',
            verification_uri_complete: 'https://provider.test/verify?code=USER',
            expires_in: 600,
            interval: 2,
          }),
      }),
      scopes: [],
    })
    expect(result.intervalMS).toBe(2000)
    expect(result.verificationURIComplete).toBe('https://provider.test/verify?code=USER')
  })

  test('rejects when the definition has no deviceAuthorizationEndpoint', async () => {
    await expect(
      startDeviceAuthorization({
        definition: { ...definition, deviceAuthorizationEndpoint: undefined },
        runtime: fakeRuntime({
          fetch: async () => {
            throw new Error('unexpected HTTP')
          },
        }),
        scopes: [],
      }),
    ).rejects.toThrow(/deviceAuthorizationEndpoint/)
  })

  test.each([
    null,
    {},
    { device_code: '', user_code: 'USER', verification_uri: 'https://verify', expires_in: 600 },
    { device_code: 'D', user_code: 'U', verification_uri: 'https://verify', expires_in: -1 },
    { device_code: 'D', user_code: 'U', verification_uri: 'https://verify', expires_in: '600' },
    {
      device_code: 'D',
      user_code: 'U',
      verification_uri: 'https://verify',
      expires_in: 600,
      interval: 0,
    },
    {
      device_code: 'D',
      user_code: 'U',
      verification_uri: 'https://verify',
      expires_in: 600,
      interval: null,
    },
  ])('rejects malformed device authorization response %j', async (body) => {
    await expect(
      startDeviceAuthorization({
        definition,
        runtime: fakeRuntime({ fetch: async () => json(body) }),
        scopes: [],
      }),
    ).rejects.toThrow()
  })
})

describe('pollDeviceToken()', () => {
  test.each([200, 400])(
    'polls until success, honouring authorization_pending and slow_down (HTTP %i)',
    async (status) => {
      const responses = [
        json({ error: 'authorization_pending' }, status),
        json({ error: 'slow_down' }, status),
        json(tokens),
      ]
      const sleeps: Array<number> = []
      const runtime = fakeRuntime({
        fetch: async (url, init) => {
          expect(String(url)).toBe('https://provider.test/token')
          expect(init?.method).toBe('POST')
          expect(Object.fromEntries(new URLSearchParams(String(init?.body)))).toEqual({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: 'DEVICE',
            client_id: 'cid',
          })
          const response = responses.shift()
          if (!response) throw new Error('unexpected poll')
          return response
        },
      })
      expect(
        await pollDeviceToken({
          definition,
          runtime,
          authorization: authorization(),
          sleep: async (ms) => {
            sleeps.push(ms)
          },
        }),
      ).toEqual(tokens)
      expect(sleeps).toEqual([5000, 10000])
    },
  )

  test.each(['expired_token', 'access_denied'])('rejects with %s', async (code) => {
    await expect(
      pollDeviceToken({
        definition,
        authorization: authorization(),
        runtime: fakeRuntime({ fetch: async () => json({ error: code }, 400) }),
      }),
    ).rejects.toMatchObject({ name: 'OAuthTokenError', code, status: 400 })
  })

  test('expires locally before sending a request', async () => {
    await expect(
      pollDeviceToken({
        definition,
        authorization: { ...authorization(), expiresAt: Date.now() - 1 },
        runtime: fakeRuntime({
          fetch: async () => {
            throw new Error('unexpected HTTP')
          },
        }),
      }),
    ).rejects.toMatchObject({ code: 'expired_token' })
  })

  test('does not poll again after expiry during sleep', async () => {
    vi.useFakeTimers()
    const auth = authorization()
    let requests = 0
    await expect(
      pollDeviceToken({
        definition,
        authorization: auth,
        runtime: fakeRuntime({
          fetch: async () => {
            requests++
            return json({ error: 'authorization_pending' }, 400)
          },
        }),
        sleep: async () => {
          vi.setSystemTime(auth.expiresAt)
        },
      }),
    ).rejects.toMatchObject({ code: 'expired_token' })
    expect(requests).toBe(1)
  })

  test('stops polling when the signal aborts during injected sleep', async () => {
    const controller = new AbortController()
    let requests = 0
    const polling = pollDeviceToken({
      definition,
      authorization: authorization(),
      signal: controller.signal,
      runtime: fakeRuntime({
        fetch: async () => {
          requests++
          return json({ error: 'authorization_pending' }, 400)
        },
      }),
      sleep: async () => {
        controller.abort()
        await new Promise(() => {})
      },
    })
    await expect(polling).rejects.toMatchObject({ name: 'AbortError' })
    expect(requests).toBe(1)
  })

  test('stops polling when the signal aborts during default sleep', async () => {
    const controller = new AbortController()
    const polling = pollDeviceToken({
      definition,
      authorization: authorization(),
      signal: controller.signal,
      runtime: fakeRuntime({
        fetch: async () => {
          setTimeout(() => controller.abort(), 0)
          return json({ error: 'authorization_pending' }, 400)
        },
      }),
    })
    await expect(polling).rejects.toMatchObject({ name: 'AbortError' })
  })

  test('does not request a token with an already aborted signal', async () => {
    const signal = AbortSignal.abort()
    await expect(
      pollDeviceToken({
        definition,
        authorization: authorization(),
        signal,
        runtime: fakeRuntime({
          fetch: async () => {
            throw new Error('unexpected HTTP')
          },
        }),
      }),
    ).rejects.toMatchObject({ name: 'AbortError' })
  })

  test('validates the token response', async () => {
    await expect(
      pollDeviceToken({
        definition,
        authorization: authorization(),
        runtime: fakeRuntime({ fetch: async () => json({ token_type: 'Bearer' }) }),
      }),
    ).rejects.toThrow(/access_token/)
  })

  test('propagates other OAuth errors without retrying', async () => {
    await expect(
      pollDeviceToken({
        definition,
        authorization: authorization(),
        runtime: fakeRuntime({ fetch: async () => json({ error: 'invalid_client' }, 401) }),
      }),
    ).rejects.toBeInstanceOf(OAuthTokenError)
  })
})

test('refreshToken in native mode sends no client_secret', async () => {
  const result = await refreshToken({
    definition,
    refreshToken: 'RT',
    runtime: fakeRuntime({
      fetch: async (url, init) => {
        expect(String(url)).toBe('https://provider.test/token')
        expect(Object.fromEntries(new URLSearchParams(String(init?.body)))).toEqual({
          grant_type: 'refresh_token',
          refresh_token: 'RT',
          client_id: 'cid',
        })
        return json(tokens)
      },
    }),
  })
  expect(result).toEqual(tokens)
})
