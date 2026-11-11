import type { Runtime } from '@sozai/runtime'
import { describe, expect, test } from 'vitest'

import { fetchOAuthJSON, OAuthTokenError } from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

function baseParams(runtime: Runtime) {
  return {
    runtime,
    url: 'https://token',
    body: 'grant_type=refresh_token',
    contentType: 'application/x-www-form-urlencoded',
  }
}

describe('fetchOAuthJSON()', () => {
  test('POSTs with redirect:error and an AbortSignal, and returns parsed JSON', async () => {
    let capturedInit: RequestInit | undefined
    const runtime = fakeRuntime({
      fetch: async (_url, init) => {
        capturedInit = init
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'content-type': 'application/json' },
        })
      },
    })

    const result = await fetchOAuthJSON(baseParams(runtime))

    expect(result).toEqual({ ok: true })
    expect(capturedInit?.method).toBe('POST')
    expect(capturedInit?.redirect).toBe('error')
    expect(capturedInit?.signal).toBeInstanceOf(AbortSignal)
    expect(String(capturedInit?.body)).toBe('grant_type=refresh_token')
  })

  test('rejects a non-HTTPS endpoint before calling fetch', async () => {
    let called = false
    const runtime = fakeRuntime({
      fetch: async () => {
        called = true
        return new Response('{}')
      },
    })
    await expect(fetchOAuthJSON({ ...baseParams(runtime), url: 'http://token' })).rejects.toThrow(
      /https/i,
    )
    expect(called).toBe(false)
  })

  test('allows an http loopback endpoint', async () => {
    const runtime = fakeRuntime({
      fetch: async () => {
        return new Response('{"ok":true}', { headers: { 'content-type': 'application/json' } })
      },
    })
    const result = await fetchOAuthJSON({
      ...baseParams(runtime),
      url: 'http://127.0.0.1:9000/token',
    })
    expect(result).toEqual({ ok: true })
  })

  test('rejects a body larger than maxBytes', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('x'.repeat(64)) })
    await expect(fetchOAuthJSON({ ...baseParams(runtime), maxBytes: 16 })).rejects.toThrow(
      /exceeded/i,
    )
  })

  test('non-OK JSON body throws an OAuthTokenError with parsed code', async () => {
    const runtime = fakeRuntime({
      fetch: async () => {
        return new Response(
          JSON.stringify({ error: 'invalid_grant', error_description: 'bad code' }),
          {
            status: 400,
            headers: { 'content-type': 'application/json' },
          },
        )
      },
    })
    const error = await fetchOAuthJSON(baseParams(runtime)).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(OAuthTokenError)
    expect((error as OAuthTokenError).status).toBe(400)
    expect((error as OAuthTokenError).code).toBe('invalid_grant')
    expect((error as OAuthTokenError).description).toBe('bad code')
  })

  test('non-OK non-JSON body throws an OAuthTokenError with undefined code', async () => {
    const runtime = fakeRuntime({
      fetch: async () => new Response('gateway timeout', { status: 504 }),
    })
    const error = await fetchOAuthJSON(baseParams(runtime)).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(OAuthTokenError)
    expect((error as OAuthTokenError).status).toBe(504)
    expect((error as OAuthTokenError).code).toBeUndefined()
  })

  test('OK non-JSON body throws a clear error', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('not json at all') })
    await expect(fetchOAuthJSON(baseParams(runtime))).rejects.toThrow(/JSON/i)
  })

  test('aborts on the timeout deadline', async () => {
    const runtime = fakeRuntime({
      fetch: (_url, init) => {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        })
      },
    })
    await expect(fetchOAuthJSON({ ...baseParams(runtime), timeoutMs: 20 })).rejects.toThrow(
      'aborted',
    )
  })

  test('aborts when the caller signal fires, not the timeout', async () => {
    const runtime = fakeRuntime({
      fetch: (_url, init) => {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        })
      },
    })
    const controller = new AbortController()
    const promise = fetchOAuthJSON({
      ...baseParams(runtime),
      signal: controller.signal,
      timeoutMs: 30000,
    })
    controller.abort()
    await expect(promise).rejects.toThrow('aborted')
  })
})

describe('fetchOAuthJSON() GET and loopback', () => {
  test('GETs without a body or content-type when method is GET', async () => {
    let capturedInit: RequestInit | undefined
    const runtime = fakeRuntime({
      fetch: async (_url, init) => {
        capturedInit = init
        return new Response(JSON.stringify({ issuer: 'https://as' }))
      },
    })
    const result = await fetchOAuthJSON({
      runtime,
      url: 'https://as/.well-known/oauth-authorization-server',
      method: 'GET',
    })
    expect(result).toEqual({ issuer: 'https://as' })
    expect(capturedInit?.method).toBe('GET')
    expect(capturedInit?.body).toBeUndefined()
    expect(new Headers(capturedInit?.headers).has('content-type')).toBe(false)
    expect(capturedInit?.redirect).toBe('error')
  })

  test('accepts an http *.localhost endpoint', async () => {
    const runtime = fakeRuntime()
    await expect(
      fetchOAuthJSON({ runtime, url: 'http://auth.localhost:8080/token', method: 'GET' }),
    ).resolves.toEqual({})
  })
})

describe('fetchOAuthJSON() empty success body', () => {
  const post = (runtime: Runtime) => ({
    runtime,
    url: 'https://as/revoke',
    body: 'token=t',
    contentType: 'application/x-www-form-urlencoded',
  })

  test('resolves undefined for an empty 200 body by default (RFC 7009)', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('', { status: 200 }) })
    await expect(fetchOAuthJSON(post(runtime))).resolves.toBeUndefined()
  })

  test('resolves undefined for a whitespace-only 200 body', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('  \n', { status: 200 }) })
    await expect(fetchOAuthJSON(post(runtime))).resolves.toBeUndefined()
  })

  test('allowEmpty: false rejects an empty 200 body', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('', { status: 200 }) })
    await expect(fetchOAuthJSON({ ...post(runtime), allowEmpty: false })).rejects.toThrow(
      'OAuth response was not valid JSON',
    )
  })

  test('a non-JSON non-empty 200 body still rejects', async () => {
    const runtime = fakeRuntime({ fetch: async () => new Response('ok', { status: 200 }) })
    await expect(fetchOAuthJSON(post(runtime))).rejects.toThrow('OAuth response was not valid JSON')
  })
})
