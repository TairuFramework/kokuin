import { describe, expect, test } from 'vitest'

import { fetchOAuthJSON, OAuthTokenError } from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

function baseParams(runtime: ReturnType<typeof fakeRuntime>) {
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
      fetch: async () =>
        new Response('{"ok":true}', { headers: { 'content-type': 'application/json' } }),
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
      fetch: async () =>
        new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'bad code' }), {
          status: 400,
          headers: { 'content-type': 'application/json' },
        }),
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
      fetch: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
    })
    await expect(fetchOAuthJSON({ ...baseParams(runtime), timeoutMs: 20 })).rejects.toThrow(
      'aborted',
    )
  })

  test('aborts when the caller signal fires, not the timeout', async () => {
    const runtime = fakeRuntime({
      fetch: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
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
