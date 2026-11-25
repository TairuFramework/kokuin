import { describe, expect, test } from 'vitest'

import {
  CLIENT_ASSERTION_TYPE,
  OAuthTokenError,
  requestClientCredentialsToken,
} from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

type Captured = { url?: string; body?: string; init?: RequestInit }

function tokenRuntime(
  captured: Captured,
  tokenBody: unknown = { access_token: 'AT', token_type: 'Bearer' },
  status = 200,
) {
  return fakeRuntime({
    fetch: async (url, init) => {
      captured.url = String(url)
      captured.body = String(init?.body)
      captured.init = init
      return new Response(JSON.stringify(tokenBody), {
        status,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
}

const base = { tokenEndpoint: 'https://token', clientID: 'cid', assertion: 'ASSERTION' }

describe('requestClientCredentialsToken()', () => {
  test('form fields', async () => {
    const captured: Captured = {}
    const token = await requestClientCredentialsToken({
      ...base,
      runtime: tokenRuntime(captured),
      scope: 'read write',
      extraParams: { resource: 'https://mcp.example/' },
    })
    expect(token.access_token).toBe('AT')
    expect(captured.url).toBe('https://token')
    const form = new URLSearchParams(captured.body)
    expect(Object.fromEntries(form)).toEqual({
      grant_type: 'client_credentials',
      client_id: 'cid',
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: 'ASSERTION',
      scope: 'read write',
      resource: 'https://mcp.example/',
    })
  })

  test('extraParams cannot override', async () => {
    const captured: Captured = {}
    await requestClientCredentialsToken({
      ...base,
      runtime: tokenRuntime(captured),
      extraParams: {
        grant_type: 'x',
        client_assertion: 'y',
        client_id: 'z',
        client_assertion_type: 'w',
      },
    })
    const form = new URLSearchParams(captured.body)
    expect(form.get('grant_type')).toBe('client_credentials')
    expect(form.get('client_assertion')).toBe('ASSERTION')
    expect(form.get('client_id')).toBe('cid')
    expect(form.get('client_assertion_type')).toBe(CLIENT_ASSERTION_TYPE)
  })

  test('no scope', async () => {
    const captured: Captured = {}
    await requestClientCredentialsToken({ ...base, runtime: tokenRuntime(captured) })
    expect(new URLSearchParams(captured.body).has('scope')).toBe(false)
  })

  test('error mapping', async () => {
    const error = await requestClientCredentialsToken({
      ...base,
      runtime: tokenRuntime({}, { error: 'invalid_client' }, 400),
    }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(OAuthTokenError)
    expect((error as OAuthTokenError).code).toBe('invalid_client')
    expect((error as OAuthTokenError).status).toBe(400)
  })

  test('redirect refused', async () => {
    const captured: Captured = {}
    await requestClientCredentialsToken({ ...base, runtime: tokenRuntime(captured) })
    expect(captured.init?.redirect).toBe('error')
  })

  test('response validated', async () => {
    await expect(
      requestClientCredentialsToken({
        ...base,
        runtime: tokenRuntime({}, { token_type: 'Bearer' }),
      }),
    ).rejects.toThrow('access_token')
  })
})
