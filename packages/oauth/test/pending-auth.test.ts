import { describe, expect, test } from 'vitest'

import {
  completeAuthorization,
  createMemoryPendingAuthStore,
  type OAuthProviderDefinition,
  type PendingAuthRecord,
  type PendingAuthStore,
  startAuthorization,
} from '../src/index.js'
import { fakeRuntime } from './fake-runtime.js'

type Extra = { ownerDID: string }

const googleNative: OAuthProviderDefinition = {
  name: 'google',
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://token',
  mode: 'native',
  clientID: 'cid',
}

type Captured = { body?: string }

function tokenRuntime(captured: Captured) {
  return fakeRuntime({
    fetch: async (_url, init) => {
      captured.body = String(init?.body)
      return new Response(JSON.stringify({ access_token: 'AT', token_type: 'Bearer' }), {
        headers: { 'content-type': 'application/json' },
      })
    },
  })
}

function pastRecord(overrides: Partial<PendingAuthRecord<Extra>> = {}): PendingAuthRecord<Extra> {
  return {
    state: 'old',
    codeVerifier: 'cv',
    provider: 'google',
    redirectURL: 'https://app/cb',
    scopes: ['openid'],
    createdAt: Date.now() - 1_000_000,
    extra: { ownerDID: 'x' },
    ...overrides,
  }
}

describe('startAuthorization()', () => {
  test('stores redirectURL + scopes, returns a URL carrying state and code_challenge', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    const { url, state } = await startAuthorization({
      runtime: fakeRuntime(),
      definition: googleNative,
      store,
      redirectURL: 'https://app/cb',
      scopes: ['openid', 'email'],
      extra: { ownerDID: 'did:kokuin:abc' },
      authorizationParams: { access_type: 'offline' },
    })

    const parsed = new URL(url)
    expect(parsed.searchParams.get('state')).toBe(state)
    expect(parsed.searchParams.get('code_challenge')).not.toBeNull()
    expect(parsed.searchParams.get('access_type')).toBe('offline')

    const record = await store.consume(state)
    expect(record?.redirectURL).toBe('https://app/cb')
    expect(record?.scopes).toEqual(['openid', 'email'])
    expect(record?.provider).toBe('google')
    expect(record?.extra.ownerDID).toBe('did:kokuin:abc')
  })

  test('sweeps an expired record', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await store.create(pastRecord())
    await startAuthorization({
      runtime: fakeRuntime(),
      definition: googleNative,
      store,
      redirectURL: 'https://app/cb',
      scopes: ['openid'],
      extra: { ownerDID: 'y' },
      ttlMs: 1000,
    })
    expect(await store.consume('old')).toBeNull()
  })

  test('a throwing sweep does not block starting a new flow', async () => {
    const inner = createMemoryPendingAuthStore<Extra>()
    const store: PendingAuthStore<Extra> = {
      ...inner,
      deleteExpired: async () => {
        throw new Error('sweep failed')
      },
    }
    const { url, state } = await startAuthorization({
      runtime: fakeRuntime(),
      definition: googleNative,
      store,
      redirectURL: 'https://app/cb',
      scopes: ['openid'],
      extra: { ownerDID: 'z' },
    })

    expect(url).toBeTruthy()
    expect(state).toBeTruthy()
    const record = await store.consume(state)
    expect(record?.state).toBe(state)
    expect(record?.extra.ownerDID).toBe('z')
  })
})

describe('completeAuthorization()', () => {
  test('consumes, exchanges with the stored redirect URI, returns tokens + record', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    const captured: Captured = {}
    const runtime = tokenRuntime(captured)
    const { state } = await startAuthorization({
      runtime,
      definition: googleNative,
      store,
      redirectURL: 'https://app/cb',
      scopes: ['openid'],
      extra: { ownerDID: 'did:kokuin:abc' },
    })

    const { tokens, record } = await completeAuthorization({
      runtime,
      definition: googleNative,
      store,
      state,
      code: 'CODE',
      redirectURL: 'https://app/cb',
    })

    expect(tokens.access_token).toBe('AT')
    expect(record.extra.ownerDID).toBe('did:kokuin:abc')
    expect(record.scopes).toEqual(['openid'])
    const form = new URLSearchParams(captured.body)
    expect(form.get('redirect_uri')).toBe('https://app/cb')
    expect(form.get('code_verifier')).toBe(record.codeVerifier)
  })

  test('replay of a consumed state is rejected', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    const runtime = tokenRuntime({})
    const { state } = await startAuthorization({
      runtime,
      definition: googleNative,
      store,
      redirectURL: 'https://app/cb',
      scopes: ['openid'],
      extra: { ownerDID: 'x' },
    })
    await completeAuthorization({
      runtime,
      definition: googleNative,
      store,
      state,
      code: 'CODE',
      redirectURL: 'https://app/cb',
    })
    await expect(
      completeAuthorization({
        runtime,
        definition: googleNative,
        store,
        state,
        code: 'CODE',
        redirectURL: 'https://app/cb',
      }),
    ).rejects.toThrow(/unknown|used/i)
  })

  test('unknown state is rejected', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await expect(
      completeAuthorization({
        runtime: fakeRuntime(),
        definition: googleNative,
        store,
        state: 'nope',
        code: 'CODE',
        redirectURL: 'https://app/cb',
      }),
    ).rejects.toThrow(/unknown|used/i)
  })

  test('an expired-but-unswept record is rejected', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await store.create(pastRecord({ state: 'stale' }))
    await expect(
      completeAuthorization({
        runtime: fakeRuntime(),
        definition: googleNative,
        store,
        state: 'stale',
        code: 'CODE',
        redirectURL: 'https://app/cb',
        ttlMs: 1000,
      }),
    ).rejects.toThrow(/expired/i)
  })

  test('provider mismatch is rejected', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await store.create(pastRecord({ state: 'p', provider: 'other', createdAt: Date.now() }))
    await expect(
      completeAuthorization({
        runtime: fakeRuntime(),
        definition: googleNative,
        store,
        state: 'p',
        code: 'CODE',
        redirectURL: 'https://app/cb',
      }),
    ).rejects.toThrow(/provider/i)
  })

  test('a supplied redirect URI that differs from the stored one is rejected', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await store.create(pastRecord({ state: 'r', createdAt: Date.now() }))
    await expect(
      completeAuthorization({
        runtime: fakeRuntime(),
        definition: googleNative,
        store,
        state: 'r',
        code: 'CODE',
        redirectURL: 'https://app/other',
      }),
    ).rejects.toThrow(/redirect/i)
  })
})

describe('createMemoryPendingAuthStore()', () => {
  test('rejects a duplicate state on create', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    await store.create(pastRecord({ state: 's', createdAt: Date.now() }))
    await expect(store.create(pastRecord({ state: 's', createdAt: Date.now() }))).rejects.toThrow(
      /duplicate/i,
    )
  })

  test('does not hand out a mutable shared record', async () => {
    const store = createMemoryPendingAuthStore<Extra>()
    const record = pastRecord({ state: 'm', createdAt: Date.now() })
    await store.create(record)
    record.extra.ownerDID = 'mutated-after-create'
    const got = await store.consume('m')
    expect(got?.extra.ownerDID).toBe('x')
  })
})
