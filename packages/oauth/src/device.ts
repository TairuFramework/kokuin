import type { Runtime } from '@sozai/runtime'

import { validateTokenResponse } from './exchange.js'
import { type FetchOAuthJSONParams, fetchOAuthJSON } from './http.js'
import {
  type OAuthProviderDefinition,
  OAuthTokenError,
  type RequestOptions,
  type TokenResponse,
} from './types.js'

export type DeviceAuthorization = {
  deviceCode: string
  userCode: string
  verificationURI: string
  verificationURIComplete?: string
  expiresAt: number
  intervalMS: number
}

export async function startDeviceAuthorization(
  params: {
    definition: OAuthProviderDefinition
    runtime: Runtime
    scopes: Array<string>
  } & RequestOptions,
): Promise<DeviceAuthorization> {
  const { definition, runtime, scopes, signal, timeoutMs, maxBytes } = params
  if (!definition.deviceAuthorizationEndpoint) {
    throw new Error('OAuth definition requires a deviceAuthorizationEndpoint')
  }
  const form = new URLSearchParams({ client_id: definition.clientID, scope: scopes.join(' ') })
  const raw = await fetchDeviceJSON({
    runtime,
    url: definition.deviceAuthorizationEndpoint,
    body: form.toString(),
    contentType: 'application/x-www-form-urlencoded',
    signal,
    timeoutMs,
    maxBytes,
  })
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('OAuth device authorization response was not an object')
  }
  const record = raw as Record<string, unknown>
  const deviceCode = requiredString(record, 'device_code')
  const userCode = requiredString(record, 'user_code')
  const verificationURI = requiredString(record, 'verification_uri')
  const expiresIn = positiveNumber(record.expires_in, 'expires_in')
  const interval = positiveNumber(record.interval === undefined ? 5 : record.interval, 'interval')
  const verificationURIComplete =
    record.verification_uri_complete === undefined
      ? undefined
      : requiredString(record, 'verification_uri_complete')
  return {
    deviceCode,
    userCode,
    verificationURI,
    ...(verificationURIComplete === undefined ? {} : { verificationURIComplete }),
    expiresAt: Date.now() + expiresIn * 1000,
    intervalMS: interval * 1000,
  }
}

export async function pollDeviceToken(
  params: {
    definition: OAuthProviderDefinition
    runtime: Runtime
    authorization: DeviceAuthorization
    sleep?: (ms: number) => Promise<void>
  } & RequestOptions,
): Promise<TokenResponse> {
  const { definition, runtime, authorization, signal, sleep, timeoutMs, maxBytes } = params
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: authorization.deviceCode,
    client_id: definition.clientID,
  })
  let intervalMS = authorization.intervalMS
  for (;;) {
    signal?.throwIfAborted()
    if (Date.now() >= authorization.expiresAt) {
      throw new OAuthTokenError({ status: 400, code: 'expired_token' })
    }
    try {
      const raw = await fetchDeviceJSON({
        runtime,
        url: definition.tokenEndpoint,
        body: form.toString(),
        contentType: 'application/x-www-form-urlencoded',
        signal,
        timeoutMs,
        maxBytes,
      })
      signal?.throwIfAborted()
      return validateTokenResponse(raw)
    } catch (error) {
      if (!(error instanceof OAuthTokenError)) throw error
      if (error.code === 'slow_down') {
        intervalMS += 5000
      } else if (error.code !== 'authorization_pending') {
        throw error
      }
    }
    await wait(
      Math.min(intervalMS, Math.max(0, authorization.expiresAt - Date.now())),
      sleep,
      signal,
    )
  }
}

async function fetchDeviceJSON(params: FetchOAuthJSONParams): Promise<unknown> {
  const raw = await fetchOAuthJSON(params)
  // Some providers return OAuth errors with HTTP 200.
  if (typeof raw === 'object' && raw !== null) {
    const record = raw as Record<string, unknown>
    if (typeof record.error === 'string') {
      throw new OAuthTokenError({
        status: 200,
        code: record.error,
        description:
          typeof record.error_description === 'string' ? record.error_description : undefined,
      })
    }
  }
  return raw
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`OAuth device authorization response has an invalid ${key}`)
  }
  return value
}

function positiveNumber(value: unknown, key: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`OAuth device authorization response has an invalid ${key}`)
  }
  return value
}

function wait(
  ms: number,
  sleep: ((ms: number) => Promise<void>) | undefined,
  signal: AbortSignal | undefined,
): Promise<void> {
  signal?.throwIfAborted()
  return new Promise((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
    }
    const abort = () => {
      cleanup()
      reject(signal?.reason)
    }
    signal?.addEventListener('abort', abort, { once: true })
    if (sleep) {
      Promise.resolve()
        .then(() => sleep(ms))
        .then(
          () => {
            cleanup()
            resolve()
          },
          (error: unknown) => {
            cleanup()
            reject(error)
          },
        )
    } else {
      timer = setTimeout(() => {
        cleanup()
        resolve()
      }, ms)
    }
  })
}
