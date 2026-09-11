import type { Runtime } from '@sozai/runtime'

import { OAuthTokenError, type RequestOptions } from './types.js'

export type FetchOAuthJSONParams = {
  runtime: Pick<Runtime, 'fetch'>
  url: string
  body: string
  contentType: string
} & RequestOptions

const DEFAULT_MAX_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 30_000

export async function fetchOAuthJSON(params: FetchOAuthJSONParams): Promise<unknown> {
  const {
    runtime,
    url,
    body,
    contentType,
    signal,
    maxBytes = DEFAULT_MAX_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = params

  assertSecureURL(url)

  const timeoutSignal = AbortSignal.timeout(timeoutMs)
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal

  const response = await runtime.fetch(url, {
    method: 'POST',
    headers: { 'content-type': contentType, accept: 'application/json' },
    body,
    redirect: 'error',
    signal: combinedSignal,
  })

  const text = await readCappedText(response, maxBytes)

  if (!response.ok) {
    throw parseOAuthError(response.status, text)
  }

  try {
    return JSON.parse(text) as unknown
  } catch {
    // biome-ignore lint/style/useErrorCause: no parsed error object to attach as cause
    throw new Error('OAuth response was not valid JSON')
  }
}

function assertSecureURL(rawURL: string): void {
  const url = new URL(rawURL)
  if (url.protocol === 'https:') {
    return
  }
  if (url.protocol === 'http:' && isLoopbackHost(url.hostname)) {
    return
  }
  throw new Error(`OAuth endpoint must use https: ${rawURL}`)
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname === '[::1]'
  )
}

function parseOAuthError(status: number, text: string): OAuthTokenError {
  let code: string | undefined
  let description: string | undefined
  try {
    const parsed = JSON.parse(text) as unknown
    if (parsed != null && typeof parsed === 'object') {
      const record = parsed as Record<string, unknown>
      if (typeof record.error === 'string') {
        code = record.error
      }
      if (typeof record.error_description === 'string') {
        description = record.error_description
      }
    }
  } catch {
    // non-JSON / empty error body → code undefined (treated as transient by callers)
  }
  return new OAuthTokenError(status, code, description)
}

async function readCappedText(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader()
  if (reader == null) {
    const text = await response.text()
    if (byteLength(text) > maxBytes) {
      throw new Error(`OAuth response exceeded ${maxBytes} bytes`)
    }
    return text
  }

  const chunks: Array<Uint8Array> = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    if (value != null) {
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel()
        throw new Error(`OAuth response exceeded ${maxBytes} bytes`)
      }
      chunks.push(value)
    }
  }

  return new TextDecoder().decode(concat(chunks, total))
}

function concat(chunks: Array<Uint8Array>, total: number): Uint8Array {
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

function byteLength(text: string): number {
  return new TextEncoder().encode(text).byteLength
}
