import type { Runtime } from '@sozai/runtime'

import { assertSecureURL } from './secure-url.js'
import { OAuthTokenError, type RequestOptions } from './types.js'

export type FetchOAuthJSONParams = {
  runtime: Pick<Runtime, 'fetch'>
  url: string
  /**
   * Accept an empty (or whitespace-only) success body, resolving `undefined`. Defaults to `true`:
   * RFC 7009 token revocation answers `200` with no content. Set `false` to reject it as invalid
   * JSON.
   */
  allowEmpty?: boolean
} & (
  | {
      /** Defaults to `POST`. */
      method?: 'POST'
      body: string
      contentType: string
    }
  | {
      /** A metadata read: no body and no content type. */
      method: 'GET'
      body?: undefined
      contentType?: undefined
    }
) &
  RequestOptions

export type RequestOAuthJSONParams = FetchOAuthJSONParams & {
  /**
   * Extra request headers, such as `authorization: Basic …`. `accept` and, when there is a body,
   * `content-type` are always set from the other params and win over the same names here
   * (case-insensitive).
   */
  headers?: Record<string, string>
}

export type OAuthJSONResponse = {
  status: number
  /** The parsed JSON body, or `undefined` for an empty body or a non-JSON non-2xx body. */
  body: unknown
}

const DEFAULT_MAX_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 30_000

/**
 * Send an OAuth request and return the status with the parsed JSON body. Unlike `fetchOAuthJSON`,
 * it does not throw on a non-2xx status.
 */
export async function requestOAuthJSON(params: RequestOAuthJSONParams): Promise<OAuthJSONResponse> {
  const {
    runtime,
    url,
    method = 'POST',
    allowEmpty = true,
    body,
    contentType,
    headers,
    signal,
    maxBytes = DEFAULT_MAX_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = params

  assertSecureURL(url)

  const timeoutSignal = AbortSignal.timeout(timeoutMs)
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal

  const requestHeaders = new Headers(headers)
  requestHeaders.set('accept', 'application/json')
  if (contentType != null) {
    requestHeaders.set('content-type', contentType)
  }

  const response = await runtime.fetch(url, {
    method,
    headers: Object.fromEntries(requestHeaders),
    body,
    redirect: 'error',
    signal: combinedSignal,
  })

  const text = await readCappedText(response, maxBytes)

  if (text.trim() === '') {
    if (response.ok && !allowEmpty) {
      throw new Error('OAuth response was not valid JSON')
    }
    return { status: response.status, body: undefined }
  }

  try {
    return { status: response.status, body: JSON.parse(text) as unknown }
  } catch {
    if (!response.ok) {
      return { status: response.status, body: undefined }
    }
    // biome-ignore lint/style/useErrorCause: no parsed error object to attach as cause
    throw new Error('OAuth response was not valid JSON')
  }
}

export async function fetchOAuthJSON(params: FetchOAuthJSONParams): Promise<unknown> {
  const { status, body } = await requestOAuthJSON(params)
  if (status < 200 || status > 299) {
    throw toOAuthError(status, body)
  }
  return body
}

function toOAuthError(status: number, body: unknown): OAuthTokenError {
  let code: string | undefined
  let description: string | undefined
  if (body != null && typeof body === 'object') {
    const record = body as Record<string, unknown>
    if (typeof record.error === 'string') {
      code = record.error
    }
    if (typeof record.error_description === 'string') {
      description = record.error_description
    }
  }
  return new OAuthTokenError({ status, code, description })
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
