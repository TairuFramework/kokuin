export type OAuthClientMode =
  | { mode: 'confidential'; clientID: string; clientSecret: string }
  | { mode: 'native'; clientID: string; clientSecret?: string }
  | { mode: 'broker'; clientID: string }

export type OAuthProviderDefinition = {
  name: string
  authorizationEndpoint: string
  tokenEndpoint: string
  baseScopes?: Array<string>
} & OAuthClientMode

export type TokenResponse = {
  access_token: string
  refresh_token?: string
  expires_in?: number
  token_type: string
  scope?: string
}

export type OAuthErrorCode =
  | 'invalid_grant'
  | 'invalid_client'
  | 'invalid_request'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | string // forward-compatible: unknown codes preserved verbatim

export class OAuthTokenError extends Error {
  status: number
  code?: OAuthErrorCode
  description?: string

  constructor(status: number, code?: OAuthErrorCode, description?: string) {
    super(description ?? code ?? `OAuth token request failed with status ${status}`)
    this.name = 'OAuthTokenError'
    this.status = status
    this.code = code
    this.description = description
  }
}

export type RequestOptions = {
  signal?: AbortSignal
  timeoutMs?: number
  maxBytes?: number
}
