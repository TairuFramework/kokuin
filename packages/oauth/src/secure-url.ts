import { isLoopbackHost, normalizeHostname } from '@sozai/http-util'

export function assertSecureURL(rawURL: string): void {
  const url = new URL(rawURL)
  if (url.protocol === 'https:') {
    return
  }
  if (url.protocol === 'http:' && isLoopbackHost(normalizeHostname(url))) {
    return
  }
  throw new Error(`OAuth endpoint must use https: ${rawURL}`)
}
