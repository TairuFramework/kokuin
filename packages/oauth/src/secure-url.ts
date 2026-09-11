export function assertSecureURL(rawURL: string): void {
  const url = new URL(rawURL)
  if (url.protocol === 'https:') {
    return
  }
  if (url.protocol === 'http:' && isLoopbackHost(url.hostname)) {
    return
  }
  throw new Error(`OAuth endpoint must use https: ${rawURL}`)
}

export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname === '[::1]'
  )
}
