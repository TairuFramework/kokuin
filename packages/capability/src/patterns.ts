import type { Permission } from './types.js'

export function isStringOrStringArray(value: unknown): value is string | Array<string> {
  if (typeof value === 'string') {
    return true
  }
  if (Array.isArray(value)) {
    return value.every((item) => typeof item === 'string')
  }
  return false
}

// Valid component: alphanumeric, `-_.:#`. Components are '/'-separated; '*' wildcards only as a whole
// last component. `#` is here because a resource may be a key (`#<key>`). Without `#` the only grant
// that could name a key would be `res: '*'`, so a grant over one key would mean a grant over
// anything. `#` is inert to the matcher (components compared whole), so widening this set cannot
// invalidate an existing capability. Not a licence for arbitrary punctuation: each addition names the
// vocabulary that needs it.
const VALID_COMPONENT_RE = /^[a-zA-Z0-9_\-.:#]+$/
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional check for control characters
const CONTROL_CHAR_RE = /[\x00-\x1f]/

export function assertValidPattern(value: string | Array<string>): void {
  if (Array.isArray(value)) {
    for (const v of value) {
      assertValidPattern(v)
    }
    return
  }

  if (value === '*') {
    return
  }

  if (value === '') {
    throw new Error('Invalid pattern: empty string')
  }

  if (CONTROL_CHAR_RE.test(value)) {
    throw new Error('Invalid pattern: contains control characters')
  }

  if (value.startsWith('/') || value.endsWith('/')) {
    throw new Error('Invalid pattern: leading or trailing slash')
  }

  if (value.includes('//')) {
    throw new Error('Invalid pattern: double slash')
  }

  if (value.includes('../') || value.includes('./')) {
    throw new Error('Invalid pattern: path traversal')
  }

  const parts = value.split('/')
  for (const [i, part] of parts.entries()) {
    if (part === '*') {
      if (i !== parts.length - 1) {
        throw new Error('Invalid pattern: wildcard must be the last component')
      }
    } else if (part.includes('*')) {
      throw new Error('Invalid pattern: wildcard must be a standalone component')
    } else if (!VALID_COMPONENT_RE.test(part)) {
      throw new Error('Invalid pattern: invalid characters')
    }
  }
}

export type IsMatchParams = { expected: string; actual: string }

export function isMatch({ actual, expected }: IsMatchParams): boolean {
  return expected === actual || actual === '*'
}

// `expected` is the requested permission, `actual` the granted one. A grant authorizes a
// request only when the grant's segments match the request's segment-for-segment at the same
// depth, with a `*` grant segment matching the remainder. A grant more specific than the
// request (e.g. `foo/bar/baz` vs requested `foo/bar`) does NOT authorize it — that broadening
// was the privilege-escalation bug. There is no implicit descent either: `foo/bar` does not
// cover `foo/bar/baz`; use `foo/bar/*` for that.
export type HasPartsMatchParams = { expected: string; actual: string }

export function hasPartsMatch({ actual, expected }: HasPartsMatchParams): boolean {
  const expectedParts = expected.split('/')
  const actualParts = actual.split('/')
  for (let i = 0; i < actualParts.length; i++) {
    const grantPart = actualParts[i]
    if (grantPart === '*') {
      return true
    }
    // Grant has a segment the request does not: the grant is more specific than the
    // request, so it must not authorize the broader request.
    if (i >= expectedParts.length) {
      return false
    }
    if (grantPart !== expectedParts[i]) {
      return false
    }
  }
  // All grant segments matched; authorize only when the request is no deeper than the grant.
  return expectedParts.length === actualParts.length
}

export type HasPermissionParams = { expected: Permission; granted: Permission }

export function hasPermission({ granted, expected }: HasPermissionParams): boolean {
  // If multiple actions are expected, check that all of them are granted
  if (Array.isArray(expected.act)) {
    return expected.act.every((act) =>
      hasPermission({ expected: { act, res: expected.res }, granted }),
    )
  }
  // If multiple resources are expected, check that all of them are granted
  if (Array.isArray(expected.res)) {
    return expected.res.every((res) =>
      hasPermission({ expected: { act: expected.act, res }, granted }),
    )
  }
  // If multiple actions are granted, check that at least one of them matches the expectation
  if (Array.isArray(granted.act)) {
    return granted.act.some((act) =>
      hasPermission({ expected, granted: { act, res: granted.res } }),
    )
  }
  // If multiple resource are granted, check that at least one of them matches the expectation
  if (Array.isArray(granted.res)) {
    return granted.res.some((res) =>
      hasPermission({ expected, granted: { act: granted.act, res } }),
    )
  }
  // Sanity check
  if (granted.act === '' || granted.res === '') {
    return false
  }
  if (
    isMatch({ expected: expected.act, actual: granted.act }) &&
    isMatch({ expected: expected.res, actual: granted.res })
  ) {
    return true
  }
  return (
    hasPartsMatch({ expected: expected.act, actual: granted.act }) &&
    hasPartsMatch({ expected: expected.res, actual: granted.res })
  )
}
