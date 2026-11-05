import { beforeEach, expect, test, vi } from 'vitest'

const existing = new Set<string>()
const resolve = vi.fn<(id: string) => string>()

vi.mock('node:fs', () => ({ existsSync: (path: string) => existing.has(path) }))
vi.mock('node:module', () => ({
  createRequire: () => Object.assign(() => ({ ABI_VERSION: -1 }), { resolve }),
}))

const { loadNapiBinding, napiBindingPath, napiTarget } = await import('../src/binding.js')

const notFound = () => {
  throw new Error('Cannot find module')
}

beforeEach(() => {
  existing.clear()
  resolve.mockReset()
})

test('resolves the platform package when no local binary exists', () => {
  resolve.mockReturnValue('/installed/binary.node')
  expect(napiBindingPath()).toBe('/installed/binary.node')
  expect(resolve).toHaveBeenCalledWith(`@kokuin/crypto-napi-${napiTarget()}`)
})

test('a local binary takes precedence over the platform package', () => {
  resolve.mockImplementationOnce(notFound)
  const local = napiBindingPath()
  existing.add(local)
  resolve.mockReturnValue('/installed/binary.node')
  expect(napiBindingPath()).toBe(local)
})

test('a platform without a package reports the expected local path', () => {
  resolve.mockImplementation(notFound)
  expect(napiBindingPath()).toMatch(/native[/\\]kokuin-crypto-napi\..+\.node$/)
})

test('an installed binary with another ABI is refused, not loaded', () => {
  resolve.mockReturnValue('/installed/binary.node')
  existing.add('/installed/binary.node')
  expect(loadNapiBinding()).toEqual({
    binding: null,
    failure: { reason: 'abi', path: '/installed/binary.node' },
  })
})
