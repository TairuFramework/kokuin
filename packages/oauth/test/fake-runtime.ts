import type { Runtime } from '@sozai/runtime'

export function fakeRuntime(overrides: Partial<Runtime> = {}): Runtime {
  let idCounter = 0
  return {
    fetch: async () => new Response('{}', { headers: { 'content-type': 'application/json' } }),
    getRandomID: () => `id-${idCounter++}`,
    getRandomValues: <T extends ArrayBufferView>(array: T): T => {
      const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
      for (let i = 0; i < view.length; i++) {
        view[i] = (i + 1) & 0xff
      }
      return array
    },
    ...overrides,
  }
}
