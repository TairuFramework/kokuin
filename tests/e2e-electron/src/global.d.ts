export {}

declare global {
  // biome-ignore lint/style/useConsistentTypeDefinitions: extend interface
  interface Window {
    kokuin: {
      sign: (payload: Record<string, unknown>, keyID?: string) => Promise<string>
    }
  }
}
