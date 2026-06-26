export {}

declare global {
  interface Window {
    kokuin: {
      sign: (payload: Record<string, unknown>, keyID?: string) => Promise<string>
    }
  }
}
