export type KokuinWindow = Window & {
  kokuin: {
    sign: (payload: Record<string, unknown>, keyID?: string) => Promise<string>
    cryptoStatus: () => Promise<{ backend: string; failure?: unknown; signCount: number }>
  }
}
