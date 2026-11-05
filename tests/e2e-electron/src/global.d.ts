export type KokuinWindow = Window & {
  kokuin: {
    sign: (payload: Record<string, unknown>, keyID?: string) => Promise<string>
  }
}
