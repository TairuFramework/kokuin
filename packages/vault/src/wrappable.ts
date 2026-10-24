export function wrappableDID(identity: { id: string; longForm?: string }): string {
  const longForm = (identity as { longForm?: unknown }).longForm
  return typeof longForm === 'string' ? longForm : identity.id
}
