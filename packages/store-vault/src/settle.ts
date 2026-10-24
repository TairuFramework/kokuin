export type SettleRelease<Values extends ReadonlyArray<unknown>> = {
  [Index in keyof Values]?: (value: Values[Index]) => void
}

/**
 * Waits for every task, then throws the first rejection in task order. Before throwing, runs
 * `release` on each fulfilled value, so a secret from a fulfilled sibling is still zeroed.
 */
export async function settleAll<Values extends ReadonlyArray<unknown>>(
  tasks: { [Index in keyof Values]: Promise<Values[Index]> },
  release?: SettleRelease<Values>,
): Promise<Values> {
  const settled = await Promise.allSettled(tasks as ReadonlyArray<Promise<unknown>>)
  const failure = settled.find((result) => result.status === 'rejected')

  if (failure === undefined) {
    const values = settled.map((result) => (result as PromiseFulfilledResult<unknown>).value)

    return values as unknown as Values
  }

  const releases = release as ReadonlyArray<((value: unknown) => void) | undefined> | undefined

  for (const [index, result] of settled.entries())
    if (result.status === 'fulfilled') releases?.[index]?.(result.value)

  throw failure.reason
}
