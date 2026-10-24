/** Most tasks a records call runs at once, so a large page cannot fill a connection pool. */
export const CONCURRENCY_LIMIT = 16

/**
 * Runs `task` over `items`, at most `limit` at a time, starting them in item order. Every task
 * settles; results keep item order.
 */
export async function settleLimited<Item, Result>(
  items: ReadonlyArray<Item>,
  task: (item: Item, index: number) => Promise<Result>,
  limit = CONCURRENCY_LIMIT,
): Promise<Array<PromiseSettledResult<Result>>> {
  const results: Array<PromiseSettledResult<Result>> = new Array(items.length)
  let next = 0

  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next
      next += 1
      try {
        results[index] = { status: 'fulfilled', value: await task(items[index] as Item, index) }
      } catch (reason) {
        results[index] = { status: 'rejected', reason }
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}
