import { expect, test } from '@playwright/test'

test('identity persists across reload', async ({ page }) => {
  await page.goto('/')

  const did1 = await page.getByTestId('durable-did').textContent()
  expect(did1).toMatch(/^did:key:z/)

  await page.reload()

  const did2 = await page.getByTestId('durable-did').textContent()
  expect(did2).toMatch(/^did:key:z/)
  expect(did2).toBe(did1)
})
