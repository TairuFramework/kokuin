import { expect, test } from '@playwright/test'

test('two identities coexist and persist independently across reload', async ({ page }) => {
  await page.goto('/')

  const alpha1 = await page.getByTestId('alpha-did').textContent()
  const beta1 = await page.getByTestId('beta-did').textContent()
  expect(alpha1).toMatch(/^did:key:z/)
  expect(beta1).toMatch(/^did:key:z/)
  expect(alpha1).not.toBe(beta1)

  await page.reload()

  const alpha2 = await page.getByTestId('alpha-did').textContent()
  const beta2 = await page.getByTestId('beta-did').textContent()
  expect(alpha2).toMatch(/^did:key:z/)
  expect(beta2).toMatch(/^did:key:z/)
  expect(alpha2).toBe(alpha1)
  expect(beta2).toBe(beta1)
})
