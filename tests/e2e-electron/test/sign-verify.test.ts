import { _electron as electron, expect, test } from '@playwright/test'

import { productName } from '../package.json'
import type { KokuinWindow } from '../src/global.js'

function getAppPath() {
  switch (process.platform) {
    case 'darwin':
      return `out/${productName}-darwin-${process.arch}/${productName}.app/Contents/MacOS/${productName}`
    case 'linux':
      return `out/${productName}-linux-${process.arch}/${productName}`
    case 'win32':
      return `out/${productName}-win32-${process.arch}/${productName}.exe`
    default:
      throw new Error(`Unsupported platform: ${process.platform}`)
  }
}

const executablePath = getAppPath()

test('sign and verify token', async () => {
  const app = await electron.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  })
  const page = await app.firstWindow()
  await page.waitForLoadState('domcontentloaded')
  await page.getByText('Sign token').click()
  await page.getByText('Verify token').click()
  await page.getByText('Verified token: OK').waitFor()
  await app.close()
})

test('the keystore signs through the Node-API provider', async () => {
  const app = await electron.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  })
  const page = await app.firstWindow()
  await page.waitForLoadState('domcontentloaded')
  const status = await page.evaluate(async () => {
    const { kokuin } = window as unknown as KokuinWindow
    await kokuin.sign({ test: 'OK' })
    return await kokuin.cryptoStatus()
  })
  // The provider falls back to nodeCrypto when the binary does not load, which signs just as well.
  expect(status.failure).toBeUndefined()
  expect(status.backend).toBe('napi')
  expect(status.signCount).toBe(1)
  await app.close()
})
