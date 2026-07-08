import { _electron as electron, expect, test } from '@playwright/test'

import { productName } from '../package.json'

function extractDID(text: string | null): string {
  if (!text) throw new Error('No text')
  const match = text.match(/did:key:z\S+/)
  if (!match) throw new Error(`No DID found in "${text}"`)
  return match[0]
}

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
const launchArgs = [
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-gpu',
  '--disable-dev-shm-usage',
]

test('two identities coexist and persist independently across an app restart', async () => {
  // First launch: sign with two different keyIDs and confirm they produce distinct identities.
  const app1 = await electron.launch({ executablePath, args: launchArgs })
  const page1 = await app1.firstWindow()
  await page1.waitForLoadState('domcontentloaded')

  await page1.getByText('Sign alpha', { exact: true }).click()
  const alphaDID1Raw = await page1.getByTestId('alpha-did').textContent()
  expect(alphaDID1Raw).toMatch(/^Alpha DID: did:key:z/)
  const alphaDID1 = extractDID(alphaDID1Raw)

  await page1.getByText('Sign beta', { exact: true }).click()
  const betaDID1Raw = await page1.getByTestId('beta-did').textContent()
  expect(betaDID1Raw).toMatch(/^Beta DID: did:key:z/)
  const betaDID1 = extractDID(betaDID1Raw)

  expect(alphaDID1).not.toBe(betaDID1)

  await app1.close()

  // Second launch (fresh process, same userData dir): alpha's key must still be the one
  // persisted on disk, not clobbered by beta's set() during the first session.
  const app2 = await electron.launch({ executablePath, args: launchArgs })
  const page2 = await app2.firstWindow()
  await page2.waitForLoadState('domcontentloaded')

  await page2.getByText('Sign alpha', { exact: true }).click()
  const alphaDID2Raw = await page2.getByTestId('alpha-did').textContent()
  expect(alphaDID2Raw).toMatch(/^Alpha DID: did:key:z/)
  const alphaDID2 = extractDID(alphaDID2Raw)

  expect(alphaDID2).toBe(alphaDID1)

  await app2.close()
})
