import path from 'node:path'
import { createNapiCrypto, type NapiCrypto } from '@kokuin/crypto-napi'
import { ElectronKeyStore } from '@kokuin/electron'
import { stringifyToken } from '@kokuin/token'
import { app, BrowserWindow, ipcMain } from 'electron'

const nativeCrypto = createNapiCrypto()
let signCount = 0
// Counted so a test can tell the keystore signs through this provider: a loaded binding alone
// would stay green if the keystore fell back to its default.
const crypto: NapiCrypto = {
  ...nativeCrypto,
  sign: (params) => {
    signCount++
    return nativeCrypto.sign(params)
  },
}

ipcMain.handle('sign', async (_event, payload: Record<string, unknown>, keyID?: string) => {
  const store = ElectronKeyStore.open({ name: 'KokuinKeystore', crypto })
  const identity = await store.provideIdentity(keyID ?? 'test')
  const token = await identity.signToken({ payload })
  return stringifyToken(token)
})

ipcMain.handle('crypto-status', () => {
  return { backend: crypto.backend, failure: crypto.failure, signCount }
})

const createWindow = () => {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
    },
  })

  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL)
  } else {
    mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`))
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
  })
}

app.on('ready', createWindow)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow()
  }
})
