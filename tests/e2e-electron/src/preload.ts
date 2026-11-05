import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('kokuin', {
  sign: (payload: Record<string, unknown>, keyID?: string): Promise<string> => {
    return ipcRenderer.invoke('sign', payload, keyID)
  },
  cryptoStatus: (): Promise<unknown> => ipcRenderer.invoke('crypto-status'),
})
