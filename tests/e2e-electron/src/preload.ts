import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('kokuin', {
  sign: (payload: Record<string, unknown>, keyID?: string): Promise<string> =>
    ipcRenderer.invoke('sign', payload, keyID),
})
