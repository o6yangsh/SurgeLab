const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  startSingbox: (config) => ipcRenderer.invoke('start-singbox', config),
  stopSingbox: () => ipcRenderer.invoke('stop-singbox'),
  saveProfiles: (data) => ipcRenderer.invoke('save-profiles', data),
  loadProfiles: () => ipcRenderer.invoke('load-profiles'),
  onSingboxLog: (callback) => ipcRenderer.on('singbox-log', (event, log) => callback(log))
});
