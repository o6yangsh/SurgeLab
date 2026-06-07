const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  startSingbox: (config) => ipcRenderer.invoke('start-singbox', config),
  stopSingbox: () => ipcRenderer.invoke('stop-singbox'),
  saveProfiles: (data) => ipcRenderer.invoke('save-profiles', data),
  loadProfiles: () => ipcRenderer.invoke('load-profiles'),
  openLogFile: () => ipcRenderer.invoke('open-log-file'),
  exportLogFile: () => ipcRenderer.invoke('export-log-file'),
  onSingboxLog: (callback) => ipcRenderer.on('singbox-log', (event, log) => callback(log)),
  onSingboxStatus: (callback) => ipcRenderer.on('singbox-status', (event, status) => callback(status))
});
