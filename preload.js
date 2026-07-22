const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  startSingbox: (config) => ipcRenderer.invoke('start-singbox', config),
  stopSingbox: () => ipcRenderer.invoke('stop-singbox'),
  saveProfiles: (data) => ipcRenderer.invoke('save-profiles', data),
  loadProfiles: () => ipcRenderer.invoke('load-profiles'),
  saveRules: (data) => ipcRenderer.invoke('save-rules', data),
  loadRules: () => ipcRenderer.invoke('load-rules'),
  testLatencies: (nodes) => ipcRenderer.invoke('test-latencies', nodes),
  testDns: (request) => ipcRenderer.invoke('test-dns', request),
  openLogFile: () => ipcRenderer.invoke('open-log-file'),
  exportLogFile: () => ipcRenderer.invoke('export-log-file'),
  onSingboxLog: (callback) => {
    const handler = (_event, log) => callback(log);
    ipcRenderer.on('singbox-log', handler);
    return () => ipcRenderer.removeListener('singbox-log', handler);
  },
  onSingboxStatus: (callback) => {
    const handler = (_event, status) => callback(status);
    ipcRenderer.on('singbox-status', handler);
    return () => ipcRenderer.removeListener('singbox-status', handler);
  }
});
