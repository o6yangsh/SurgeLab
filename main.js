const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

let mainWindow;
let singboxProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    title: 'SurgeLab for Windows',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadFile('src/index.html');
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Handlers for Controller

ipcMain.handle('start-singbox', async (event, configJson) => {
  if (singboxProcess) return { status: 'already-running' };
  
  // Save config to disk before starting
  const configPath = path.join(__dirname, 'sing-box.json');
  fs.writeFileSync(configPath, configJson);

  const singboxPath = path.join(__dirname, process.platform === 'win32' ? 'sing-box.exe' : 'sing-box');
  
  if (!fs.existsSync(singboxPath)) {
    const errorMsg = `[ERROR] Cannot find sing-box executable at ${singboxPath}`;
    mainWindow.webContents.send('singbox-log', errorMsg);
    return { status: 'error', message: 'binary not found' };
  }

  singboxProcess = spawn(singboxPath, ['run', '-c', configPath]);

  singboxProcess.stdout.on('data', (data) => {
    mainWindow.webContents.send('singbox-log', `[sing-box] ${data.toString().trim()}`);
  });

  singboxProcess.stderr.on('data', (data) => {
    mainWindow.webContents.send('singbox-log', `[sing-box ERR] ${data.toString().trim()}`);
  });

  singboxProcess.on('close', (code) => {
    singboxProcess = null;
    mainWindow.webContents.send('singbox-log', `[INFO] sing-box process exited with code ${code}`);
  });

  mainWindow.webContents.send('singbox-log', '[INFO] sing-box started on 127.0.0.1');
  return { status: 'running', pid: singboxProcess.pid };
});

ipcMain.handle('stop-singbox', async () => {
  if (singboxProcess) {
    singboxProcess.kill();
    singboxProcess = null;
    mainWindow.webContents.send('singbox-log', '[INFO] sing-box stopped.');
    return { status: 'stopped' };
  }
  return { status: 'already-stopped' };
});

ipcMain.handle('save-profiles', async (event, data) => {
  fs.writeFileSync(path.join(__dirname, 'profiles.json'), JSON.stringify(data, null, 2));
  return { success: true };
});

ipcMain.handle('load-profiles', async () => {
  const p = path.join(__dirname, 'profiles.json');
  if (fs.existsSync(p)) {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  return [];
});
