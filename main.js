const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

let mainWindow;
let singboxProcess = null;

// Use userData for writable files (config, profiles)
// In packaged app, __dirname is read-only (inside asar archive)
function getDataDir() {
  return app.getPath('userData');
}

// Find sing-box binary: check extraResources first (packaged), then project root (dev)
function getSingboxPath() {
  const binaryName = process.platform === 'win32' ? 'sing-box.exe' : 'sing-box';
  // Packaged app: binary is in resources/sing-box.exe
  const packagedPath = path.join(process.resourcesPath, binaryName);
  if (fs.existsSync(packagedPath)) return packagedPath;
  // Dev mode: binary is in project root
  const devPath = path.join(__dirname, binaryName);
  if (fs.existsSync(devPath)) return devPath;
  return null;
}

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

// Clean up sing-box process when app quits to prevent orphaned processes
app.on('before-quit', () => {
  if (singboxProcess) {
    singboxProcess.kill();
    singboxProcess = null;
  }
});

// IPC Handlers for Controller

ipcMain.handle('start-singbox', async (event, configJson) => {
  if (singboxProcess) return { status: 'already-running' };
  
  // Save config to writable userData directory
  const configPath = path.join(getDataDir(), 'sing-box.json');
  fs.writeFileSync(configPath, configJson);

  const singboxPath = getSingboxPath();
  
  if (!singboxPath) {
    const errorMsg = '[ERROR] Cannot find sing-box binary. Place sing-box.exe in the app folder.';
    mainWindow.webContents.send('singbox-log', errorMsg);
    return { status: 'error', message: 'binary not found' };
  }

  singboxProcess = spawn(singboxPath, ['run', '-c', configPath]);

  singboxProcess.stdout.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) mainWindow.webContents.send('singbox-log', `[sing-box] ${line}`);
    });
  });

  singboxProcess.stderr.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) mainWindow.webContents.send('singbox-log', `[sing-box ERR] ${line}`);
    });
  });

  singboxProcess.on('error', (err) => {
    singboxProcess = null;
    mainWindow.webContents.send('singbox-log', `[ERROR] Failed to start sing-box: ${err.message}`);
    mainWindow.webContents.send('singbox-status', 'stopped');
  });

  singboxProcess.on('close', (code) => {
    singboxProcess = null;
    mainWindow.webContents.send('singbox-log', `[INFO] sing-box exited with code ${code}`);
    mainWindow.webContents.send('singbox-status', 'stopped');
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
  fs.writeFileSync(path.join(getDataDir(), 'profiles.json'), JSON.stringify(data, null, 2));
  return { success: true };
});

ipcMain.handle('load-profiles', async () => {
  const p = path.join(getDataDir(), 'profiles.json');
  if (fs.existsSync(p)) {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  return [];
});
