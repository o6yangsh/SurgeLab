const { app, BrowserWindow, ipcMain, shell, Menu, MenuItem, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
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

// Download helper with redirect support
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const request = https.get(url, (response) => {
      // Handle redirects (e.g. 301, 302)
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        file.close();
        fs.unlink(dest, () => {}); // delete partial file
        return downloadFile(response.headers.location, dest).then(resolve).catch(reject);
      }
      
      if (response.statusCode !== 200) {
        file.close();
        fs.unlink(dest, () => {});
        return reject(new Error(`Failed to get '${url}' (status code: ${response.statusCode})`));
      }

      response.pipe(file);
      
      file.on('finish', () => {
        file.close(resolve);
      });
    });

    request.on('error', (err) => {
      file.close();
      fs.unlink(dest, () => {});
      reject(err);
    });
  });
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

  // Context Menu for Copy/Paste
  mainWindow.webContents.on('context-menu', (e, params) => {
    const menu = new Menu();

    if (params.isEditable) {
      menu.append(new MenuItem({ label: 'Cut', role: 'cut', enabled: params.selectionText.length > 0 }));
      menu.append(new MenuItem({ label: 'Copy', role: 'copy', enabled: params.selectionText.length > 0 }));
      menu.append(new MenuItem({ label: 'Paste', role: 'paste' }));
      menu.append(new MenuItem({ type: 'separator' }));
      menu.append(new MenuItem({ label: 'Select All', role: 'selectall' }));
    } else {
      menu.append(new MenuItem({ label: 'Copy', role: 'copy', enabled: params.selectionText.length > 0 }));
      menu.append(new MenuItem({ label: 'Select All', role: 'selectall' }));
    }

    menu.popup({ window: mainWindow });
  });
}

app.whenReady().then(() => {
  if (app.setAboutPanelOptions) {
    app.setAboutPanelOptions({
      applicationName: 'SurgeLab',
      applicationVersion: '1.2.0',
      version: 'v1.2.0',
      copyright: 'Copyright © 2026 SurgeLab Team',
      authors: ['SurgeLab Team']
    });
  }
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

  // Initialize persistent log file
  const logFile = path.join(getDataDir(), 'sing-box.log');
  try {
    fs.writeFileSync(logFile, '');
  } catch (err) {
    console.error('Failed to init log file:', err);
  }

  // Ensure geosite.db and geoip.db exist locally to prevent offline crash
  const geositePath = path.join(getDataDir(), 'geosite.db');
  const geoipPath = path.join(getDataDir(), 'geoip.db');
  if (!fs.existsSync(geositePath) || !fs.existsSync(geoipPath)) {
    mainWindow.webContents.send('singbox-log', '[INFO] geoip.db or geosite.db is missing. Downloading from mirror (ghproxy)...');
    try {
      if (!fs.existsSync(geositePath)) {
        await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db', geositePath);
        mainWindow.webContents.send('singbox-log', '[INFO] geosite.db downloaded successfully.');
      }
      if (!fs.existsSync(geoipPath)) {
        await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db', geoipPath);
        mainWindow.webContents.send('singbox-log', '[INFO] geoip.db downloaded successfully.');
      }
    } catch (err) {
      mainWindow.webContents.send('singbox-log', `[WARNING] Failed to download geo databases: ${err.message}. sing-box may fail to start.`);
    }
  }

  const singboxPath = getSingboxPath();
  
  if (!singboxPath) {
    const errorMsg = '[ERROR] Cannot find sing-box binary. Place sing-box.exe in the app folder.';
    mainWindow.webContents.send('singbox-log', errorMsg);
    return { status: 'error', message: 'binary not found' };
  }

  singboxProcess = spawn(singboxPath, ['run', '-c', configPath], { cwd: getDataDir() });

  singboxProcess.stdout.on('data', (data) => {
    try {
      fs.appendFileSync(logFile, data);
    } catch (e) {}
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) mainWindow.webContents.send('singbox-log', `[sing-box] ${line}`);
    });
  });

  singboxProcess.stderr.on('data', (data) => {
    try {
      fs.appendFileSync(logFile, data);
    } catch (e) {}
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

ipcMain.handle('open-log-file', async () => {
  const logPath = path.join(getDataDir(), 'sing-box.log');
  if (fs.existsSync(logPath)) {
    await shell.openPath(logPath);
    return { success: true };
  }
  return { success: false, message: 'Log file does not exist.' };
});

ipcMain.handle('export-log-file', async () => {
  const logPath = path.join(getDataDir(), 'sing-box.log');
  if (!fs.existsSync(logPath)) {
    return { success: false, message: 'Log file is empty or does not exist.' };
  }

  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Export System Logs',
    defaultPath: path.join(app.getPath('desktop'), 'SurgeLab_Logs.txt'),
    filters: [
      { name: 'Text Files', extensions: ['txt'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });

  if (filePath) {
    try {
      fs.copyFileSync(logPath, filePath);
      return { success: true, filePath };
    } catch (err) {
      return { success: false, message: `Failed to save file: ${err.message}` };
    }
  }
  return { success: false, cancelled: true };
});
