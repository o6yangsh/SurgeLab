const { app, BrowserWindow, ipcMain, shell, Menu, MenuItem, dialog, safeStorage, session } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { spawn } = require('child_process');

let mainWindow;
let singboxProcess = null;
let logStream = null; // Use write stream instead of appendFileSync

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

// Find packaged resource: check extraResources first (packaged), then project root (dev)
function getResourcePath(filename) {
  // Packaged app: files are in resources/
  const packagedPath = path.join(process.resourcesPath, filename);
  if (fs.existsSync(packagedPath)) return packagedPath;
  // Dev mode: files are in project root
  const devPath = path.join(__dirname, filename);
  if (fs.existsSync(devPath)) return devPath;
  return null;
}

// ── Security: Download helper with redirect limit and timeout ──
function downloadFile(url, dest, maxRedirects = 5) {
  if (maxRedirects <= 0) {
    return Promise.reject(new Error('Too many redirects'));
  }
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    let finished = false;

    const cleanup = (err) => {
      if (finished) return;
      finished = true;
      file.close();
      fs.unlink(dest, () => {});
      reject(err);
    };

    const request = https.get(url, { timeout: 30000 }, (response) => {
      // Handle redirects (e.g. 301, 302) with decrement
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        file.close();
        fs.unlink(dest, () => {});
        return downloadFile(response.headers.location, dest, maxRedirects - 1).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        return cleanup(new Error(`Failed to get '${url}' (status code: ${response.statusCode})`));
      }

      response.pipe(file);

      file.on('finish', () => {
        if (finished) return;
        finished = true;
        file.close(resolve);
      });
    });

    request.on('timeout', () => {
      request.destroy();
      cleanup(new Error('Download timed out after 30 seconds'));
    });

    request.on('error', (err) => {
      cleanup(err);
    });
  });
}

// ── Security: Validate sing-box config JSON structure ──
function validateConfig(configJson) {
  let config;
  try {
    config = JSON.parse(configJson);
  } catch (e) {
    return { valid: false, message: 'Invalid JSON format.' };
  }
  if (!config.dns || !config.inbounds || !config.outbounds || !config.route) {
    return { valid: false, message: 'Missing required config sections (dns, inbounds, outbounds, route).' };
  }
  if (!Array.isArray(config.inbounds) || !Array.isArray(config.outbounds)) {
    return { valid: false, message: 'inbounds and outbounds must be arrays.' };
  }
  // Ensure inbounds only bind to loopback (prevent LAN exposure)
  for (const inbound of config.inbounds) {
    if (inbound.listen && inbound.listen !== '127.0.0.1' && inbound.listen !== '::1') {
      return { valid: false, message: `Security: inbound "${inbound.tag}" must bind to 127.0.0.1, not ${inbound.listen}.` };
    }
  }
  return { valid: true, config };
}

// ── Security: Encrypt sensitive profile fields using OS credential store ──
function encryptProfiles(profiles) {
  if (!safeStorage.isEncryptionAvailable()) return profiles;
  return profiles.map(p => {
    const clone = JSON.parse(JSON.stringify(p));
    if (clone.uuid) {
      clone.uuid = safeStorage.encryptString(clone.uuid).toString('base64');
      clone.__encrypted_uuid = true;
    }
    if (clone.password) {
      clone.password = safeStorage.encryptString(clone.password).toString('base64');
      clone.__encrypted_password = true;
    }
    return clone;
  });
}

function decryptProfiles(profiles) {
  if (!safeStorage.isEncryptionAvailable()) return profiles;
  return profiles.map(p => {
    const clone = JSON.parse(JSON.stringify(p));
    try {
      if (clone.__encrypted_uuid && clone.uuid) {
        clone.uuid = safeStorage.decryptString(Buffer.from(clone.uuid, 'base64'));
        delete clone.__encrypted_uuid;
      }
      if (clone.__encrypted_password && clone.password) {
        clone.password = safeStorage.decryptString(Buffer.from(clone.password, 'base64'));
        delete clone.__encrypted_password;
      }
    } catch (e) {
      // Decryption failed (e.g., migrated from another machine) — clear sensitive fields
      console.error('Decryption failed for profile, clearing sensitive data:', e.message);
      if (clone.__encrypted_uuid) { clone.uuid = ''; delete clone.__encrypted_uuid; }
      if (clone.__encrypted_password) { clone.password = ''; delete clone.__encrypted_password; }
    }
    return clone;
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    title: 'SurgeLab',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,        // Security: enable renderer sandbox
      webviewTag: false,     // Security: disable <webview> tag
    }
  });

  mainWindow.loadFile('src/index.html');

  // ── Security: Block navigation to external URLs (prevents phishing/redirect attacks) ──
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'file:') {
      event.preventDefault();
    }
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

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
  // ── Security: Set CSP header for all requests ──
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:;"]
      }
    });
  });

  if (app.setAboutPanelOptions) {
    app.setAboutPanelOptions({
      applicationName: 'SurgeLab',
      applicationVersion: '1.4.0',
      version: 'v1.4.0',
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
  if (logStream) {
    logStream.end();
    logStream = null;
  }
  if (singboxProcess) {
    singboxProcess.kill();
    singboxProcess = null;
  }
});

// IPC Handlers for Controller

ipcMain.handle('start-singbox', async (event, configJson) => {
  if (singboxProcess) return { status: 'already-running' };

  // ── Security: Validate config before writing to disk ──
  const validation = validateConfig(configJson);
  if (!validation.valid) {
    mainWindow.webContents.send('singbox-log', `[SECURITY] Config validation failed: ${validation.message}`);
    return { status: 'error', message: validation.message };
  }

  // Save config to writable userData directory
  const configPath = path.join(getDataDir(), 'sing-box.json');
  fs.writeFileSync(configPath, configJson);

  // Initialize persistent log file using write stream (non-blocking)
  const logFile = path.join(getDataDir(), 'sing-box.log');
  try {
    if (logStream) logStream.end();
    logStream = fs.createWriteStream(logFile, { flags: 'w' });
  } catch (err) {
    console.error('Failed to init log file:', err);
  }

  // Ensure geosite.db and geoip.db exist locally in userData
  const geositePath = path.join(getDataDir(), 'geosite.db');
  const geoipPath = path.join(getDataDir(), 'geoip.db');
  if (!fs.existsSync(geositePath) || !fs.existsSync(geoipPath)) {
    mainWindow.webContents.send('singbox-log', '[INFO] geoip.db or geosite.db is missing in application data. Initializing from bundle...');
    try {
      if (!fs.existsSync(geositePath)) {
        const bundledGeosite = getResourcePath('geosite.db');
        if (bundledGeosite) {
          fs.copyFileSync(bundledGeosite, geositePath);
          mainWindow.webContents.send('singbox-log', '[INFO] geosite.db copied from bundle (offline).');
        } else {
          mainWindow.webContents.send('singbox-log', '[INFO] Bundled geosite.db not found. Downloading from mirror...');
          await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db', geositePath);
          mainWindow.webContents.send('singbox-log', '[INFO] geosite.db downloaded successfully.');
        }
      }
      if (!fs.existsSync(geoipPath)) {
        const bundledGeoip = getResourcePath('geoip.db');
        if (bundledGeoip) {
          fs.copyFileSync(bundledGeoip, geoipPath);
          mainWindow.webContents.send('singbox-log', '[INFO] geoip.db copied from bundle (offline).');
        } else {
          mainWindow.webContents.send('singbox-log', '[INFO] Bundled geoip.db not found. Downloading from mirror...');
          await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db', geoipPath);
          mainWindow.webContents.send('singbox-log', '[INFO] geoip.db downloaded successfully.');
        }
      }
    } catch (err) {
      mainWindow.webContents.send('singbox-log', `[WARNING] Failed to initialize geo databases: ${err.message}. sing-box may fail to start.`);
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
    if (logStream && !logStream.destroyed) logStream.write(data);
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) mainWindow.webContents.send('singbox-log', `[sing-box] ${line}`);
    });
  });

  singboxProcess.stderr.on('data', (data) => {
    if (logStream && !logStream.destroyed) logStream.write(data);
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

  // Trigger background database update after 30 seconds to keep databases fresh
  setTimeout(async () => {
    if (!singboxProcess) return;
    mainWindow.webContents.send('singbox-log', '[INFO] Starting background check for geo database updates...');
    const tempGeosite = path.join(getDataDir(), 'geosite.db.tmp');
    const tempGeoip = path.join(getDataDir(), 'geoip.db.tmp');
    try {
      await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db', tempGeosite);
      // Atomic replace: rename is atomic on same filesystem
      if (fs.existsSync(tempGeosite)) {
        fs.renameSync(tempGeosite, geositePath);
      }
      await downloadFile('https://mirror.ghproxy.com/https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db', tempGeoip);
      if (fs.existsSync(tempGeoip)) {
        fs.renameSync(tempGeoip, geoipPath);
      }
      mainWindow.webContents.send('singbox-log', '[INFO] Background update of geoip.db and geosite.db completed successfully.');
    } catch (err) {
      mainWindow.webContents.send('singbox-log', `[WARNING] Background update of geo databases failed: ${err.message}. Will retry on next startup.`);
      try { if (fs.existsSync(tempGeosite)) fs.unlinkSync(tempGeosite); } catch (e) {}
      try { if (fs.existsSync(tempGeoip)) fs.unlinkSync(tempGeoip); } catch (e) {}
    }
  }, 30000);

  return { status: 'running', pid: singboxProcess.pid };
});

// ── Security: Graceful shutdown with timeout fallback ──
ipcMain.handle('stop-singbox', async () => {
  if (singboxProcess) {
    const proc = singboxProcess;
    return new Promise((resolve) => {
      const forceKillTimer = setTimeout(() => {
        try { proc.kill('SIGKILL'); } catch (e) {}
        singboxProcess = null;
        mainWindow.webContents.send('singbox-log', '[WARNING] sing-box force-killed after timeout.');
        resolve({ status: 'stopped' });
      }, 5000);

      proc.on('close', () => {
        clearTimeout(forceKillTimer);
        singboxProcess = null;
        mainWindow.webContents.send('singbox-log', '[INFO] sing-box stopped.');
        resolve({ status: 'stopped' });
      });

      proc.kill('SIGTERM');
    });
  }
  return { status: 'already-stopped' };
});

// ── Security: Encrypt profiles before saving to disk ──
ipcMain.handle('save-profiles', async (event, data) => {
  try {
    const encrypted = encryptProfiles(data);
    fs.writeFileSync(path.join(getDataDir(), 'profiles.json'), JSON.stringify(encrypted, null, 2));
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  }
});

// ── Security: Decrypt profiles when loading from disk, with error recovery ──
ipcMain.handle('load-profiles', async () => {
  const p = path.join(getDataDir(), 'profiles.json');
  if (fs.existsSync(p)) {
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      return decryptProfiles(raw);
    } catch (err) {
      console.error('Failed to load profiles:', err.message);
      // Backup corrupted file for recovery
      try {
        fs.copyFileSync(p, p + '.bak');
      } catch (e) {}
      return [];
    }
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
