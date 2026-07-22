const { app, BrowserWindow, ipcMain, shell, Menu, MenuItem, dialog, safeStorage, session } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, execFile } = require('child_process');
const SystemProxyManager = require('./src/SystemProxyManager');
const Diagnostics = require('./src/Diagnostics');

let mainWindow;
let singboxProcess = null;
let logStream = null; // Use write stream instead of appendFileSync
let systemProxyManager = null;
let stopPromise = null;
let quitCleanupStarted = false;

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
    if ('inet4_address' in inbound || 'sniff' in inbound || 'sniff_override_destination' in inbound) {
      return { valid: false, message: `Inbound "${inbound.tag}" uses a removed sing-box field.` };
    }
  }
  if (config.outbounds.some(outbound => outbound.type === 'block' || outbound.type === 'dns')) {
    return { valid: false, message: 'Removed block/dns outbound types are not allowed.' };
  }
  if ((config.route.rules || []).some(rule => 'geoip' in rule || 'geosite' in rule)) {
    return { valid: false, message: 'Legacy geoip/geosite rules are not allowed; use rule_set.' };
  }
  return { valid: true, config };
}

function checkSingboxConfig(binaryPath, configPath) {
  return new Promise((resolve, reject) => {
    execFile(binaryPath, ['check', '-c', configPath], { cwd: getDataDir(), timeout: 15000 }, (error, stdout, stderr) => {
      if (error) return reject(new Error((stderr || stdout || error.message).trim()));
      resolve();
    });
  });
}

function waitForProcessStartup(proc, delay = 750) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, delay);
    const onError = error => {
      cleanup();
      reject(error);
    };
    const onClose = code => {
      cleanup();
      reject(new Error(`sing-box exited during startup with code ${code}.`));
    };
    const cleanup = () => {
      clearTimeout(timer);
      proc.removeListener('error', onError);
      proc.removeListener('close', onClose);
    };
    proc.once('error', onError);
    proc.once('close', onClose);
  });
}

function writeFileAtomic(filePath, contents) {
  const tempPath = `${filePath}.tmp`;
  fs.writeFileSync(tempPath, contents, { mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

function isWindowsAdministrator() {
  if (process.platform !== 'win32') return Promise.resolve(true);
  const script = [
    '$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());',
    '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
  ].join(' ');
  return new Promise(resolve => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000 }, (error, stdout) => {
      resolve(!error && String(stdout).trim().toLowerCase() === 'true');
    });
  });
}

function sendLog(message) {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('singbox-log', message);
}

async function restoreSystemProxy() {
  if (!systemProxyManager) return;
  try {
    await systemProxyManager.restore();
  } catch (error) {
    sendLog(`[ERROR] Failed to restore Windows system proxy: ${error.message}`);
  }
}

async function stopEngine() {
  if (stopPromise) return stopPromise;
  stopPromise = (async () => {
    const proc = singboxProcess;
    if (proc) {
      await new Promise(resolve => {
        let finished = false;
        const finish = () => {
          if (finished) return;
          finished = true;
          resolve();
        };
        const forceKillTimer = setTimeout(() => {
          try { proc.kill('SIGKILL'); } catch (_) {}
          sendLog('[WARNING] sing-box force-killed after timeout.');
          finish();
        }, 5000);
        proc.once('close', () => {
          clearTimeout(forceKillTimer);
          finish();
        });
        try { proc.kill('SIGTERM'); } catch (_) { finish(); }
      });
    }
    if (singboxProcess === proc) singboxProcess = null;
    await restoreSystemProxy();
    return { status: proc ? 'stopped' : 'already-stopped' };
  })();
  try {
    return await stopPromise;
  } finally {
    stopPromise = null;
  }
}

// ── Security: Encrypt sensitive profile fields using OS credential store ──
function encryptProfiles(profiles) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure credential storage is unavailable. Profiles were not written to disk.');
  }
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
    if (clone.plugin_opts) {
      clone.plugin_opts = safeStorage.encryptString(clone.plugin_opts).toString('base64');
      clone.__encrypted_plugin_opts = true;
    }
    if (clone.obfs && clone.obfs.password) {
      clone.obfs.password = safeStorage.encryptString(clone.obfs.password).toString('base64');
      clone.__encrypted_obfs_password = true;
    }
    return clone;
  });
}

function decryptProfiles(profiles) {
  if (!safeStorage.isEncryptionAvailable()) {
    if (profiles.some(profile => Object.keys(profile).some(key => key.startsWith('__encrypted_')))) {
      throw new Error('Secure credential storage is unavailable; encrypted profiles cannot be opened.');
    }
    return profiles;
  }
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
      if (clone.__encrypted_plugin_opts && clone.plugin_opts) {
        clone.plugin_opts = safeStorage.decryptString(Buffer.from(clone.plugin_opts, 'base64'));
        delete clone.__encrypted_plugin_opts;
      }
      if (clone.__encrypted_obfs_password && clone.obfs && clone.obfs.password) {
        clone.obfs.password = safeStorage.decryptString(Buffer.from(clone.obfs.password, 'base64'));
        delete clone.__encrypted_obfs_password;
      }
    } catch (e) {
      // Decryption failed (e.g., migrated from another machine) — clear sensitive fields
      console.error('Decryption failed for profile, clearing sensitive data:', e.message);
      if (clone.__encrypted_uuid) { clone.uuid = ''; delete clone.__encrypted_uuid; }
      if (clone.__encrypted_password) { clone.password = ''; delete clone.__encrypted_password; }
      if (clone.__encrypted_plugin_opts) { clone.plugin_opts = ''; delete clone.__encrypted_plugin_opts; }
      if (clone.__encrypted_obfs_password) {
        if (clone.obfs) clone.obfs.password = '';
        delete clone.__encrypted_obfs_password;
      }
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

app.whenReady().then(async () => {
  // ── Security: Set CSP header for all requests ──
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self' stun:;"]
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
  systemProxyManager = new SystemProxyManager({
    execFile,
    snapshotPath: path.join(getDataDir(), 'system-proxy-backup.json')
  });
  try {
    const recovery = await systemProxyManager.recoverStaleSettings();
    if (recovery.recovered) console.info('Recovered Windows system proxy settings left by an interrupted session.');
  } catch (error) {
    console.error('Failed to recover stale Windows system proxy settings:', error.message);
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

// Clean up the child process and restore the original Windows proxy settings.
app.on('before-quit', (event) => {
  if (quitCleanupStarted) return;
  event.preventDefault();
  quitCleanupStarted = true;
  stopEngine().finally(() => {
    if (logStream) {
      logStream.end();
      logStream = null;
    }
    app.quit();
  });
});

// IPC Handlers for Controller

ipcMain.handle('start-singbox', async (event, configJson) => {
  if (singboxProcess) return { status: 'already-running' };

  // ── Security: Validate config before writing to disk ──
  const validation = validateConfig(configJson);
  if (!validation.valid) {
    sendLog(`[SECURITY] Config validation failed: ${validation.message}`);
    return { status: 'error', message: validation.message };
  }

  const requestedMode = validation.config.inbounds.some(inbound => inbound.type === 'tun') ? 'tun' : 'system';
  if (requestedMode === 'tun' && !(await isWindowsAdministrator())) {
    const message = 'TUN mode requires Administrator privileges on Windows. Restart SurgeLab as Administrator.';
    sendLog(`[ERROR] ${message}`);
    return { status: 'error', message };
  }

  // Validate a candidate file first so a bad config never replaces the last known-good config.
  const configPath = path.join(getDataDir(), 'sing-box.json');
  const candidatePath = path.join(getDataDir(), 'sing-box.next.json');
  writeFileAtomic(candidatePath, configJson);

  const singboxPath = getSingboxPath();
  if (!singboxPath) {
    try { if (fs.existsSync(candidatePath)) fs.unlinkSync(candidatePath); } catch (_) {}
    const errorMsg = '[ERROR] Cannot find sing-box binary. Place sing-box in the app folder.';
    sendLog(errorMsg);
    return { status: 'error', message: 'binary not found' };
  }

  try {
    await checkSingboxConfig(singboxPath, candidatePath);
    fs.renameSync(candidatePath, configPath);
    sendLog('[INFO] sing-box configuration check passed.');
  } catch (error) {
    try { if (fs.existsSync(candidatePath)) fs.unlinkSync(candidatePath); } catch (_) {}
    sendLog(`[ERROR] sing-box rejected the configuration: ${error.message}`);
    return { status: 'error', message: 'Configuration check failed. See logs for details.' };
  }

  if (requestedMode === 'system') {
    try {
      await systemProxyManager.enable('127.0.0.1', 2080);
      sendLog('[INFO] Windows system proxy enabled at 127.0.0.1:2080.');
    } catch (error) {
      sendLog(`[ERROR] ${error.message}`);
      return { status: 'error', message: error.message };
    }
  }

  // Initialize persistent log file using write stream (non-blocking)
  const logFile = path.join(getDataDir(), 'sing-box.log');
  try {
    if (logStream) logStream.end();
    logStream = fs.createWriteStream(logFile, { flags: 'w' });
  } catch (err) {
    console.error('Failed to init log file:', err);
  }

  try {
    singboxProcess = spawn(singboxPath, ['run', '-c', configPath], { cwd: getDataDir(), windowsHide: true });
  } catch (error) {
    await restoreSystemProxy();
    sendLog(`[ERROR] Failed to start sing-box: ${error.message}`);
    return { status: 'error', message: error.message };
  }

  const startedProcess = singboxProcess;

  singboxProcess.stdout.on('data', (data) => {
    if (logStream && !logStream.destroyed) logStream.write(data);
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) sendLog(`[sing-box] ${line}`);
    });
  });

  singboxProcess.stderr.on('data', (data) => {
    if (logStream && !logStream.destroyed) logStream.write(data);
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line) sendLog(`[sing-box ERR] ${line}`);
    });
  });

  startedProcess.on('error', async (err) => {
    if (singboxProcess === startedProcess) singboxProcess = null;
    await restoreSystemProxy();
    sendLog(`[ERROR] Failed to start sing-box: ${err.message}`);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('singbox-status', 'stopped');
  });

  startedProcess.on('close', async (code) => {
    if (singboxProcess === startedProcess) singboxProcess = null;
    await restoreSystemProxy();
    sendLog(`[INFO] sing-box exited with code ${code}`);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('singbox-status', 'stopped');
  });

  try {
    await waitForProcessStartup(startedProcess);
  } catch (error) {
    await restoreSystemProxy();
    return { status: 'error', message: error.message };
  }

  sendLog(requestedMode === 'tun' ? '[INFO] sing-box TUN mode started.' : '[INFO] sing-box system proxy mode started.');

  return { status: 'running', pid: startedProcess.pid };
});

// ── Security: Graceful shutdown with timeout fallback ──
ipcMain.handle('stop-singbox', async () => stopEngine());

// ── Security: Encrypt profiles before saving to disk ──
ipcMain.handle('save-profiles', async (event, data) => {
  try {
    if (!Array.isArray(data)) throw new Error('Profiles must be an array.');
    const encrypted = encryptProfiles(data);
    writeFileAtomic(path.join(getDataDir(), 'profiles.json'), JSON.stringify(encrypted, null, 2));
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

ipcMain.handle('save-rules', async (event, rules) => {
  try {
    if (!Array.isArray(rules)) throw new Error('Rules must be an array.');
    writeFileAtomic(path.join(getDataDir(), 'rules.json'), JSON.stringify(rules, null, 2));
    return { success: true };
  } catch (error) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('load-rules', async () => {
  const rulesPath = path.join(getDataDir(), 'rules.json');
  if (!fs.existsSync(rulesPath)) return [];
  try {
    const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
    return Array.isArray(rules) ? rules : [];
  } catch (error) {
    console.error('Failed to load rules:', error.message);
    return [];
  }
});

ipcMain.handle('test-latencies', async (event, nodes) => {
  if (!Array.isArray(nodes)) return [];
  const safeNodes = nodes.slice(0, 50).map(node => ({ name: String(node.name || node.server || 'Node'), server: node.server, port: node.port }));
  return Promise.all(safeNodes.map(async node => ({
    name: node.name,
    server: node.server,
    ...(await Diagnostics.testLatency(node))
  })));
});

ipcMain.handle('test-dns', async (event, request) => {
  try {
    return await Diagnostics.testDns(request && request.domain, request && request.server);
  } catch (error) {
    return { success: false, error: error.message };
  }
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
