const fs = require('fs');

const REGISTRY_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const PROXY_VALUES = ['ProxyEnable', 'ProxyServer', 'ProxyOverride'];

class SystemProxyManager {
    constructor({ execFile, snapshotPath, platform = process.platform }) {
        this.execFile = execFile;
        this.snapshotPath = snapshotPath;
        this.platform = platform;
        this.snapshot = null;
        this.active = false;
        this.operation = Promise.resolve();
    }

    _queue(task) {
        this.operation = this.operation.catch(() => {}).then(task);
        return this.operation;
    }

    _exec(command, args) {
        return new Promise((resolve, reject) => {
            this.execFile(command, args, { windowsHide: true, timeout: 10000 }, (error, stdout, stderr) => {
                if (error) {
                    error.details = String(stderr || stdout || error.message).trim();
                    reject(error);
                    return;
                }
                resolve(String(stdout || ''));
            });
        });
    }

    static parseRegistry(output) {
        const values = {};
        String(output || '').split(/\r?\n/).forEach(line => {
            const match = line.match(/^\s+(ProxyEnable|ProxyServer|ProxyOverride)\s+(REG_\w+)\s*(.*)$/i);
            if (match) values[match[1]] = { type: match[2], value: match[3].trim() };
        });
        return values;
    }

    async _readWindowsSettings() {
        try {
            return SystemProxyManager.parseRegistry(await this._exec('reg.exe', ['QUERY', REGISTRY_KEY]));
        } catch (error) {
            throw new Error(`Unable to read Windows proxy settings: ${error.details || error.message}`);
        }
    }

    _persistSnapshot(snapshot) {
        const tempPath = `${this.snapshotPath}.tmp`;
        fs.writeFileSync(tempPath, JSON.stringify(snapshot, null, 2), { mode: 0o600 });
        fs.renameSync(tempPath, this.snapshotPath);
    }

    _loadSnapshot() {
        if (!this.snapshotPath || !fs.existsSync(this.snapshotPath)) return null;
        try {
            return JSON.parse(fs.readFileSync(this.snapshotPath, 'utf8'));
        } catch (error) {
            throw new Error(`Unable to read the saved proxy backup: ${error.message}`);
        }
    }

    _clearSnapshot() {
        if (this.snapshotPath && fs.existsSync(this.snapshotPath)) fs.unlinkSync(this.snapshotPath);
    }

    async _setValue(name, type, value) {
        await this._exec('reg.exe', ['ADD', REGISTRY_KEY, '/v', name, '/t', type, '/d', String(value), '/f']);
    }

    async _deleteValue(name) {
        try {
            await this._exec('reg.exe', ['DELETE', REGISTRY_KEY, '/v', name, '/f']);
        } catch (_) {
            // A missing value means the original state has already been restored.
        }
    }

    async _notifyWindows() {
        const script = [
            '$signature = @"',
            '[DllImport("wininet.dll", SetLastError = true)]',
            'public static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);',
            '"@;',
            'Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace SurgeLab;',
            '[SurgeLab.NativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null;',
            '[SurgeLab.NativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null;'
        ].join('\n');
        await this._exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
    }

    async _restoreSnapshot(snapshot) {
        for (const name of PROXY_VALUES) {
            const previous = snapshot[name];
            if (previous) await this._setValue(name, previous.type, previous.value);
            else await this._deleteValue(name);
        }
        await this._notifyWindows();
    }

    recoverStaleSettings() {
        return this._queue(async () => {
            if (this.platform !== 'win32') return { supported: false, recovered: false };
            const stale = this._loadSnapshot();
            if (!stale) return { supported: true, recovered: false };
            await this._restoreSnapshot(stale);
            this._clearSnapshot();
            this.snapshot = null;
            this.active = false;
            return { supported: true, recovered: true };
        });
    }

    enable(host = '127.0.0.1', port = 2080) {
        return this._queue(async () => {
            if (this.platform !== 'win32') return { supported: false };
            if (this.active) return { supported: true };
            const stale = this._loadSnapshot();
            if (stale) {
                await this._restoreSnapshot(stale);
                this._clearSnapshot();
            }
            this.snapshot = await this._readWindowsSettings();
            this._persistSnapshot(this.snapshot);
            try {
                await this._setValue('ProxyEnable', 'REG_DWORD', 1);
                await this._setValue('ProxyServer', 'REG_SZ', `${host}:${port}`);
                await this._setValue('ProxyOverride', 'REG_SZ', '<local>');
                await this._notifyWindows();
                this.active = true;
                return { supported: true };
            } catch (error) {
                try {
                    await this._restoreSnapshot(this.snapshot);
                    this._clearSnapshot();
                } finally {
                    this.snapshot = null;
                    this.active = false;
                }
                throw new Error(`Unable to enable Windows system proxy: ${error.details || error.message}`);
            }
        });
    }

    restore() {
        return this._queue(async () => {
            if (this.platform !== 'win32') return { supported: false };
            const snapshot = this.snapshot || this._loadSnapshot();
            if (!snapshot) return { supported: true };
            await this._restoreSnapshot(snapshot);
            this._clearSnapshot();
            this.snapshot = null;
            this.active = false;
            return { supported: true };
        });
    }
}

module.exports = SystemProxyManager;
