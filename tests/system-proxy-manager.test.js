const fs = require('fs');
const os = require('os');
const path = require('path');
const SystemProxyManager = require('../src/SystemProxyManager');

describe('SystemProxyManager', () => {
    let directory;
    let snapshotPath;
    let registry;
    let execFile;

    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), 'surgelab-proxy-'));
        snapshotPath = path.join(directory, 'proxy-backup.json');
        registry = {
            ProxyEnable: { type: 'REG_DWORD', value: '0x0' },
            ProxyServer: { type: 'REG_SZ', value: 'old.proxy:8080' }
        };
        execFile = jest.fn((command, args, options, callback) => {
            if (command === 'powershell.exe') return callback(null, '', '');
            const action = args[0];
            if (action === 'QUERY') {
                const lines = Object.entries(registry).map(([name, item]) => `    ${name}    ${item.type}    ${item.value}`);
                return callback(null, lines.join('\r\n'), '');
            }
            const name = args[args.indexOf('/v') + 1];
            if (action === 'ADD') {
                registry[name] = { type: args[args.indexOf('/t') + 1], value: args[args.indexOf('/d') + 1] };
                return callback(null, '', '');
            }
            if (action === 'DELETE') {
                delete registry[name];
                return callback(null, '', '');
            }
            callback(new Error('Unexpected command'));
        });
    });

    afterEach(() => fs.rmSync(directory, { recursive: true, force: true }));

    test('enables Windows proxy and restores the exact previous values', async () => {
        const manager = new SystemProxyManager({ execFile, snapshotPath, platform: 'win32' });
        await manager.enable('127.0.0.1', 2080);
        expect(registry.ProxyEnable.value).toBe('1');
        expect(registry.ProxyServer.value).toBe('127.0.0.1:2080');
        expect(registry.ProxyOverride.value).toBe('<local>');
        expect(fs.existsSync(snapshotPath)).toBe(true);

        await manager.restore();
        expect(registry.ProxyEnable.value).toBe('0x0');
        expect(registry.ProxyServer.value).toBe('old.proxy:8080');
        expect(registry.ProxyOverride).toBeUndefined();
        expect(fs.existsSync(snapshotPath)).toBe(false);
    });

    test('recovers a backup left by an interrupted session', async () => {
        const first = new SystemProxyManager({ execFile, snapshotPath, platform: 'win32' });
        await first.enable();
        const restarted = new SystemProxyManager({ execFile, snapshotPath, platform: 'win32' });
        const result = await restarted.recoverStaleSettings();
        expect(result.recovered).toBe(true);
        expect(registry.ProxyEnable.value).toBe('0x0');
        expect(fs.existsSync(snapshotPath)).toBe(false);
    });

    test('is a no-op on non-Windows platforms', async () => {
        const manager = new SystemProxyManager({ execFile, snapshotPath, platform: 'linux' });
        expect(await manager.enable()).toEqual({ supported: false });
        expect(execFile).not.toHaveBeenCalled();
    });
});
