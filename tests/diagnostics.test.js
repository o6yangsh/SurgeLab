const net = require('net');
const Diagnostics = require('../src/Diagnostics');

describe('Diagnostics', () => {
    let server;
    let port;

    beforeAll(done => {
        server = net.createServer(socket => socket.end());
        server.listen(0, '127.0.0.1', () => {
            port = server.address().port;
            done();
        });
    });

    afterAll(done => { server.close(done); });

    test('measures TCP connection latency to a node', async () => {
        const result = await Diagnostics.testLatency({ server: '127.0.0.1', port });
        expect(result.success).toBe(true);
        expect(result.latency).toBeGreaterThanOrEqual(0);
    });

    test('rejects malformed node targets without opening a socket', async () => {
        await expect(Diagnostics.testLatency({ server: 'bad host', port: 70000 }))
            .resolves.toMatchObject({ success: false, error: 'Invalid node host.' });
    });

    test('validates DNS test inputs', async () => {
        await expect(Diagnostics.testDns('bad domain!', '223.5.5.5')).rejects.toThrow('Invalid DNS test domain');
        await expect(Diagnostics.testDns('example.com', 'dns.example.com')).rejects.toThrow('must be an IP address');
    });
});
