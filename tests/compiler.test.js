const ProfileCompiler = require('../src/ProfileCompiler');

describe('ProfileCompiler', () => {
    const mockNodes = [
        {
            type: 'vless',
            name: 'Proxy1',
            server: 'us.example.com',
            port: 443,
            uuid: 'some-uuid',
            tls: { enabled: true }
        }
    ];

    const mockRules = [
        { domain_suffix: ['google.com'], outbound: 'Proxy1' },
        { geosite: 'cn', outbound: 'direct' }
    ];

    const mockDns = { local: '114.114.114.114', remote: 'https://doh.example.com' };

    test('compiles TUN mode config with correct inbound', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'tun');
        expect(config.inbounds[0].type).toBe('tun');
        expect(config.inbounds[0].interface_name).toBe('tun0');
        expect(config.inbounds[0].strict_route).toBe(true);
    });

    test('compiles System Proxy mode with 127.0.0.1 binding', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'system');
        expect(config.inbounds[0].type).toBe('mixed');
        expect(config.inbounds[0].listen).toBe('127.0.0.1');
    });

    test('uses custom DNS settings', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'tun');
        expect(config.dns.servers[0].address).toBe('https://doh.example.com');
        expect(config.dns.servers[1].address).toBe('114.114.114.114');
    });

    test('includes default outbounds (direct, block, dns-out)', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'tun');
        const tags = config.outbounds.map(o => o.tag);
        expect(tags).toContain('direct');
        expect(tags).toContain('block');
        expect(tags).toContain('dns-out');
    });

    test('compiles routing rules correctly', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'tun');
        expect(config.route.rules).toHaveLength(2);
        expect(config.route.rules[0].domain_suffix).toContain('google.com');
        expect(config.route.rules[0].outbound).toBe('Proxy1');
    });

    test('compiles VMess outbound with alter_id and security', () => {
        const vmessNodes = [{
            type: 'vmess', name: 'VMess1', server: 'vmess.com', port: 443,
            uuid: 'vm-uuid', alterId: 0, security: 'auto',
            tls: { enabled: true, server_name: 'vmess.com' }
        }];
        const config = ProfileCompiler.compile(vmessNodes, [], mockDns, 'tun');
        const vmOut = config.outbounds.find(o => o.tag === 'VMess1');
        expect(vmOut.uuid).toBe('vm-uuid');
        expect(vmOut.alter_id).toBe(0);
        expect(vmOut.security).toBe('auto');
    });
});

describe('Secret Redaction', () => {
    test('masks UUID and password in redacted export', () => {
        const nodes = [{ type: 'vless', uuid: 'real-uuid', password: 'real-pass' }];
        const redacted = ProfileCompiler.redactProfile(nodes);
        expect(redacted[0].uuid).toBe('MASKED_UUID');
        expect(redacted[0].password).toBe('MASKED_PASSWORD');
    });

    test('does NOT mutate original profiles (deep clone)', () => {
        const nodes = [{ type: 'vless', uuid: 'real-uuid', tls: { reality: { public_key: 'pk', short_id: 'sid' } } }];
        ProfileCompiler.redactProfile(nodes);
        // Original should be untouched
        expect(nodes[0].uuid).toBe('real-uuid');
        expect(nodes[0].tls.reality.public_key).toBe('pk');
    });

    test('masks REALITY public_key and short_id', () => {
        const nodes = [{ type: 'vless', tls: { reality: { public_key: 'pk', short_id: 'sid' } } }];
        const redacted = ProfileCompiler.redactProfile(nodes);
        expect(redacted[0].tls.reality.public_key).toBe('MASKED_PUBLIC_KEY');
        expect(redacted[0].tls.reality.short_id).toBe('MASKED_SHORT_ID');
    });
});

describe('Security Constraints', () => {
    test('System Proxy mode never binds to 0.0.0.0', () => {
        const config = ProfileCompiler.compile([], [], {}, 'system');
        expect(config.inbounds[0].listen).toBe('127.0.0.1');
        expect(config.inbounds[0].listen).not.toBe('0.0.0.0');
    });

    test('TUN mode enables strict_route to prevent LAN leaks', () => {
        const config = ProfileCompiler.compile([], [], {}, 'tun');
        expect(config.inbounds[0].strict_route).toBe(true);
    });
});
