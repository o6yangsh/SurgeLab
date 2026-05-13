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

    test('compiles TUN mode config properly', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'tun');
        
        // Assert inbounds
        expect(config.inbounds[0].type).toBe('tun');
        expect(config.inbounds[0].interface_name).toBe('tun0');
        
        // Assert DNS
        expect(config.dns.servers[0].address).toBe('https://doh.example.com');
        
        // Assert Routes
        expect(config.route.rules.length).toBe(2);
        expect(config.route.rules[0].domain_suffix).toContain('google.com');
        expect(config.route.rules[0].outbound).toBe('Proxy1');
    });

    test('compiles System proxy mode config properly', () => {
        const config = ProfileCompiler.compile(mockNodes, mockRules, mockDns, 'system');
        expect(config.inbounds[0].type).toBe('mixed');
        expect(config.inbounds[0].listen).toBe('127.0.0.1');
    });

    test('redacts profile secrets correctly', () => {
        const redacted = ProfileCompiler.redactProfile(mockNodes);
        expect(redacted[0].uuid).toBe('MASKED_UUID');
        // Original should remain intact
        expect(mockNodes[0].uuid).toBe('some-uuid');
    });
});
