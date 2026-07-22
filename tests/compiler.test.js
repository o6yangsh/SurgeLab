const ProfileCompiler = require('../src/ProfileCompiler');

describe('ProfileCompiler for sing-box 1.13', () => {
    const nodes = [
        { type: 'vless', name: 'US Node', server: 'us.example.com', port: 443, uuid: 'uuid-1', tls: { enabled: true } },
        { type: 'trojan', name: 'JP Node', server: 'jp.example.com', port: 443, password: 'secret', tls: { enabled: true }, transport: { type: 'grpc', service_name: 'tunnel' } }
    ];
    const rules = [
        { type: 'domain_suffix', value: 'google.com', outbound: 'proxy' },
        { type: 'ip_cidr', value: ['10.0.0.0/8'], outbound: 'direct' },
        { type: 'domain_keyword', value: 'ads', outbound: 'reject' },
        { type: 'rule_set', value: 'geosite-cn', outbound: 'direct' },
        { type: 'rule_set', value: 'geoip-cn', outbound: 'direct' }
    ];
    const dns = { local: '114.114.114.114', remote: 'https://doh.example.com/dns-query', fakeIpEnabled: true };

    test('uses modern TUN fields and route sniff action', () => {
        const config = ProfileCompiler.compile(nodes, rules, dns, 'tun');
        expect(config.inbounds[0]).toMatchObject({
            type: 'tun', address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], strict_route: true, auto_route: true
        });
        expect(config.inbounds[0]).not.toHaveProperty('inet4_address');
        expect(config.inbounds[0]).not.toHaveProperty('sniff');
        expect(config.route.rules[0]).toEqual({ action: 'sniff' });
        expect(config.route.rules[1]).toEqual({ protocol: 'dns', action: 'hijack-dns' });
        expect(config.route.default_domain_resolver).toEqual({ server: 'local', strategy: 'ipv4_only' });
    });

    test('keeps system proxy bound to loopback', () => {
        const inbound = ProfileCompiler.compile(nodes, rules, dns, 'system').inbounds[0];
        expect(inbound).toMatchObject({ type: 'mixed', listen: '127.0.0.1', listen_port: 2080 });
    });

    test('uses typed DNS servers and modern FakeIP server', () => {
        const compiled = ProfileCompiler.compile(nodes, rules, dns, 'tun').dns;
        expect(compiled.servers[0]).toMatchObject({
            type: 'https', server: 'doh.example.com', server_port: 443, path: '/dns-query',
            domain_resolver: 'local', detour: 'proxy', tls: { enabled: true, server_name: 'doh.example.com' }
        });
        expect(compiled.servers[1]).toMatchObject({ type: 'udp', server: '114.114.114.114', detour: 'direct' });
        expect(compiled.servers[2]).toMatchObject({ type: 'fakeip', inet4_range: '198.18.0.0/15' });
        expect(compiled.rules).toContainEqual({ query_type: ['A', 'AAAA'], action: 'route', server: 'fakeip' });
        expect(compiled.final).toBe('remote');
    });

    test('omits FakeIP when the UI setting is disabled', () => {
        const compiled = ProfileCompiler.compile(nodes, rules, { ...dns, fakeIpEnabled: false }, 'tun').dns;
        expect(compiled.servers.some(server => server.type === 'fakeip')).toBe(false);
        expect(compiled.rules.some(rule => rule.server === 'fakeip')).toBe(false);
        expect(compiled.reverse_mapping).toBe(false);
    });

    test('creates URLTest and selector groups with unique stable tags', () => {
        const outbounds = ProfileCompiler.compile(nodes, rules, dns, 'tun').outbounds;
        expect(outbounds.map(item => item.tag)).toEqual(['US-Node', 'JP-Node', 'auto', 'proxy', 'direct']);
        expect(outbounds.find(item => item.tag === 'auto')).toMatchObject({ type: 'urltest', outbounds: ['US-Node', 'JP-Node'] });
        expect(outbounds.find(item => item.tag === 'proxy')).toMatchObject({ type: 'selector', default: 'auto' });
        expect(outbounds.some(item => ['block', 'dns'].includes(item.type))).toBe(false);
    });

    test('preserves protocol transport and TLS settings', () => {
        const out = ProfileCompiler.compile(nodes, rules, dns, 'tun').outbounds.find(item => item.tag === 'JP-Node');
        expect(out).toMatchObject({
            type: 'trojan', password: 'secret', tls: { enabled: true },
            transport: { type: 'grpc', service_name: 'tunnel' }
        });
    });

    test('compiles route/reject actions and remote rule sets', () => {
        const route = ProfileCompiler.compile(nodes, rules, dns, 'tun').route;
        expect(route.rules).toContainEqual({ domain_suffix: ['google.com'], action: 'route', outbound: 'proxy' });
        expect(route.rules).toContainEqual({ domain_keyword: ['ads'], action: 'reject' });
        expect(route.rule_set).toEqual(expect.arrayContaining([
            expect.objectContaining({ tag: 'geosite-cn', type: 'remote', format: 'binary' }),
            expect.objectContaining({ tag: 'geoip-cn', type: 'remote', format: 'binary' })
        ]));
        expect(route.final).toBe('proxy');
    });

    test('falls back safely to direct when no node exists', () => {
        const config = ProfileCompiler.compile([], [{ type: 'domain', value: 'example.com', outbound: 'proxy' }], {}, 'system');
        expect(config.outbounds).toEqual([{ type: 'direct', tag: 'direct' }]);
        expect(config.route.final).toBe('direct');
        expect(config.route.rules[2].outbound).toBe('direct');
        expect(config.dns.servers[0].detour).toBe('direct');
    });

    test('rejects unknown remote rule sets', () => {
        expect(() => ProfileCompiler.compile(nodes, [{ type: 'rule_set', value: 'unknown', outbound: 'direct' }], dns, 'tun'))
            .toThrow('Unknown remote rule set');
    });
});

describe('Secret redaction', () => {
    test('masks credentials and REALITY keys without mutating input', () => {
        const nodes = [{
            type: 'vless', uuid: 'uuid', password: 'password',
            tls: { reality: { public_key: 'pk', short_id: 'sid' } },
            obfs: { password: 'obfs' }
        }];
        const redacted = ProfileCompiler.redactProfile(nodes);
        expect(redacted[0]).toMatchObject({
            uuid: 'MASKED_UUID', password: 'MASKED_PASSWORD', obfs: { password: 'MASKED_PASSWORD' },
            tls: { reality: { public_key: 'MASKED_PUBLIC_KEY', short_id: 'MASKED_SHORT_ID' } }
        });
        expect(nodes[0].uuid).toBe('uuid');
    });
});
