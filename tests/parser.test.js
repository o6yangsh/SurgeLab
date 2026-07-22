const URIParser = require('../src/URIParser');

describe('URIParser', () => {
    test('parses VLESS Reality, flow, uTLS and ALPN', () => {
        const parsed = URIParser.parse('vless://b831381d-2253-4d56-8255-a0c5bdc6f2a7@example.com:443?security=reality&sni=edge.example.com&pbk=public_key&sid=short_id&flow=xtls-rprx-vision&fp=chrome&alpn=h2%2Chttp%2F1.1#My%20Vless');
        expect(parsed).toMatchObject({
            type: 'vless', name: 'My Vless', server: 'example.com', port: 443,
            uuid: 'b831381d-2253-4d56-8255-a0c5bdc6f2a7', flow: 'xtls-rprx-vision',
            tls: {
                enabled: true, server_name: 'edge.example.com', alpn: ['h2', 'http/1.1'],
                utls: { enabled: true, fingerprint: 'chrome' },
                reality: { enabled: true, public_key: 'public_key', short_id: 'short_id' }
            }
        });
    });

    test('parses VLESS WebSocket transport options', () => {
        const parsed = URIParser.parse('vless://uuid@ws.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fsocket&ed=2048&eh=Sec-WebSocket-Protocol#WS');
        expect(parsed.transport).toEqual({
            type: 'ws', path: '/socket', headers: { Host: 'cdn.example.com' },
            max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol'
        });
    });

    test('parses Hysteria2 bandwidth, obfuscation and TLS options', () => {
        const parsed = URIParser.parse('hy2://my-password@server.hy2.com:8443?sni=edge.example.com&insecure=1&upmbps=20&downmbps=80&obfs=salamander&obfs-password=secret#HY2');
        expect(parsed).toMatchObject({
            type: 'hysteria2', password: 'my-password', server: 'server.hy2.com', port: 8443,
            up_mbps: 20, down_mbps: 80,
            obfs: { type: 'salamander', password: 'secret' },
            tls: { enabled: true, server_name: 'edge.example.com', insecure: true }
        });
    });

    test('accepts hysteria2:// alias', () => {
        expect(URIParser.parse('hysteria2://pass@server.com:443#Test').password).toBe('pass');
    });

    test('parses Trojan gRPC transport', () => {
        const parsed = URIParser.parse('trojan://mypassword@jp.example.com:443?sni=jp.example.com&type=grpc&serviceName=tunnel#JP');
        expect(parsed.transport).toEqual({ type: 'grpc', service_name: 'tunnel' });
        expect(parsed.tls.enabled).toBe(true);
    });

    test('parses Shadowsocks SIP002 base64url and plugin', () => {
        const userInfo = Buffer.from('aes-256-gcm:testpass').toString('base64url');
        const parsed = URIParser.parse(`ss://${userInfo}@ss.example.com:8388?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com#SS-Node`);
        expect(parsed).toMatchObject({
            type: 'shadowsocks', method: 'aes-256-gcm', password: 'testpass',
            server: 'ss.example.com', port: 8388, name: 'SS-Node',
            plugin: 'v2ray-plugin', plugin_opts: 'tls;host=cdn.example.com'
        });
    });

    test('parses percent-encoded plain Shadowsocks user info and IPv6', () => {
        const parsed = URIParser.parse('ss://2022-blake3-aes-128-gcm%3Apassword@[2001:db8::1]:8388#IPv6');
        expect(parsed.server).toBe('2001:db8::1');
        expect(parsed.method).toBe('2022-blake3-aes-128-gcm');
        expect(parsed.password).toBe('password');
    });

    test('parses VMess TLS and WebSocket transport', () => {
        const vmess = {
            v: '2', ps: 'US-VMess', add: 'vmess.example.com', port: '443', id: 'some-uuid',
            aid: '0', scy: 'auto', tls: 'tls', sni: 'edge.example.com', net: 'ws',
            host: 'cdn.example.com', path: '/vmess', fp: 'chrome'
        };
        const parsed = URIParser.parse(`vmess://${Buffer.from(JSON.stringify(vmess)).toString('base64url')}`);
        expect(parsed.transport).toEqual({ type: 'ws', path: '/vmess', headers: { Host: 'cdn.example.com' } });
        expect(parsed.tls.server_name).toBe('edge.example.com');
        expect(parsed.tls.utls.fingerprint).toBe('chrome');
    });

    test('parses multiple non-comment URI lines', () => {
        const parsed = URIParser.parseMany('# subscription\ntrojan://a@one.example:443\n\nhy2://b@two.example:443');
        expect(parsed).toHaveLength(2);
    });

    test.each(['0', '65536', '44x'])('rejects invalid port %s', port => {
        expect(() => URIParser.parse(`trojan://pass@example.com:${port}`)).toThrow();
    });

    test('throws on empty and unsupported URI', () => {
        expect(() => URIParser.parse('')).toThrow('URI cannot be empty');
        expect(() => URIParser.parse('ftp://example.com')).toThrow('Unsupported URI scheme');
    });
});
