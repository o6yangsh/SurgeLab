const URIParser = require('../src/URIParser');

describe('URIParser', () => {
    test('parses a VLESS + REALITY URI correctly', () => {
        const uri = 'vless://b831381d-2253-4d56-8255-a0c5bdc6f2a7@example.com:443?security=reality&sni=example.com&pbk=public_key&sid=short_id#My%20Vless';
        const parsed = URIParser.parse(uri);
        
        expect(parsed.type).toBe('vless');
        expect(parsed.name).toBe('My Vless');
        expect(parsed.server).toBe('example.com');
        expect(parsed.port).toBe(443);
        expect(parsed.uuid).toBe('b831381d-2253-4d56-8255-a0c5bdc6f2a7');
        expect(parsed.tls.enabled).toBe(true);
        expect(parsed.tls.reality.enabled).toBe(true);
        expect(parsed.tls.reality.public_key).toBe('public_key');
    });

    test('parses a Hysteria2 URI correctly', () => {
        const uri = 'hy2://my-password@server.hy2.com:8443?sni=server.hy2.com#HY2%20Node';
        const parsed = URIParser.parse(uri);

        expect(parsed.type).toBe('hysteria2');
        expect(parsed.password).toBe('my-password');
        expect(parsed.server).toBe('server.hy2.com');
        expect(parsed.port).toBe(8443);
        expect(parsed.name).toBe('HY2 Node');
    });

    test('parses hysteria2:// prefix as alias for hy2://', () => {
        const parsed = URIParser.parse('hysteria2://pass@server.com:443#Test');
        expect(parsed.type).toBe('hysteria2');
        expect(parsed.password).toBe('pass');
    });

    test('parses a Trojan URI correctly', () => {
        const parsed = URIParser.parse('trojan://mypassword@jp.example.com:443?sni=jp.example.com#JP-Tokyo');
        expect(parsed.type).toBe('trojan');
        expect(parsed.password).toBe('mypassword');
        expect(parsed.server).toBe('jp.example.com');
        expect(parsed.port).toBe(443);
        expect(parsed.tls.enabled).toBe(true);
    });

    test('parses a Shadowsocks SIP002 URI correctly', () => {
        // aes-256-gcm:testpass => base64 = YWVzLTI1Ni1nY206dGVzdHBhc3M=
        const parsed = URIParser.parse('ss://YWVzLTI1Ni1nY206dGVzdHBhc3M=@ss.example.com:8388#SS-Node');
        expect(parsed.type).toBe('shadowsocks');
        expect(parsed.method).toBe('aes-256-gcm');
        expect(parsed.password).toBe('testpass');
        expect(parsed.server).toBe('ss.example.com');
        expect(parsed.port).toBe(8388);
        expect(parsed.name).toBe('SS-Node');
    });

    test('parses a VMess base64 JSON URI correctly', () => {
        const vmessObj = { v: "2", ps: "US-VMess", add: "vmess.example.com", port: "443", id: "some-uuid", aid: "0", scy: "auto", tls: "tls", sni: "vmess.example.com" };
        const uri = 'vmess://' + Buffer.from(JSON.stringify(vmessObj)).toString('base64');
        const parsed = URIParser.parse(uri);

        expect(parsed.type).toBe('vmess');
        expect(parsed.name).toBe('US-VMess');
        expect(parsed.server).toBe('vmess.example.com');
        expect(parsed.port).toBe(443);
        expect(parsed.uuid).toBe('some-uuid');
        expect(parsed.tls.enabled).toBe(true);
    });

    test('throws error on empty URI', () => {
        expect(() => URIParser.parse('')).toThrow('URI cannot be empty');
    });

    test('throws error on unsupported URI scheme', () => {
        expect(() => URIParser.parse('ftp://example.com')).toThrow('Unsupported URI scheme');
    });
});
