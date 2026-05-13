const URIParser = require('../src/URIParser');

describe('URIParser', () => {
    test('parses a VLESS REALITY URI', () => {
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

    test('parses a Hysteria2 URI', () => {
        const uri = 'hy2://my-password@server.hy2.com:8443?sni=server.hy2.com#HY2%20Node';
        const parsed = URIParser.parse(uri);

        expect(parsed.type).toBe('hysteria2');
        expect(parsed.password).toBe('my-password');
        expect(parsed.server).toBe('server.hy2.com');
        expect(parsed.port).toBe(8443);
    });

    test('throws error on empty URI', () => {
        expect(() => URIParser.parse('')).toThrow('URI cannot be empty');
    });
});
