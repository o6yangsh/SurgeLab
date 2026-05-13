class URIParser {
    /**
     * Parses a standard proxy URI into a structured object.
     * @param {string} uri - The proxy URI (e.g. vless://, hy2://, ss://)
     * @returns {Object} Structured node object
     */
    static parse(uri) {
        if (!uri) throw new Error('URI cannot be empty');
        if (uri.startsWith('vless://')) return this.parseVless(uri);
        if (uri.startsWith('hy2://') || uri.startsWith('hysteria2://')) return this.parseHy2(uri);
        if (uri.startsWith('trojan://')) return this.parseTrojan(uri);
        if (uri.startsWith('ss://')) return this.parseSS(uri);
        // Fallback for demo purposes
        return this.parseGeneric(uri);
    }

    static parseVless(uri) {
        // Format: vless://uuid@server:port?security=reality&sni=xxx&pbk=xxx&sid=xxx#name
        try {
            const url = new URL(uri);
            const isReality = url.searchParams.get('security') === 'reality';
            
            return {
                type: 'vless',
                name: decodeURIComponent(url.hash.slice(1)) || 'VLESS Node',
                server: url.hostname,
                port: parseInt(url.port || '443', 10),
                uuid: url.username,
                tls: {
                    enabled: url.searchParams.get('security') === 'tls' || isReality,
                    server_name: url.searchParams.get('sni') || url.hostname,
                    reality: isReality ? {
                        enabled: true,
                        public_key: url.searchParams.get('pbk'),
                        short_id: url.searchParams.get('sid')
                    } : undefined
                }
            };
        } catch (e) {
            throw new Error(`Failed to parse VLESS URI: ${e.message}`);
        }
    }

    static parseHy2(uri) {
        // Format: hy2://password@server:port?sni=xxx#name
        try {
            // hysteria2:// is also valid, ensure we parse cleanly
            const normalized = uri.replace(/^hysteria2:\/\//, 'hy2://');
            const url = new URL(normalized);
            return {
                type: 'hysteria2',
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria2 Node',
                server: url.hostname,
                port: parseInt(url.port || '443', 10),
                password: url.username,
                sni: url.searchParams.get('sni') || url.hostname
            };
        } catch (e) {
            throw new Error(`Failed to parse Hysteria2 URI: ${e.message}`);
        }
    }

    static parseTrojan(uri) {
        // Format: trojan://password@server:port?sni=xxx#name
        try {
            const url = new URL(uri);
            return {
                type: 'trojan',
                name: decodeURIComponent(url.hash.slice(1)) || 'Trojan Node',
                server: url.hostname,
                port: parseInt(url.port || '443', 10),
                password: url.username,
                tls: {
                    enabled: true,
                    server_name: url.searchParams.get('sni') || url.hostname
                }
            };
        } catch (e) {
            throw new Error(`Failed to parse Trojan URI: ${e.message}`);
        }
    }

    static parseSS(uri) {
        // Shadowsocks is often base64 encoded.
        // Format: ss://base64(method:password)@server:port#name
        // or ss://base64(method:password@server:port)#name
        try {
            const url = new URL(uri);
            let method = '', password = '';
            let server = url.hostname;
            let port = url.port;

            if (url.username) {
                // Try decoding the userinfo part if it doesn't contain a colon natively
                const decoded = Buffer.from(url.username, 'base64').toString('utf8');
                if (decoded.includes(':')) {
                    [method, password] = decoded.split(':');
                } else {
                    // Fallback if not base64 encoded
                    method = url.username;
                    password = url.password;
                }
            }
            
            return {
                type: 'shadowsocks',
                name: decodeURIComponent(url.hash.slice(1)) || 'Shadowsocks Node',
                server: server,
                port: parseInt(port || '8388', 10),
                method: method || 'aes-256-gcm',
                password: password
            };
        } catch (e) {
            throw new Error(`Failed to parse SS URI: ${e.message}`);
        }
    }

    static parseGeneric(uri) {
        const url = new URL(uri);
        return {
            type: url.protocol.replace(':', ''),
            name: decodeURIComponent(url.hash.slice(1)) || 'Generic Node',
            server: url.hostname,
            port: parseInt(url.port || '443', 10)
        };
    }
}

if (typeof module !== 'undefined') {
    module.exports = URIParser;
}
