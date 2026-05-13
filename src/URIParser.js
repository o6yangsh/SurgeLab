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
        if (uri.startsWith('vmess://')) return this.parseVmess(uri);
        throw new Error(`Unsupported URI scheme: ${uri.split('://')[0]}`);
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
        // Shadowsocks SIP002 format: ss://base64(method:password)@server:port#name
        try {
            // Extract the part after ss:// and before the hash
            const withoutScheme = uri.slice(5); // remove 'ss://'
            const hashIndex = withoutScheme.lastIndexOf('#');
            const name = hashIndex !== -1 ? decodeURIComponent(withoutScheme.slice(hashIndex + 1)) : 'Shadowsocks Node';
            const mainPart = hashIndex !== -1 ? withoutScheme.slice(0, hashIndex) : withoutScheme;

            let method = '', password = '', server = '', port = 8388;
            const atIndex = mainPart.lastIndexOf('@');

            if (atIndex !== -1) {
                // SIP002: base64(method:password)@server:port
                const userinfo = mainPart.slice(0, atIndex);
                const hostPort = mainPart.slice(atIndex + 1);
                const decoded = atob(userinfo);
                const colonIdx = decoded.indexOf(':');
                method = decoded.slice(0, colonIdx);
                password = decoded.slice(colonIdx + 1);
                const lastColon = hostPort.lastIndexOf(':');
                server = hostPort.slice(0, lastColon);
                port = parseInt(hostPort.slice(lastColon + 1), 10);
            } else {
                // Legacy: entire payload is base64 encoded
                const decoded = atob(mainPart);
                const match = decoded.match(/^(.+?):(.+)@(.+):(\d+)$/);
                if (match) {
                    method = match[1];
                    password = match[2];
                    server = match[3];
                    port = parseInt(match[4], 10);
                }
            }
            
            return {
                type: 'shadowsocks',
                name: name,
                server: server,
                port: port || 8388,
                method: method || 'aes-256-gcm',
                password: password
            };
        } catch (e) {
            throw new Error(`Failed to parse SS URI: ${e.message}`);
        }
    }

    static parseVmess(uri) {
        // vmess:// uses base64 encoded JSON
        try {
            const encoded = uri.slice(8); // remove 'vmess://'
            const json = JSON.parse(atob(encoded));
            return {
                type: 'vmess',
                name: json.ps || 'VMess Node',
                server: json.add,
                port: parseInt(json.port, 10),
                uuid: json.id,
                alterId: parseInt(json.aid || '0', 10),
                security: json.scy || 'auto',
                tls: {
                    enabled: json.tls === 'tls',
                    server_name: json.sni || json.host || json.add
                }
            };
        } catch (e) {
            throw new Error(`Failed to parse VMess URI: ${e.message}`);
        }
    }
}

if (typeof module !== 'undefined') {
    module.exports = URIParser;
}
