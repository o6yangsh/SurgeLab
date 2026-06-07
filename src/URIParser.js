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

    /**
     * Cross-environment base64 decode (works in both browser and Node.js/Jest).
     * @param {string} str - Base64 encoded string
     * @returns {string} Decoded string
     */
    static _base64Decode(str) {
        if (typeof Buffer !== 'undefined') {
            return Buffer.from(str, 'base64').toString('utf8');
        }
        return atob(str);
    }

    /**
     * Validate port number is in the valid range 1-65535.
     * @param {number} port - Port number to validate
     * @returns {number} Validated port
     */
    static _validatePort(port) {
        const p = parseInt(port, 10);
        if (isNaN(p) || p < 1 || p > 65535) {
            throw new Error(`Invalid port number: ${port}. Must be 1-65535.`);
        }
        return p;
    }

    /**
     * Extract server and port from a host:port string, supporting IPv6.
     * @param {string} hostPort - e.g. "1.2.3.4:443" or "[::1]:443"
     * @returns {{ server: string, port: number }}
     */
    static _parseHostPort(hostPort) {
        let server, port;
        if (hostPort.startsWith('[')) {
            // IPv6: [::1]:443
            const closeBracket = hostPort.indexOf(']');
            if (closeBracket === -1) throw new Error(`Invalid IPv6 address: ${hostPort}`);
            server = hostPort.slice(1, closeBracket);
            port = hostPort.slice(closeBracket + 2); // skip ']:'
        } else {
            const lastColon = hostPort.lastIndexOf(':');
            server = hostPort.slice(0, lastColon);
            port = hostPort.slice(lastColon + 1);
        }
        return { server, port: this._validatePort(port) };
    }

    static parseVless(uri) {
        // Format: vless://uuid@server:port?security=reality&sni=xxx&pbk=xxx&sid=xxx#name
        try {
            const url = new URL(uri);
            const isReality = url.searchParams.get('security') === 'reality';
            const port = this._validatePort(url.port || '443');
            
            return {
                type: 'vless',
                name: decodeURIComponent(url.hash.slice(1)) || 'VLESS Node',
                server: url.hostname,
                port: port,
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
            const port = this._validatePort(url.port || '443');
            return {
                type: 'hysteria2',
                name: decodeURIComponent(url.hash.slice(1)) || 'Hysteria2 Node',
                server: url.hostname,
                port: port,
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
            const port = this._validatePort(url.port || '443');
            return {
                type: 'trojan',
                name: decodeURIComponent(url.hash.slice(1)) || 'Trojan Node',
                server: url.hostname,
                port: port,
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
                const decoded = this._base64Decode(userinfo);
                const colonIdx = decoded.indexOf(':');
                method = decoded.slice(0, colonIdx);
                password = decoded.slice(colonIdx + 1);
                // Use _parseHostPort for proper IPv6 support
                const hp = this._parseHostPort(hostPort);
                server = hp.server;
                port = hp.port;
            } else {
                // Legacy: entire payload is base64 encoded
                const decoded = this._base64Decode(mainPart);
                // Use a more robust regex that handles passwords with special chars
                // Format: method:password@server:port
                // Strategy: find last '@', then parse server:port from the right
                const lastAt = decoded.lastIndexOf('@');
                if (lastAt !== -1) {
                    const methodPassword = decoded.slice(0, lastAt);
                    const serverPort = decoded.slice(lastAt + 1);
                    const colonIdx = methodPassword.indexOf(':');
                    method = methodPassword.slice(0, colonIdx);
                    password = methodPassword.slice(colonIdx + 1);
                    const hp = this._parseHostPort(serverPort);
                    server = hp.server;
                    port = hp.port;
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
            const json = JSON.parse(this._base64Decode(encoded));
            return {
                type: 'vmess',
                name: json.ps || 'VMess Node',
                server: json.add,
                port: this._validatePort(json.port),
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
