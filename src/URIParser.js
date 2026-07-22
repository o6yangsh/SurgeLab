class URIParser {
    static parse(uri) {
        const value = String(uri || '').trim();
        if (!value) throw new Error('URI cannot be empty');
        if (value.startsWith('vless://')) return this.parseVless(value);
        if (value.startsWith('hy2://') || value.startsWith('hysteria2://')) return this.parseHy2(value);
        if (value.startsWith('trojan://')) return this.parseTrojan(value);
        if (value.startsWith('ss://')) return this.parseSS(value);
        if (value.startsWith('vmess://')) return this.parseVmess(value);
        throw new Error(`Unsupported URI scheme: ${value.split('://')[0]}`);
    }

    static parseMany(text) {
        return String(text || '')
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .map(line => this.parse(line));
    }

    static _decode(value) {
        try { return decodeURIComponent(value || ''); } catch (_) { return value || ''; }
    }

    static _base64Decode(str) {
        const normalized = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
        if (typeof Buffer !== 'undefined') return Buffer.from(padded, 'base64').toString('utf8');
        return decodeURIComponent(Array.from(atob(padded), c => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
    }

    static _validatePort(port) {
        const raw = String(port ?? '');
        if (!/^\d{1,5}$/.test(raw)) throw new Error(`Invalid port number: ${port}. Must be 1-65535.`);
        const parsed = Number(raw);
        if (parsed < 1 || parsed > 65535) throw new Error(`Invalid port number: ${port}. Must be 1-65535.`);
        return parsed;
    }

    static _parseHostPort(hostPort) {
        const value = String(hostPort || '');
        let server;
        let port;
        if (value.startsWith('[')) {
            const close = value.indexOf(']');
            if (close < 0 || value[close + 1] !== ':') throw new Error(`Invalid IPv6 address: ${value}`);
            server = value.slice(1, close);
            port = value.slice(close + 2);
        } else {
            const colon = value.lastIndexOf(':');
            if (colon <= 0) throw new Error(`Missing server or port: ${value}`);
            server = value.slice(0, colon);
            port = value.slice(colon + 1);
        }
        if (!server) throw new Error('Server cannot be empty');
        return { server, port: this._validatePort(port) };
    }

    static _boolean(value) {
        return /^(1|true|yes)$/i.test(String(value || ''));
    }

    static _list(value) {
        return String(value || '').split(',').map(item => item.trim()).filter(Boolean);
    }

    static _buildTls(params, server, defaultEnabled = false) {
        const security = params.get('security') || params.get('tls');
        const realityEnabled = security === 'reality';
        const enabled = defaultEnabled || realityEnabled || /^(tls|1|true)$/i.test(security || '');
        if (!enabled) return undefined;

        const tls = {
            enabled: true,
            server_name: params.get('sni') || server
        };
        const alpn = this._list(params.get('alpn'));
        if (alpn.length) tls.alpn = alpn;
        if (this._boolean(params.get('allowInsecure') || params.get('insecure') || params.get('skip-cert-verify'))) {
            tls.insecure = true;
        }
        const fingerprint = params.get('fp');
        if (fingerprint) tls.utls = { enabled: true, fingerprint };
        if (realityEnabled) {
            if (!tls.utls) tls.utls = { enabled: true, fingerprint: 'chrome' };
            tls.reality = {
                enabled: true,
                public_key: params.get('pbk') || '',
                short_id: params.get('sid') || ''
            };
        }
        return tls;
    }

    static _buildTransport(params) {
        const type = (params.get('type') || params.get('network') || '').toLowerCase();
        if (!type || type === 'tcp' || type === 'none') return undefined;
        if (type === 'ws') {
            const transport = { type: 'ws', path: params.get('path') || '/' };
            const host = params.get('host');
            if (host) transport.headers = { Host: host };
            const earlyData = Number(params.get('ed'));
            if (Number.isFinite(earlyData) && earlyData > 0) transport.max_early_data = earlyData;
            if (params.get('eh')) transport.early_data_header_name = params.get('eh');
            return transport;
        }
        if (type === 'grpc') {
            return { type: 'grpc', service_name: params.get('serviceName') || params.get('service_name') || '' };
        }
        if (type === 'httpupgrade') {
            const transport = { type: 'httpupgrade', path: params.get('path') || '/' };
            if (params.get('host')) transport.host = params.get('host');
            return transport;
        }
        if (type === 'http' || type === 'h2') {
            const transport = { type: 'http', path: params.get('path') || '/' };
            const hosts = this._list(params.get('host'));
            if (hosts.length) transport.host = hosts;
            return transport;
        }
        if (type === 'quic') return { type: 'quic' };
        throw new Error(`Unsupported transport type: ${type}`);
    }

    static parseVless(uri) {
        try {
            const url = new URL(uri);
            if (!url.hostname || !url.username) throw new Error('UUID and server are required');
            const node = {
                type: 'vless',
                name: this._decode(url.hash.slice(1)) || 'VLESS Node',
                server: url.hostname,
                port: this._validatePort(url.port || '443'),
                uuid: this._decode(url.username)
            };
            const flow = url.searchParams.get('flow');
            if (flow) node.flow = flow;
            const packetEncoding = url.searchParams.get('packetEncoding') || url.searchParams.get('packet_encoding');
            if (packetEncoding) node.packet_encoding = packetEncoding;
            const tls = this._buildTls(url.searchParams, url.hostname);
            const transport = this._buildTransport(url.searchParams);
            if (tls) node.tls = tls;
            if (transport) node.transport = transport;
            return node;
        } catch (error) {
            throw new Error(`Failed to parse VLESS URI: ${error.message}`);
        }
    }

    static parseHy2(uri) {
        try {
            const url = new URL(uri.replace(/^hysteria2:\/\//, 'hy2://'));
            if (!url.hostname || !url.username) throw new Error('Password and server are required');
            const node = {
                type: 'hysteria2',
                name: this._decode(url.hash.slice(1)) || 'Hysteria2 Node',
                server: url.hostname,
                port: this._validatePort(url.port || '443'),
                password: this._decode(url.password || url.username),
                tls: this._buildTls(url.searchParams, url.hostname, true)
            };
            const up = Number(url.searchParams.get('upmbps') || url.searchParams.get('up'));
            const down = Number(url.searchParams.get('downmbps') || url.searchParams.get('down'));
            if (Number.isFinite(up) && up > 0) node.up_mbps = up;
            if (Number.isFinite(down) && down > 0) node.down_mbps = down;
            const obfsType = url.searchParams.get('obfs');
            const obfsPassword = url.searchParams.get('obfs-password') || url.searchParams.get('obfs_password');
            if (obfsType && obfsPassword) node.obfs = { type: obfsType, password: obfsPassword };
            const ports = url.searchParams.get('mport');
            if (ports) node.server_ports = ports.split(',').map(value => value.trim()).filter(Boolean);
            const hopInterval = url.searchParams.get('hop-interval');
            if (hopInterval) node.hop_interval = hopInterval;
            return node;
        } catch (error) {
            throw new Error(`Failed to parse Hysteria2 URI: ${error.message}`);
        }
    }

    static parseTrojan(uri) {
        try {
            const url = new URL(uri);
            if (!url.hostname || !url.username) throw new Error('Password and server are required');
            const node = {
                type: 'trojan',
                name: this._decode(url.hash.slice(1)) || 'Trojan Node',
                server: url.hostname,
                port: this._validatePort(url.port || '443'),
                password: this._decode(url.username),
                tls: this._buildTls(url.searchParams, url.hostname, true)
            };
            const transport = this._buildTransport(url.searchParams);
            if (transport) node.transport = transport;
            return node;
        } catch (error) {
            throw new Error(`Failed to parse Trojan URI: ${error.message}`);
        }
    }

    static _parsePlugin(value) {
        if (!value) return {};
        const parts = value.split(';').filter(Boolean);
        return { plugin: parts.shift(), plugin_opts: parts.join(';') };
    }

    static parseSS(uri) {
        try {
            const body = uri.slice(5);
            const hashIndex = body.indexOf('#');
            const beforeHash = hashIndex >= 0 ? body.slice(0, hashIndex) : body;
            const fragment = hashIndex >= 0 ? body.slice(hashIndex + 1) : '';
            const queryIndex = beforeHash.indexOf('?');
            const main = queryIndex >= 0 ? beforeHash.slice(0, queryIndex) : beforeHash;
            const params = new URLSearchParams(queryIndex >= 0 ? beforeHash.slice(queryIndex + 1) : '');
            let methodPassword;
            let hostPort;
            const at = main.lastIndexOf('@');
            if (at >= 0) {
                const userInfo = main.slice(0, at);
                hostPort = main.slice(at + 1);
                const decodedUserInfo = this._decode(userInfo);
                methodPassword = decodedUserInfo.includes(':') ? decodedUserInfo : this._base64Decode(userInfo);
            } else {
                const decoded = this._base64Decode(main);
                const decodedAt = decoded.lastIndexOf('@');
                if (decodedAt < 0) throw new Error('Missing server');
                methodPassword = decoded.slice(0, decodedAt);
                hostPort = decoded.slice(decodedAt + 1);
            }
            const colon = methodPassword.indexOf(':');
            if (colon <= 0) throw new Error('Missing encryption method or password');
            const hp = this._parseHostPort(hostPort);
            return {
                type: 'shadowsocks',
                name: this._decode(fragment) || 'Shadowsocks Node',
                server: hp.server,
                port: hp.port,
                method: methodPassword.slice(0, colon),
                password: this._decode(methodPassword.slice(colon + 1)),
                ...this._parsePlugin(params.get('plugin'))
            };
        } catch (error) {
            throw new Error(`Failed to parse SS URI: ${error.message}`);
        }
    }

    static parseVmess(uri) {
        try {
            const json = JSON.parse(this._base64Decode(uri.slice(8)));
            if (!json.add || !json.id) throw new Error('UUID and server are required');
            const node = {
                type: 'vmess',
                name: json.ps || 'VMess Node',
                server: json.add,
                port: this._validatePort(json.port),
                uuid: json.id,
                alterId: Number(json.aid || 0),
                security: json.scy || 'auto'
            };
            const params = new URLSearchParams();
            const mappings = {
                type: json.net, host: json.host, path: json.path, serviceName: json.serviceName,
                security: json.tls, sni: json.sni, alpn: json.alpn, fp: json.fp,
                allowInsecure: json.allowInsecure
            };
            Object.entries(mappings).forEach(([key, value]) => {
                if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
            });
            const tls = this._buildTls(params, json.add);
            const transport = this._buildTransport(params);
            if (tls) node.tls = tls;
            if (transport) node.transport = transport;
            if (json.packetEncoding) node.packet_encoding = json.packetEncoding;
            return node;
        } catch (error) {
            throw new Error(`Failed to parse VMess URI: ${error.message}`);
        }
    }
}

if (typeof module !== 'undefined') module.exports = URIParser;
