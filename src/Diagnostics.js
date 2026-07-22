const net = require('net');
const dns = require('dns');
const { domainToASCII } = require('url');

class Diagnostics {
    static validateNode(node) {
        const host = String(node && node.server || '').trim();
        const port = Number(node && node.port);
        if (!host || /[\s\0]/.test(host)) throw new Error('Invalid node host.');
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid node port.');
        return { host, port };
    }

    static testLatency(node, timeout = 5000) {
        return new Promise(resolve => {
            let target;
            try {
                target = this.validateNode(node);
            } catch (error) {
                resolve({ success: false, error: error.message });
                return;
            }
            const started = process.hrtime.bigint();
            const socket = net.createConnection(target);
            let settled = false;
            const finish = result => {
                if (settled) return;
                settled = true;
                socket.destroy();
                resolve(result);
            };
            socket.setTimeout(timeout);
            socket.once('connect', () => {
                const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
                finish({ success: true, latency: Math.round(elapsed) });
            });
            socket.once('timeout', () => finish({ success: false, error: `Timed out after ${timeout} ms.` }));
            socket.once('error', error => finish({ success: false, error: error.message }));
        });
    }

    static async testDns(domain, server = '223.5.5.5', timeout = 5000) {
        const asciiDomain = domainToASCII(String(domain || '').trim());
        if (!asciiDomain || asciiDomain.length > 253 || !/^[a-z0-9.-]+$/i.test(asciiDomain)) {
            throw new Error('Invalid DNS test domain.');
        }
        if (!net.isIP(server)) throw new Error('Diagnostic DNS server must be an IP address.');
        const resolver = new dns.promises.Resolver({ timeout, tries: 1 });
        resolver.setServers([server]);
        const started = process.hrtime.bigint();
        let addresses;
        try {
            addresses = await resolver.resolve4(asciiDomain);
        } catch (ipv4Error) {
            try {
                addresses = await resolver.resolve6(asciiDomain);
            } catch (_) {
                throw new Error(ipv4Error.message);
            }
        }
        return {
            success: true,
            addresses,
            latency: Math.round(Number(process.hrtime.bigint() - started) / 1e6),
            server
        };
    }
}

module.exports = Diagnostics;
