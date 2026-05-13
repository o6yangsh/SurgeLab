class ProfileCompiler {
    /**
     * Compiles internal state into a valid sing-box JSON configuration.
     * @param {Array} nodes - List of proxy node objects
     * @param {Array} rules - List of routing rules
     * @param {Object} dnsSettings - Local/Remote DNS configuration
     * @param {string} mode - 'system' | 'tun'
     * @returns {Object} sing-box JSON config
     */
    static compile(nodes, rules, dnsSettings, mode) {
        return {
            log: {
                level: "info",
                timestamp: true
            },
            dns: this.buildDNS(dnsSettings),
            inbounds: this.buildInbounds(mode),
            outbounds: this.buildOutbounds(nodes),
            route: this.buildRoute(rules)
        };
    }

    static buildDNS(dnsSettings) {
        return {
            servers: [
                {
                    tag: "remote",
                    address: dnsSettings.remote || "https://cloudflare-dns.com/dns-query",
                    detour: "proxy"
                },
                {
                    tag: "local",
                    address: dnsSettings.local || "223.5.5.5",
                    detour: "direct"
                }
            ],
            rules: [
                {
                    geosite: "cn",
                    server: "local"
                }
            ],
            strategy: "ipv4_only"
        };
    }

    static buildInbounds(mode) {
        const inbounds = [];
        
        // System proxy mode (Mixed inbound)
        if (mode === 'system') {
            inbounds.push({
                type: "mixed",
                tag: "mixed-in",
                listen: "127.0.0.1",
                listen_port: 2080,
                sniff: true
            });
        }
        
        // TUN mode (strictly bound, no LAN sharing)
        if (mode === 'tun') {
            inbounds.push({
                type: "tun",
                tag: "tun-in",
                interface_name: "tun0",
                inet4_address: "172.19.0.1/30",
                auto_route: true,
                strict_route: true,
                stack: "system",
                sniff: true,
                sniff_override_destination: true
            });
        }
        
        return inbounds;
    }

    static buildOutbounds(nodes) {
        const outbounds = nodes.map(n => {
            const out = {
                type: n.type,
                tag: n.name,
                server: n.server,
                server_port: n.port,
            };

            if (n.type === 'vless') {
                out.uuid = n.uuid;
                if (n.tls && n.tls.enabled) {
                    out.tls = n.tls;
                }
            } else if (n.type === 'vmess') {
                out.uuid = n.uuid;
                out.alter_id = n.alterId || 0;
                out.security = n.security || 'auto';
                if (n.tls && n.tls.enabled) {
                    out.tls = n.tls;
                }
            } else if (n.type === 'hysteria2') {
                out.up_mbps = 100;
                out.down_mbps = 100;
                out.password = n.password;
                if (n.sni) out.tls = { enabled: true, server_name: n.sni };
            } else if (n.type === 'trojan' || n.type === 'shadowsocks') {
                out.password = n.password;
                if (n.method) out.method = n.method;
                if (n.tls) out.tls = n.tls;
            }

            return out;
        });

        // Add defaults
        outbounds.push({ type: "direct", tag: "direct" });
        outbounds.push({ type: "block", tag: "block" });
        outbounds.push({ type: "dns", tag: "dns-out" });

        return outbounds;
    }

    static buildRoute(rules) {
        const compiledRules = rules.map(r => {
            const rule = { outbound: r.outbound };
            if (r.domain_suffix) rule.domain_suffix = r.domain_suffix;
            if (r.domain_keyword) rule.domain_keyword = r.domain_keyword;
            if (r.geoip) rule.geoip = r.geoip;
            if (r.geosite) rule.geosite = r.geosite;
            return rule;
        });

        return {
            rules: compiledRules,
            auto_detect_interface: true
        };
    }

    /**
     * Helper for exporting profiles to ensure no passwords/UUIDs are saved in plaintext.
     */
    static redactProfile(nodes) {
        return nodes.map(n => {
            const redacted = JSON.parse(JSON.stringify(n)); // deep clone to avoid mutating original
            if (redacted.uuid) redacted.uuid = 'MASKED_UUID';
            if (redacted.password) redacted.password = 'MASKED_PASSWORD';
            if (redacted.tls && redacted.tls.reality) {
                redacted.tls.reality.public_key = 'MASKED_PUBLIC_KEY';
                redacted.tls.reality.short_id = 'MASKED_SHORT_ID';
            }
            return redacted;
        });
    }
}

if (typeof module !== 'undefined') {
    module.exports = ProfileCompiler;
}
