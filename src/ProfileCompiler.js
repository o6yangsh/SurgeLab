const RuleEngineClass = typeof require !== 'undefined' ? require('./RuleEngine') : RuleEngine;

class ProfileCompiler {
    static compile(nodes = [], rules = [], dnsSettings = {}, mode = 'system') {
        const prepared = this.prepareNodes(nodes);
        const hasProxy = prepared.length > 0;
        const route = this.buildRoute(rules, hasProxy);
        const config = {
            log: { level: 'info', timestamp: true },
            dns: this.buildDNS(dnsSettings, hasProxy, route.rule_set || []),
            inbounds: this.buildInbounds(mode),
            outbounds: this.buildOutbounds(prepared),
            route
        };
        if ((route.rule_set || []).length) {
            config.experimental = { cache_file: { enabled: true } };
        }
        return config;
    }

    static slugTag(value, index) {
        const clean = String(value || `node-${index + 1}`)
            .trim().replace(/\s+/g, '-').replace(/[^\w\-.\u4e00-\u9fff]/g, '-').replace(/-+/g, '-');
        return clean || `node-${index + 1}`;
    }

    static prepareNodes(nodes) {
        const used = new Set(['direct', 'proxy', 'auto']);
        return (nodes || []).map((node, index) => {
            let tag = this.slugTag(node.tag || node.name, index);
            const base = tag;
            let suffix = 2;
            while (used.has(tag)) tag = `${base}-${suffix++}`;
            used.add(tag);
            return { ...node, tag };
        });
    }

    static buildDNS(settings = {}, hasProxy = false, ruleSets = []) {
        const remote = this.parseDnsServer(settings.remote || 'https://cloudflare-dns.com/dns-query', 'remote');
        const local = this.parseDnsServer(settings.local || '223.5.5.5', 'local');
        if (remote.type === 'https' || remote.type === 'tls' || remote.type === 'quic') {
            remote.domain_resolver = 'local';
        }
        remote.detour = hasProxy ? 'proxy' : 'direct';
        local.detour = 'direct';
        const fakeIpEnabled = settings.fakeIpEnabled === true;
        const servers = [remote, local];
        if (fakeIpEnabled) {
            servers.push({ type: 'fakeip', tag: 'fakeip', inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' });
        }
        const rules = [];
        if (ruleSets.some(ruleSet => ruleSet.tag === 'geosite-cn')) {
            rules.push({ rule_set: ['geosite-cn'], action: 'route', server: 'local' });
        }
        if (fakeIpEnabled) rules.push({ query_type: ['A', 'AAAA'], action: 'route', server: 'fakeip' });
        return {
            servers,
            rules,
            final: 'remote',
            strategy: settings.strategy || 'prefer_ipv4',
            reverse_mapping: fakeIpEnabled
        };
    }

    static parseDnsServer(value, tag) {
        const raw = String(value || '').trim();
        if (/^https?:\/\//i.test(raw)) {
            const url = new URL(raw);
            return {
                type: url.protocol === 'http:' ? 'http' : 'https',
                tag,
                server: url.hostname,
                server_port: url.port ? Number(url.port) : (url.protocol === 'http:' ? 80 : 443),
                path: `${url.pathname || '/'}${url.search || ''}`,
                ...(url.protocol === 'https:' ? { tls: { enabled: true, server_name: url.hostname } } : {})
            };
        }
        if (/^(tls|quic|udp|tcp):\/\//i.test(raw)) {
            const url = new URL(raw);
            const type = url.protocol.slice(0, -1);
            const server = { type, tag, server: url.hostname, server_port: url.port ? Number(url.port) : (type === 'tls' ? 853 : 53) };
            if (type === 'tls' || type === 'quic') server.tls = { enabled: true, server_name: url.hostname };
            return server;
        }
        return { type: 'udp', tag, server: raw, server_port: 53 };
    }

    static buildInbounds(mode) {
        if (mode === 'tun') {
            return [{
                type: 'tun', tag: 'tun-in', interface_name: 'tun0',
                address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                auto_route: true, strict_route: true, stack: 'system'
            }];
        }
        return [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }];
    }

    static buildOutbounds(nodes) {
        const outbounds = nodes.map(node => this.buildNodeOutbound(node));
        if (nodes.length > 1) {
            outbounds.push({
                type: 'urltest', tag: 'auto', outbounds: nodes.map(node => node.tag),
                url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 50
            });
        }
        if (nodes.length) {
            outbounds.push({
                type: 'selector', tag: 'proxy',
                outbounds: [...(nodes.length > 1 ? ['auto'] : []), ...nodes.map(node => node.tag)],
                default: nodes.length > 1 ? 'auto' : nodes[0].tag
            });
        }
        outbounds.push({ type: 'direct', tag: 'direct' });
        return outbounds;
    }

    static buildNodeOutbound(node) {
        const out = { type: node.type, tag: node.tag, server: node.server, server_port: node.port };
        const copy = (...fields) => fields.forEach(field => {
            if (node[field] !== undefined && node[field] !== null && node[field] !== '') out[field] = node[field];
        });
        if (node.type === 'vless') copy('uuid', 'flow', 'network', 'tls', 'packet_encoding', 'transport', 'multiplex');
        else if (node.type === 'vmess') {
            copy('uuid', 'network', 'tls', 'packet_encoding', 'transport', 'multiplex');
            out.alter_id = node.alterId || node.alter_id || 0;
            out.security = node.security || 'auto';
        } else if (node.type === 'trojan') copy('password', 'network', 'tls', 'transport', 'multiplex');
        else if (node.type === 'shadowsocks') copy('method', 'password', 'plugin', 'plugin_opts', 'network', 'udp_over_tcp', 'multiplex');
        else if (node.type === 'hysteria2') copy('password', 'up_mbps', 'down_mbps', 'obfs', 'tls', 'network', 'server_ports', 'hop_interval');
        else throw new Error(`Unsupported outbound type: ${node.type}`);
        return out;
    }

    static buildRoute(rules, hasProxy) {
        const compiled = [
            { action: 'sniff' },
            { protocol: 'dns', action: 'hijack-dns' }
        ];
        const ruleSetTags = new Set();
        (rules || []).forEach(rawRule => {
            const normalized = RuleEngineClass.normalizeRule(rawRule);
            if (!hasProxy && normalized.outbound === 'proxy') normalized.outbound = 'direct';
            const rule = RuleEngineClass.compileRule(normalized);
            if (!rule) return;
            if (rule.rule_set) rule.rule_set.forEach(tag => ruleSetTags.add(tag));
            compiled.push(rule);
        });
        const ruleSetUrls = {
            'geosite-cn': 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
            'geoip-cn': 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs'
        };
        const rule_set = [...ruleSetTags].map(tag => {
            if (!ruleSetUrls[tag]) throw new Error(`Unknown remote rule set: ${tag}`);
            return { type: 'remote', tag, format: 'binary', url: ruleSetUrls[tag], download_detour: hasProxy ? 'proxy' : 'direct' };
        });
        return {
            rules: compiled,
            ...(rule_set.length ? { rule_set } : {}),
            final: hasProxy ? 'proxy' : 'direct',
            auto_detect_interface: true,
            default_domain_resolver: { server: 'local', strategy: 'ipv4_only' }
        };
    }

    static redactProfile(nodes) {
        return nodes.map(node => {
            const redacted = JSON.parse(JSON.stringify(node));
            if (redacted.uuid) redacted.uuid = 'MASKED_UUID';
            if (redacted.password) redacted.password = 'MASKED_PASSWORD';
            if (redacted.plugin_opts) redacted.plugin_opts = 'MASKED_PLUGIN_OPTIONS';
            if (redacted.obfs && redacted.obfs.password) redacted.obfs.password = 'MASKED_PASSWORD';
            if (redacted.tls && redacted.tls.reality) {
                redacted.tls.reality.public_key = 'MASKED_PUBLIC_KEY';
                redacted.tls.reality.short_id = 'MASKED_SHORT_ID';
            }
            return redacted;
        });
    }
}

if (typeof module !== 'undefined') module.exports = ProfileCompiler;
