class RuleEngine {
    static normalizeRule(rule = {}) {
        const normalized = {
            id: rule.id || `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            enabled: rule.enabled !== false,
            outbound: rule.outbound || rule.target || 'proxy'
        };
        const fields = [
            'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr',
            'ip_is_private', 'process_name', 'rule_set', 'network', 'port'
        ];
        for (const field of fields) {
            if (rule[field] !== undefined) {
                normalized.type = field;
                normalized.value = rule[field];
                return normalized;
            }
        }
        normalized.type = rule.type || 'domain_suffix';
        normalized.value = rule.value ?? '';
        return normalized;
    }

    static compileRule(rule) {
        const normalized = this.normalizeRule(rule);
        if (!normalized.enabled) return null;
        const values = Array.isArray(normalized.value)
            ? normalized.value.filter(value => value !== '')
            : String(normalized.value).split(',').map(value => value.trim()).filter(Boolean);
        if (normalized.type !== 'ip_is_private' && values.length === 0) return null;

        const compiled = {};
        if (normalized.type === 'ip_is_private') {
            compiled.ip_is_private = normalized.value !== false && normalized.value !== 'false';
        } else if (normalized.type === 'port') {
            compiled.port = values.map(value => Number(value)).filter(Number.isInteger);
        } else {
            compiled[normalized.type] = values;
        }
        if (normalized.outbound === 'reject' || normalized.outbound === 'block') {
            compiled.action = 'reject';
        } else {
            compiled.action = 'route';
            compiled.outbound = normalized.outbound;
        }
        return compiled;
    }

    static match(target, rules, context = {}) {
        const value = String(target || '').trim();
        const host = this._host(value);
        const ip = this._isIPv4(host) ? host : null;
        const normalizedRules = (rules || []).map(rule => this.normalizeRule(rule));
        for (let index = 0; index < normalizedRules.length; index += 1) {
            const rule = normalizedRules[index];
            if (!rule.enabled) continue;
            const result = this._matches(rule, host, ip, context);
            if (result === true) return { matched: true, rule, index, outbound: rule.outbound };
            if (result === null) continue;
        }
        return { matched: false, rule: null, index: -1, outbound: context.final || 'proxy' };
    }

    static _host(value) {
        try {
            const url = value.includes('://') ? new URL(value) : new URL(`https://${value}`);
            return url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        } catch (_) {
            return value.split(':')[0].toLowerCase().replace(/^\[|\]$/g, '');
        }
    }

    static _values(value) {
        return (Array.isArray(value) ? value : String(value || '').split(','))
            .map(item => String(item).trim().toLowerCase())
            .filter(Boolean);
    }

    static _matches(rule, host, ip, context) {
        const values = this._values(rule.value);
        switch (rule.type) {
        case 'domain': return values.includes(host);
        case 'domain_suffix': return values.some(value => host === value.replace(/^\./, '') || host.endsWith(`.${value.replace(/^\./, '')}`));
        case 'domain_keyword': return values.some(value => host.includes(value));
        case 'domain_regex': return values.some(value => {
            try { return new RegExp(value, 'i').test(host); } catch (_) { return false; }
        });
        case 'ip_cidr': return Boolean(ip && values.some(cidr => this._inIPv4Cidr(ip, cidr)));
        case 'ip_is_private': return Boolean(ip && this._isPrivateIPv4(ip));
        case 'process_name': return values.includes(String(context.processName || '').toLowerCase());
        case 'network': return values.includes(String(context.network || '').toLowerCase());
        case 'port': return values.map(Number).includes(Number(context.port));
        // Binary remote rule-sets are evaluated by sing-box. The UI deliberately
        // does not guess their contents.
        case 'rule_set': return null;
        default: return false;
        }
    }

    static _isIPv4(value) {
        const parts = value.split('.');
        return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    }

    static _ipv4Number(value) {
        return value.split('.').reduce((sum, part) => (sum * 256 + Number(part)) >>> 0, 0) >>> 0;
    }

    static _inIPv4Cidr(ip, cidr) {
        const [network, prefixText = '32'] = cidr.split('/');
        const prefix = Number(prefixText);
        if (!this._isIPv4(network) || prefix < 0 || prefix > 32) return false;
        const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
        return (this._ipv4Number(ip) & mask) === (this._ipv4Number(network) & mask);
    }

    static _isPrivateIPv4(ip) {
        return ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16']
            .some(cidr => this._inIPv4Cidr(ip, cidr));
    }
}

if (typeof module !== 'undefined') module.exports = RuleEngine;
