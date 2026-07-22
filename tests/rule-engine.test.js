const RuleEngine = require('../src/RuleEngine');

describe('RuleEngine', () => {
    const rules = [
        { type: 'domain', value: 'exact.example.com', outbound: 'direct' },
        { type: 'domain_suffix', value: 'example.org', outbound: 'proxy' },
        { type: 'domain_keyword', value: 'tracker', outbound: 'reject' },
        { type: 'ip_cidr', value: '203.0.113.0/24', outbound: 'proxy' },
        { type: 'ip_is_private', value: true, outbound: 'direct' },
        { type: 'process_name', value: 'curl.exe', outbound: 'proxy' }
    ];

    test.each([
        ['https://exact.example.com/path', {}, 'direct'],
        ['sub.example.org', {}, 'proxy'],
        ['ad-tracker.test', {}, 'reject'],
        ['203.0.113.42', {}, 'proxy'],
        ['192.168.1.1', {}, 'direct'],
        ['unmatched.test', { processName: 'curl.exe' }, 'proxy']
    ])('matches %s using first-match routing', (target, context, outbound) => {
        expect(RuleEngine.match(target, rules, context).outbound).toBe(outbound);
    });

    test('uses final target when nothing matches', () => {
        expect(RuleEngine.match('unmatched.test', rules, { final: 'direct' })).toMatchObject({ matched: false, outbound: 'direct' });
    });

    test('does not pretend to evaluate remote binary rule sets', () => {
        const result = RuleEngine.match('example.cn', [{ type: 'rule_set', value: 'geosite-cn', outbound: 'direct' }], { final: 'proxy' });
        expect(result).toMatchObject({ matched: false, outbound: 'proxy' });
    });

    test('compiles reject rules to a route action', () => {
        expect(RuleEngine.compileRule({ type: 'domain_keyword', value: 'ads', outbound: 'reject' }))
            .toEqual({ domain_keyword: ['ads'], action: 'reject' });
    });
});
