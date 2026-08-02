import {
  defaultApiKeyClientIpResolver,
  isIpAllowed,
  normalizeAllowedIpCidrs,
} from './ip-allowlist';

describe('normalizeAllowedIpCidrs', () => {
  it('normalizes exact addresses and CIDR network boundaries', () => {
    expect(
      normalizeAllowedIpCidrs(['203.0.113.42', '10.0.0.42/24', '2001:db8::1', '2001:db8::abcd/48']),
    ).toEqual(['203.0.113.42/32', '10.0.0.0/24', '2001:db8::1/128', '2001:db8::/48']);
  });

  it('deduplicates equivalent entries', () => {
    expect(normalizeAllowedIpCidrs(['10.0.0.1/24', '10.0.0.0/24'])).toEqual(['10.0.0.0/24']);
  });

  it('normalizes IPv4-mapped IPv6 addresses', () => {
    expect(normalizeAllowedIpCidrs(['::ffff:203.0.113.9'])).toEqual(['203.0.113.9/32']);
  });

  it('rejects malformed entries', () => {
    expect(() => normalizeAllowedIpCidrs(['not-an-ip'])).toThrow(
      'invalid IP allowlist entry: not-an-ip',
    );
    expect(() => normalizeAllowedIpCidrs(['10.0.0.0/99'])).toThrow(
      'invalid IP allowlist entry: 10.0.0.0/99',
    );
  });
});

describe('isIpAllowed', () => {
  it('matches exact addresses and CIDR ranges for IPv4 and IPv6', () => {
    expect(isIpAllowed('203.0.113.42', ['203.0.113.42/32'])).toBe(true);
    expect(isIpAllowed('10.0.0.99', ['10.0.0.0/24'])).toBe(true);
    expect(isIpAllowed('10.0.1.1', ['10.0.0.0/24'])).toBe(false);
    expect(isIpAllowed('2001:db8::1234', ['2001:db8::/48'])).toBe(true);
    expect(isIpAllowed('2001:db9::1', ['2001:db8::/48'])).toBe(false);
  });

  it('accepts IPv4-mapped request addresses and fails closed on missing or malformed IPs', () => {
    expect(isIpAllowed('::ffff:203.0.113.42', ['203.0.113.0/24'])).toBe(true);
    expect(isIpAllowed(undefined, ['203.0.113.0/24'])).toBe(false);
    expect(isIpAllowed('not-an-ip', ['203.0.113.0/24'])).toBe(false);
  });

  it('allows every IP when the allowlist is empty', () => {
    expect(isIpAllowed(undefined, [])).toBe(true);
  });
});

describe('defaultApiKeyClientIpResolver', () => {
  it('reads request.ip without consulting forwarded headers', () => {
    expect(
      defaultApiKeyClientIpResolver({
        ip: '203.0.113.42',
        headers: { 'x-forwarded-for': '198.51.100.1' },
      }),
    ).toBe('203.0.113.42');
    expect(defaultApiKeyClientIpResolver({ headers: {} })).toBeUndefined();
  });
});
