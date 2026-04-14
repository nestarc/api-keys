import { ApiKeyError } from './errors';
import { generateKey, parseKey } from './key-format';

describe('generateKey', () => {
  it('produces nk_live_<12>_<32> format by default', () => {
    const key = generateKey({ namespace: 'nk', environment: 'live' });

    expect(key.raw).toMatch(/^nk_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);
    expect(key.prefix.length).toBe(12);
    expect(key.secret.length).toBe(32);
    expect(key.environment).toBe('live');
  });

  it('produces distinct prefix/secret on each call', () => {
    const a = generateKey({ namespace: 'nk', environment: 'test' });
    const b = generateKey({ namespace: 'nk', environment: 'test' });

    expect(a.prefix).not.toBe(b.prefix);
    expect(a.secret).not.toBe(b.secret);
  });

  it('honors custom namespace', () => {
    const key = generateKey({ namespace: 'acme', environment: 'live' });

    expect(key.raw.startsWith('acme_live_')).toBe(true);
  });
});

describe('parseKey', () => {
  it('extracts namespace, env, prefix, secret', () => {
    const parsed = parseKey(`nk_live_abcdefghijkl_${'x'.repeat(32)}`);

    expect(parsed.namespace).toBe('nk');
    expect(parsed.environment).toBe('live');
    expect(parsed.prefix).toBe('abcdefghijkl');
    expect(parsed.secret).toBe('x'.repeat(32));
  });

  it('throws ApiKeyError(malformed) on wrong shape', () => {
    expect(() => parseKey('not_a_key')).toThrow(ApiKeyError);
    expect(() => parseKey('nk_live_short_secret')).toThrow(ApiKeyError);
  });

  it('throws on invalid environment', () => {
    expect(() => parseKey(`nk_prod_${'a'.repeat(12)}_${'b'.repeat(32)}`)).toThrow(
      ApiKeyError,
    );
  });
});
