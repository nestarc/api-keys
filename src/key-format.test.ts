import { ApiKeyError } from './errors';
import { API_KEY_REDACT_REGEX, generateKey, parseKey } from './key-format';

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

  it.each([
    ['', 'empty'],
    ['under_score', 'underscore'],
    ['punctuation!', 'punctuation'],
    ['a'.repeat(33), 'too long'],
  ])('rejects an invalid %s namespace before generating key material', (namespace) => {
    expect(() => generateKey({ namespace, environment: 'live' })).toThrow(
      expect.objectContaining({ code: 'api_key_invalid_input' }),
    );
  });

  it('rejects an untyped invalid environment before generating key material', () => {
    expect(() => generateKey({ namespace: 'nk', environment: 'prod' as 'live' })).toThrow(
      expect.objectContaining({ code: 'api_key_invalid_input' }),
    );
  });

  it.each([
    ['a', 'live'],
    ['Acme42', 'test'],
    ['a'.repeat(32), 'live'],
  ] as const)(
    'round-trips and redacts every supported key shape for %s/%s',
    (namespace, environment) => {
      for (let sample = 0; sample < 16; sample += 1) {
        const generated = generateKey({ namespace, environment });

        expect(parseKey(generated.raw)).toEqual({
          namespace,
          environment,
          prefix: generated.prefix,
          secret: generated.secret,
        });
        expect(
          JSON.stringify({ authorization: `Bearer ${generated.raw}` }).replace(
            API_KEY_REDACT_REGEX,
            '[REDACTED_API_KEY]',
          ),
        ).toBe('{"authorization":"Bearer [REDACTED_API_KEY]"}');
      }
    },
  );
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
    expect(() => parseKey(`nk_prod_${'a'.repeat(12)}_${'b'.repeat(32)}`)).toThrow(ApiKeyError);
  });

  it.each([
    [`nk_live_${'!'.repeat(12)}_${'b'.repeat(32)}`, 'prefix punctuation'],
    [`nk_live_${'a'.repeat(12)}_${'!'.repeat(32)}`, 'secret punctuation'],
    [`under_score_live_${'a'.repeat(12)}_${'b'.repeat(32)}`, 'namespace delimiter'],
    [`punctuation!_live_${'a'.repeat(12)}_${'b'.repeat(32)}`, 'namespace punctuation'],
  ])('rejects %s as malformed (%s)', (raw) => {
    expect(() => parseKey(raw)).toThrow(expect.objectContaining({ code: 'api_key_malformed' }));
  });
});
