import {
  API_KEY_TENANT_ID_MAX_LENGTH,
  isValidTenantId,
  validateTenantId,
} from './input-validation';

describe('tenant identity validation', () => {
  it.each([
    ['simple', 'tenant_a'],
    ['internal whitespace', 'tenant acme'],
    ['non-ASCII exact value', '테넌트-아크미'],
    ['maximum length', 't'.repeat(API_KEY_TENANT_ID_MAX_LENGTH)],
  ])('preserves a valid %s', (_case, tenantId) => {
    expect(validateTenantId(tenantId)).toBe(tenantId);
    expect(isValidTenantId(tenantId)).toBe(true);
  });

  it('does not Unicode-normalize opaque tenant identities', () => {
    const composed = 'café';
    const decomposed = 'café';

    expect(validateTenantId(composed)).toBe(composed);
    expect(validateTenantId(decomposed)).toBe(decomposed);
    expect(validateTenantId(composed)).not.toBe(validateTenantId(decomposed));
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['number', 42],
    ['empty', ''],
    ['whitespace-only', '\t'],
    ['leading whitespace', ' tenant_a'],
    ['trailing whitespace', 'tenant_a\n'],
    ['oversized', 't'.repeat(API_KEY_TENANT_ID_MAX_LENGTH + 1)],
  ])('rejects %s instead of coercing or trimming it', (_case, tenantId) => {
    expect(isValidTenantId(tenantId)).toBe(false);
    expect(() => validateTenantId(tenantId)).toThrow(
      expect.objectContaining({ code: 'api_key_invalid_input' }),
    );
  });
});
