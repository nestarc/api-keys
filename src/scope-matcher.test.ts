import { flattenScopes, scopeSatisfies } from './scope-matcher';

describe('flattenScopes', () => {
  it('converts Scope objects to "resource:level" strings', () => {
    expect(
      flattenScopes([
        { resource: 'invoices', level: 'read' },
        { resource: 'reports', level: 'write' },
      ]),
    ).toEqual(['invoices:read', 'reports:write']);
  });

  it('rejects empty scope arrays', () => {
    expect(() => flattenScopes([])).toThrow(/at least one scope/);
  });

  it('deduplicates identical scopes', () => {
    expect(
      flattenScopes([
        { resource: 'invoices', level: 'read' },
        { resource: 'invoices', level: 'read' },
        { resource: 'reports', level: 'write' },
      ]),
    ).toEqual(['invoices:read', 'reports:write']);
  });

  it.each([
    [[{ resource: '', level: 'read' }], 'empty resource'],
    [[{ resource: 'reports:admin', level: 'read' }], 'resource delimiter'],
    [[{ resource: 'reports?', level: 'read' }], 'resource punctuation'],
    [[{ resource: 'a'.repeat(129), level: 'read' }], 'resource length'],
    [[{ resource: 'reports', level: 'admin' }], 'scope level'],
    [undefined, 'non-array scopes'],
  ])('rejects invalid runtime scope input: %s (%s)', (scopes, _case) => {
    expect(() => flattenScopes(scopes as never)).toThrow(
      expect.objectContaining({ code: 'api_key_invalid_input' }),
    );
  });

  it('accepts the documented resource boundary and characters', () => {
    const resource = `A${'a'.repeat(123)}._/-`;

    expect(flattenScopes([{ resource, level: 'write' }])).toEqual([`${resource}:write`]);
  });
});

describe('scopeSatisfies', () => {
  it('exact match passes', () => {
    expect(scopeSatisfies(['invoices:read'], 'invoices', 'read')).toBe(true);
  });

  it('write implies read', () => {
    expect(scopeSatisfies(['invoices:write'], 'invoices', 'read')).toBe(true);
  });

  it('read does not imply write', () => {
    expect(scopeSatisfies(['invoices:read'], 'invoices', 'write')).toBe(false);
  });

  it('different resource fails', () => {
    expect(scopeSatisfies(['invoices:write'], 'reports', 'read')).toBe(false);
  });
});
