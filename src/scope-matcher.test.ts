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
