import type { Scope, ScopeLevel } from './types';

export function flattenScopes(scopes: Scope[]): string[] {
  if (scopes.length === 0) {
    throw new Error('at least one scope is required');
  }

  return Array.from(new Set(scopes.map((scope) => `${scope.resource}:${scope.level}`)));
}

export function scopeSatisfies(
  granted: string[],
  resource: string,
  required: ScopeLevel,
): boolean {
  const writeScope = `${resource}:write`;
  if (granted.includes(writeScope)) {
    return true;
  }

  if (required === 'read') {
    return granted.includes(`${resource}:read`);
  }

  return false;
}
