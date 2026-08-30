import type { Scope, ScopeLevel } from './types';
import { validateScopes } from './input-validation';

export function flattenScopes(scopes: Scope[]): string[] {
  const validatedScopes = validateScopes(scopes);

  return Array.from(new Set(validatedScopes.map((scope) => `${scope.resource}:${scope.level}`)));
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
