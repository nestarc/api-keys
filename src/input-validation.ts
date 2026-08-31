import { ApiKeyOperationError, ApiKeyOperationErrorCode } from './errors';
import type { Environment, Scope, ScopeLevel } from './types';

export const API_KEY_NAMESPACE_MAX_LENGTH = 32;
export const API_KEY_SCOPE_RESOURCE_MAX_LENGTH = 128;
export const API_KEY_TENANT_ID_MAX_LENGTH = 255;

const NAMESPACE_PATTERN = /^[A-Za-z0-9]+$/;
const SCOPE_RESOURCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

export function isValidNamespace(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= API_KEY_NAMESPACE_MAX_LENGTH &&
    NAMESPACE_PATTERN.test(value)
  );
}

export function validateNamespace(value: unknown): string {
  if (!isValidNamespace(value)) {
    invalidInput(
      `namespace must contain 1-${API_KEY_NAMESPACE_MAX_LENGTH} ASCII alphanumeric characters`,
    );
  }

  return value;
}

export function isValidEnvironment(value: unknown): value is Environment {
  return value === 'live' || value === 'test';
}

export function validateEnvironment(value: unknown): Environment {
  if (!isValidEnvironment(value)) {
    invalidInput('environment must be exactly "live" or "test"');
  }

  return value;
}

export function isValidTenantId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= API_KEY_TENANT_ID_MAX_LENGTH &&
    value.trim() === value
  );
}

export function validateTenantId(value: unknown): string {
  if (!isValidTenantId(value)) {
    invalidInput(
      `tenantId must be an exact 1-${API_KEY_TENANT_ID_MAX_LENGTH} character string without leading or trailing whitespace`,
    );
  }

  return value;
}

export function isValidScopeLevel(value: unknown): value is ScopeLevel {
  return value === 'read' || value === 'write';
}

export function isValidScopeResource(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= API_KEY_SCOPE_RESOURCE_MAX_LENGTH &&
    SCOPE_RESOURCE_PATTERN.test(value)
  );
}

export function validateScopes(value: unknown): Scope[] {
  if (!Array.isArray(value) || value.length === 0) {
    invalidInput('at least one scope is required');
  }

  for (const scope of value) {
    if (!scope || typeof scope !== 'object') {
      invalidInput('each scope must be an object');
    }

    const candidate = scope as { resource?: unknown; level?: unknown };
    if (!isValidScopeResource(candidate.resource)) {
      invalidInput(
        `scope resource must contain 1-${API_KEY_SCOPE_RESOURCE_MAX_LENGTH} ASCII letters, digits, dot, underscore, slash, or hyphen; it must start with a letter or digit`,
      );
    }
    if (!isValidScopeLevel(candidate.level)) {
      invalidInput('scope level must be exactly "read" or "write"');
    }
  }

  return value as Scope[];
}

function invalidInput(reason: string): never {
  throw new ApiKeyOperationError(ApiKeyOperationErrorCode.InvalidInput, reason);
}
