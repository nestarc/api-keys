import type { ApiKeyContext } from './types';

export const API_KEY_CONTEXT_PROPERTY = 'apiKey';
export const API_KEY_CONTEXT_WRITER = Symbol('API_KEY_CONTEXT_WRITER');

export type ApiKeyContextWriter = (
  apiKey: ApiKeyContext,
  request: unknown,
) => void | Promise<void>;

export function getApiKeyContext(request: unknown): ApiKeyContext | undefined {
  if (!request || typeof request !== 'object') {
    return undefined;
  }

  const value = (request as Record<string, unknown>)[API_KEY_CONTEXT_PROPERTY];
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  return value as ApiKeyContext;
}
