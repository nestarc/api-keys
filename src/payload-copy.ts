import type { ApiKeyContext, ApiKeyEvent, ApiKeyVerificationMetric } from './types';

export function copyApiKeyContext(context: ApiKeyContext): ApiKeyContext {
  return {
    ...context,
    scopes: [...context.scopes],
    ...(context.allowedIpCidrs === undefined
      ? {}
      : { allowedIpCidrs: [...context.allowedIpCidrs] }),
  };
}

export function copyApiKeyEvent(event: ApiKeyEvent): ApiKeyEvent {
  const at = new Date(event.at.getTime());

  switch (event.type) {
    case 'api_key.created':
    case 'api_key.used':
      return {
        ...event,
        at,
        scopes: [...event.scopes],
      };
    case 'api_key.rotated':
      return {
        ...event,
        at,
        scopes: [...event.scopes],
        graceExpiresAt: new Date(event.graceExpiresAt.getTime()),
      };
    case 'api_key.revoked':
    case 'api_key.auth_failed':
      return {
        ...event,
        at,
      };
  }
}

export function copyApiKeyVerificationMetric(
  metric: ApiKeyVerificationMetric,
): ApiKeyVerificationMetric {
  return { ...metric };
}
