export const ApiKeyErrorCode = {
  Missing: 'api_key_missing',
  Malformed: 'api_key_malformed',
  Invalid: 'api_key_invalid',
  Revoked: 'api_key_revoked',
  Expired: 'api_key_expired',
  EnvironmentMismatch: 'api_key_environment_mismatch',
  ScopeInsufficient: 'api_key_scope_insufficient',
} as const;

export type ApiKeyErrorCode = (typeof ApiKeyErrorCode)[keyof typeof ApiKeyErrorCode];

const HTTP_STATUS: Record<ApiKeyErrorCode, number> = {
  api_key_missing: 401,
  api_key_malformed: 401,
  api_key_invalid: 401,
  api_key_revoked: 401,
  api_key_expired: 401,
  api_key_environment_mismatch: 403,
  api_key_scope_insufficient: 403,
};

export class ApiKeyError extends Error {
  readonly code: ApiKeyErrorCode;
  readonly httpStatus: number;

  constructor(code: ApiKeyErrorCode, reason?: string) {
    super(reason ? `${code}: ${reason}` : code);
    this.name = 'ApiKeyError';
    this.code = code;
    this.httpStatus = HTTP_STATUS[code];
  }
}
