import { HttpException } from '@nestjs/common';

export const ApiKeyErrorCode = {
  Missing: 'api_key_missing',
  Malformed: 'api_key_malformed',
  Invalid: 'api_key_invalid',
  Revoked: 'api_key_revoked',
  Expired: 'api_key_expired',
  EnvironmentMismatch: 'api_key_environment_mismatch',
  ScopeInsufficient: 'api_key_scope_insufficient',
  IpNotAllowed: 'api_key_ip_not_allowed',
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
  api_key_ip_not_allowed: 403,
};

export class ApiKeyError extends HttpException {
  readonly code: ApiKeyErrorCode;
  /**
   * Backward-compatible status property. Prefer Nest's getStatus() for new code.
   */
  readonly httpStatus: number;

  constructor(code: ApiKeyErrorCode, reason?: string) {
    const httpStatus = HTTP_STATUS[code];
    super({ statusCode: httpStatus, code }, httpStatus);
    this.name = 'ApiKeyError';
    this.message = reason ? `${code}: ${reason}` : code;
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

export const ApiKeyOperationErrorCode = {
  NotFound: 'api_key_record_not_found',
  NotRotatable: 'api_key_not_rotatable',
  InvalidTime: 'api_key_invalid_time',
  InvalidInput: 'api_key_invalid_input',
} as const;

export type ApiKeyOperationErrorCode =
  (typeof ApiKeyOperationErrorCode)[keyof typeof ApiKeyOperationErrorCode];

export class ApiKeyOperationError extends Error {
  readonly code: ApiKeyOperationErrorCode;

  constructor(code: ApiKeyOperationErrorCode, reason?: string) {
    super(reason ? `${code}: ${reason}` : code);
    this.name = 'ApiKeyOperationError';
    this.code = code;
  }
}
