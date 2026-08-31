import { HttpException } from '@nestjs/common';
import {
  ApiKeyError,
  ApiKeyErrorCode,
  ApiKeyOperationError,
  ApiKeyOperationErrorCode,
} from './errors';

describe('ApiKeyError', () => {
  it('carries a code and http status', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.Invalid);

    expect(err).toBeInstanceOf(HttpException);
    expect(err).toBeInstanceOf(ApiKeyError);
    expect(err.code).toBe('api_key_invalid');
    expect(err.httpStatus).toBe(401);
    expect(err.getStatus()).toBe(401);
    expect(err.getResponse()).toEqual({
      statusCode: 401,
      code: 'api_key_invalid',
    });
  });

  it('environment mismatch maps to 403', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.EnvironmentMismatch);

    expect(err.httpStatus).toBe(403);
  });

  it('IP allowlist mismatch maps to 403', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.IpNotAllowed);

    expect(err.httpStatus).toBe(403);
  });

  it('preserves an optional reason', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.Malformed, 'bad prefix');

    expect(err.message).toContain('bad prefix');
    expect(JSON.stringify(err.getResponse())).not.toContain('bad prefix');
  });
});

describe('ApiKeyOperationError', () => {
  it('exposes the stable invalid-time code', () => {
    const err = new ApiKeyOperationError(
      ApiKeyOperationErrorCode.InvalidTime,
      'expiresAt must be a valid Date',
    );

    expect(err).toBeInstanceOf(ApiKeyOperationError);
    expect(err.code).toBe('api_key_invalid_time');
  });

  it('exposes the stable invalid-input code', () => {
    const err = new ApiKeyOperationError(ApiKeyOperationErrorCode.InvalidInput);

    expect(err.code).toBe('api_key_invalid_input');
  });

  it('preserves the terminal prefix-collision cause', () => {
    const cause = new Error('duplicate prefix');
    const err = new ApiKeyOperationError(
      ApiKeyOperationErrorCode.PrefixCollision,
      'unique prefix attempts exhausted',
      { cause },
    );

    expect(err.code).toBe('api_key_prefix_collision');
    expect(err.cause).toBe(cause);
  });
});
