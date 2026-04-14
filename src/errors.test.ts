import { ApiKeyError, ApiKeyErrorCode } from './errors';

describe('ApiKeyError', () => {
  it('carries a code and http status', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.Invalid);

    expect(err.code).toBe('api_key_invalid');
    expect(err.httpStatus).toBe(401);
  });

  it('environment mismatch maps to 403', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.EnvironmentMismatch);

    expect(err.httpStatus).toBe(403);
  });

  it('preserves an optional reason', () => {
    const err = new ApiKeyError(ApiKeyErrorCode.Malformed, 'bad prefix');

    expect(err.message).toContain('bad prefix');
  });
});
