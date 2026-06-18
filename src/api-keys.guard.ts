import { CanActivate, ExecutionContext, Inject, Injectable, Optional } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiKeysService } from './api-keys.service';
import {
  API_KEY_CONTEXT_PROPERTY,
  API_KEY_CONTEXT_WRITER,
  ApiKeyContextWriter,
} from './context';
import { ENVIRONMENT_METADATA } from './decorators/require-environment.decorator';
import {
  RequiredScope,
  SCOPE_METADATA,
} from './decorators/require-scope.decorator';
import { ApiKeyError, ApiKeyErrorCode } from './errors';
import { scopeSatisfies } from './scope-matcher';
import type { Environment } from './types';

export { API_KEY_CONTEXT_PROPERTY };

@Injectable()
export class ApiKeysGuard implements CanActivate {
  constructor(
    private readonly service: ApiKeysService,
    private readonly reflector: Reflector,
    @Optional()
    @Inject(API_KEY_CONTEXT_WRITER)
    private readonly contextWriter?: ApiKeyContextWriter,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Record<string, unknown>>();
    const header = request.headers as Record<string, string> | undefined;
    const authorization = header?.authorization;

    if (!authorization) {
      throw new ApiKeyError(ApiKeyErrorCode.Missing);
    }

    const rawKey = authorization.startsWith('Bearer ')
      ? authorization.slice('Bearer '.length)
      : authorization;
    const apiKeyContext = await this.service.verify(rawKey);

    const requiredEnvironment = this.reflector.getAllAndOverride<Environment | undefined>(
      ENVIRONMENT_METADATA,
      [context.getHandler(), context.getClass()],
    );
    if (requiredEnvironment && apiKeyContext.environment !== requiredEnvironment) {
      throw new ApiKeyError(ApiKeyErrorCode.EnvironmentMismatch);
    }

    const requiredScope = this.reflector.getAllAndOverride<RequiredScope | undefined>(
      SCOPE_METADATA,
      [context.getHandler(), context.getClass()],
    );
    if (
      requiredScope &&
      !scopeSatisfies(apiKeyContext.scopes, requiredScope.resource, requiredScope.level)
    ) {
      throw new ApiKeyError(ApiKeyErrorCode.ScopeInsufficient);
    }

    request[API_KEY_CONTEXT_PROPERTY] = apiKeyContext;
    await this.contextWriter?.(apiKeyContext, request);
    return true;
  }
}
