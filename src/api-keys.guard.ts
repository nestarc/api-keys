import { Inject, Injectable, Optional } from '@nestjs/common';
import type { CanActivate, ExecutionContext } from '@nestjs/common' with {
  'resolution-mode': 'import',
};
import { Reflector } from '@nestjs/core';
import type { Reflector as ReflectorType } from '@nestjs/core' with {
  'resolution-mode': 'import',
};
import { ApiKeysService } from './api-keys.service';
import { API_KEY_CONTEXT_PROPERTY, API_KEY_CONTEXT_WRITER, ApiKeyContextWriter } from './context';
import { ENVIRONMENT_METADATA } from './decorators/require-environment.decorator';
import { RequiredScope, SCOPE_METADATA } from './decorators/require-scope.decorator';
import {
  API_KEY_CLIENT_IP_RESOLVER,
  ApiKeyClientIpResolver,
  defaultApiKeyClientIpResolver,
} from './ip-allowlist';
import { copyApiKeyContext } from './payload-copy';
import type { Environment } from './types';

export { API_KEY_CONTEXT_PROPERTY };

@Injectable()
export class ApiKeysGuard implements CanActivate {
  constructor(
    private readonly service: ApiKeysService,
    @Inject(Reflector)
    private readonly reflector: ReflectorType,
    @Optional()
    @Inject(API_KEY_CONTEXT_WRITER)
    private readonly contextWriter?: ApiKeyContextWriter,
    @Optional()
    @Inject(API_KEY_CLIENT_IP_RESOLVER)
    private readonly clientIpResolver?: ApiKeyClientIpResolver,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Record<string, unknown>>();
    const header = request.headers as Record<string, string> | undefined;
    const authorization = header?.authorization;

    const requiredEnvironment = this.reflector.getAllAndOverride<Environment | undefined>(
      ENVIRONMENT_METADATA,
      [context.getHandler(), context.getClass()],
    );
    const requiredScope = this.reflector.getAllAndOverride<RequiredScope | undefined>(
      SCOPE_METADATA,
      [context.getHandler(), context.getClass()],
    );
    const rawKey = authorization
      ? authorization.startsWith('Bearer ')
        ? authorization.slice('Bearer '.length)
        : authorization
      : undefined;
    const apiKeyContext = await this.service.authorizeRequest({
      rawKey,
      requiredEnvironment,
      requiredScope,
      request,
      clientIpResolver: this.clientIpResolver ?? defaultApiKeyClientIpResolver,
    });

    request[API_KEY_CONTEXT_PROPERTY] = copyApiKeyContext(apiKeyContext);
    await this.contextWriter?.(copyApiKeyContext(apiKeyContext), request);
    request[API_KEY_CONTEXT_PROPERTY] = copyApiKeyContext(apiKeyContext);
    return true;
  }
}
