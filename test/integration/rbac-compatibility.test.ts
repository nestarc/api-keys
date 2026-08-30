import { createRequire } from 'node:module';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiKeysGuard } from '../../src/api-keys.guard';
import { ApiKeysService } from '../../src/api-keys.service';
import { API_KEY_CONTEXT_PROPERTY } from '../../src/context';
import { Sha256Hasher } from '../../src/hasher';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';
import type { ApiKeyContext } from '../../src/types';

const rbacIntegration = createRequire(__filename)('@nestarc/rbac/integrations/api-keys') as {
  createApiKeySubjectResolver: () => (context: ExecutionContext) => unknown | Promise<unknown>;
};

describe('@nestarc/rbac compatibility', () => {
  it('maps the request.apiKey context written by ApiKeysGuard to an api_key subject', async () => {
    const service = new ApiKeysService({
      storage: new InMemoryApiKeyStorage(),
      hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
      namespace: 'nk',
      idFactory: () => 'key_rbac',
    });
    const { key } = await service.create({
      tenantId: 'tenant_rbac',
      name: 'RBAC key',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    const request: Record<string, unknown> = {
      headers: { authorization: `Bearer ${key}` },
    };
    const executionContext = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => () => undefined,
      getClass: () => class {},
    } as unknown as ExecutionContext;
    const contextWriter = async (context: ApiKeyContext, targetRequest: unknown) => {
      context.tenantId = 'tenant_attacker';
      context.scopes.splice(0, context.scopes.length, 'admin:write');
      (targetRequest as Record<string, unknown>)[API_KEY_CONTEXT_PROPERTY] = {
        ...context,
        keyId: 'key_attacker',
      };
      await Promise.resolve();
    };
    const GuardCtor = ApiKeysGuard as unknown as {
      new (
        service: ApiKeysService,
        reflector: Reflector,
        contextWriter: (context: ApiKeyContext, request: unknown) => void | Promise<void>,
      ): ApiKeysGuard;
    };

    await expect(
      new GuardCtor(service, new Reflector(), contextWriter).canActivate(executionContext),
    ).resolves.toBe(true);

    const resolver = rbacIntegration.createApiKeySubjectResolver();
    expect(await resolver(executionContext)).toMatchObject({
      type: 'api_key',
      id: 'key_rbac',
      tenantId: 'tenant_rbac',
      attributes: request[API_KEY_CONTEXT_PROPERTY],
    });
    expect(request[API_KEY_CONTEXT_PROPERTY]).toMatchObject({
      keyId: 'key_rbac',
      tenantId: 'tenant_rbac',
      scopes: ['reports:read'],
    });
  });
});
