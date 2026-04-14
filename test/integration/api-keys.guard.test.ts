import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ApiKeysGuard,
  API_KEY_CONTEXT_PROPERTY,
} from '../../src/api-keys.guard';
import { ApiKeysService } from '../../src/api-keys.service';
import { ENVIRONMENT_METADATA } from '../../src/decorators/require-environment.decorator';
import { SCOPE_METADATA } from '../../src/decorators/require-scope.decorator';
import { Sha256Hasher } from '../../src/hasher';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';

function setup() {
  const storage = new InMemoryApiKeyStorage();
  const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
  const service = new ApiKeysService({ storage, hasher, namespace: 'nk' });
  const reflector = new Reflector();
  const guard = new ApiKeysGuard(service, reflector);

  return { guard, service, reflector };
}

function ctx(
  headers: Record<string, string>,
  handler = () => undefined,
  cls = class {},
): ExecutionContext {
  const req: Record<string, unknown> = { headers };

  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => handler,
    getClass: () => cls,
  } as unknown as ExecutionContext;
}

describe('ApiKeysGuard', () => {
  it('rejects request with no authorization header', async () => {
    const { guard } = setup();

    await expect(guard.canActivate(ctx({}))).rejects.toMatchObject({
      code: 'api_key_missing',
    });
  });

  it('accepts valid key and attaches context to request', async () => {
    const { guard, service } = setup();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'invoices', level: 'write' }],
    });

    const executionContext = ctx({ authorization: `Bearer ${key}` });
    const result = await guard.canActivate(executionContext);
    expect(result).toBe(true);

    const req = executionContext.switchToHttp().getRequest() as Record<string, unknown>;
    expect(req[API_KEY_CONTEXT_PROPERTY]).toMatchObject({
      tenantId: 't1',
      scopes: ['invoices:write'],
      environment: 'live',
    });
  });

  it('enforces @RequireScope', async () => {
    const { guard, service, reflector } = setup();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'invoices', level: 'read' }],
    });

    jest.spyOn(reflector, 'getAllAndOverride').mockImplementation((metadataKey: unknown) => {
      return metadataKey === SCOPE_METADATA
        ? { resource: 'invoices', level: 'write' }
        : undefined;
    });

    await expect(guard.canActivate(ctx({ authorization: `Bearer ${key}` }))).rejects.toMatchObject({
      code: 'api_key_scope_insufficient',
    });
  });

  it('enforces @RequireEnvironment', async () => {
    const { guard, service, reflector } = setup();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      environment: 'test',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    jest.spyOn(reflector, 'getAllAndOverride').mockImplementation((metadataKey: unknown) => {
      return metadataKey === ENVIRONMENT_METADATA ? 'live' : undefined;
    });

    await expect(guard.canActivate(ctx({ authorization: `Bearer ${key}` }))).rejects.toMatchObject({
      code: 'api_key_environment_mismatch',
    });
  });
});
