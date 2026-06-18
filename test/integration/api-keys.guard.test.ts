import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ApiKeysGuard,
  API_KEY_CONTEXT_PROPERTY,
} from '../../src/api-keys.guard';
import { ApiKeysService } from '../../src/api-keys.service';
import { getApiKeyContext } from '../../src/context';
import { CurrentApiKey } from '../../src/decorators/current-api-key.decorator';
import { ENVIRONMENT_METADATA } from '../../src/decorators/require-environment.decorator';
import { SCOPE_METADATA } from '../../src/decorators/require-scope.decorator';
import { Sha256Hasher } from '../../src/hasher';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';
import type { ApiKeyContext } from '../../src/types';

function setup(contextWriter?: (apiKey: ApiKeyContext, request: unknown) => void | Promise<void>) {
  const storage = new InMemoryApiKeyStorage();
  const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
  const service = new ApiKeysService({ storage, hasher, namespace: 'nk' });
  const reflector = new Reflector();
  const GuardCtor = ApiKeysGuard as unknown as {
    new (
      service: ApiKeysService,
      reflector: Reflector,
      contextWriter?: (apiKey: ApiKeyContext, request: unknown) => void | Promise<void>,
    ): ApiKeysGuard;
  };
  const guard = new GuardCtor(service, reflector, contextWriter);

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
      prefix: expect.stringMatching(/^[A-Za-z0-9]{12}$/),
    });
    expect(getApiKeyContext(req)).toBe(req[API_KEY_CONTEXT_PROPERTY]);
    expect(typeof CurrentApiKey).toBe('function');
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

  it('runs contextWriter only after scope and environment checks pass', async () => {
    const contextWriter = jest.fn();
    const { guard, service, reflector } = setup(contextWriter);
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'reports', level: 'write' }],
    });

    jest.spyOn(reflector, 'getAllAndOverride').mockImplementation((metadataKey: unknown) => {
      return metadataKey === SCOPE_METADATA
        ? { resource: 'reports', level: 'read' }
        : undefined;
    });
    const executionContext = ctx({ authorization: `Bearer ${key}` });

    await expect(guard.canActivate(executionContext)).resolves.toBe(true);
    expect(contextWriter).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId: 't1',
        scopes: ['reports:write'],
        prefix: expect.stringMatching(/^[A-Za-z0-9]{12}$/),
      }),
      executionContext.switchToHttp().getRequest(),
    );

    contextWriter.mockClear();
    jest.spyOn(reflector, 'getAllAndOverride').mockImplementation((metadataKey: unknown) => {
      return metadataKey === SCOPE_METADATA
        ? { resource: 'reports', level: 'write' }
        : 'test';
    });

    await expect(guard.canActivate(ctx({ authorization: `Bearer ${key}` }))).rejects.toMatchObject({
      code: 'api_key_environment_mismatch',
    });
    expect(contextWriter).not.toHaveBeenCalled();
  });
});
