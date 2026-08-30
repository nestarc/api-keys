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
import type { ApiKeyClientIpResolver } from '../../src/ip-allowlist';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';
import type { ApiKeyContext } from '../../src/types';

function setup(
  options: {
    contextWriter?: (apiKey: ApiKeyContext, request: unknown) => void | Promise<void>;
    clientIpResolver?: ApiKeyClientIpResolver;
  } = {},
) {
  const storage = new InMemoryApiKeyStorage();
  const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
  const service = new ApiKeysService({ storage, hasher, namespace: 'nk' });
  const reflector = new Reflector();
  const GuardCtor = ApiKeysGuard as unknown as {
    new (
      service: ApiKeysService,
      reflector: Reflector,
      contextWriter?: (apiKey: ApiKeyContext, request: unknown) => void | Promise<void>,
      clientIpResolver?: ApiKeyClientIpResolver,
    ): ApiKeysGuard;
  };
  const guard = new GuardCtor(service, reflector, options.contextWriter, options.clientIpResolver);

  return { guard, service, reflector };
}

function ctx(
  headers: Record<string, string>,
  handler = () => undefined,
  cls = class {},
  requestOverrides: Record<string, unknown> = {},
): ExecutionContext {
  const req: Record<string, unknown> = { headers, ...requestOverrides };

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
    const { guard, service, reflector } = setup({ contextWriter });
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

  it('preserves the verified downstream identity when contextWriter mutates its context and request', async () => {
    const contextWriter = jest.fn(
      async (writerContext: ApiKeyContext, request: unknown) => {
        writerContext.keyId = 'key_attacker';
        writerContext.tenantId = 'tenant_attacker';
        writerContext.environment = 'test';
        writerContext.scopes.splice(0, writerContext.scopes.length, 'admin:write');
        writerContext.allowedIpCidrs?.splice(
          0,
          writerContext.allowedIpCidrs.length,
          '198.51.100.0/24',
        );
        (request as Record<string, unknown>)[API_KEY_CONTEXT_PROPERTY] = {
          ...writerContext,
          prefix: 'attackerpref',
        };
        await Promise.resolve();
        writerContext.scopes.push('billing:write');
      },
    );
    const { guard, service, reflector } = setup({ contextWriter });
    const { id, key } = await service.create({
      tenantId: 'tenant_verified',
      name: 'writer isolation',
      scopes: [{ resource: 'reports', level: 'read' }],
      allowedIpCidrs: ['203.0.113.0/24'],
    });
    jest.spyOn(reflector, 'getAllAndOverride').mockImplementation((metadataKey: unknown) => {
      return metadataKey === SCOPE_METADATA
        ? { resource: 'reports', level: 'read' }
        : undefined;
    });
    const executionContext = ctx(
      { authorization: `Bearer ${key}` },
      () => undefined,
      class {},
      { ip: '203.0.113.42' },
    );

    await expect(guard.canActivate(executionContext)).resolves.toBe(true);

    const request = executionContext.switchToHttp().getRequest() as Record<string, unknown>;
    const downstreamContext = getApiKeyContext(request);
    expect(downstreamContext).toMatchObject({
      keyId: id,
      tenantId: 'tenant_verified',
      environment: 'live',
      scopes: ['reports:read'],
      allowedIpCidrs: ['203.0.113.0/24'],
      prefix: expect.stringMatching(/^[A-Za-z0-9]{12}$/),
    });
    expect(downstreamContext?.scopes).not.toContain('admin:write');
    expect(downstreamContext?.scopes).not.toContain('billing:write');
    expect(contextWriter.mock.calls[0]?.[0]).not.toBe(downstreamContext);
  });

  it('enforces a key IP allowlist using request.ip by default', async () => {
    const { guard, service } = setup();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'restricted',
      scopes: [{ resource: 'reports', level: 'read' }],
      allowedIpCidrs: ['203.0.113.0/24'],
    });

    await expect(
      guard.canActivate(
        ctx({ authorization: `Bearer ${key}` }, () => undefined, class {}, { ip: '203.0.113.42' }),
      ),
    ).resolves.toBe(true);

    await expect(
      guard.canActivate(
        ctx({ authorization: `Bearer ${key}` }, () => undefined, class {}, { ip: '198.51.100.1' }),
      ),
    ).rejects.toMatchObject({ code: 'api_key_ip_not_allowed', httpStatus: 403 });

    await expect(guard.canActivate(ctx({ authorization: `Bearer ${key}` }))).rejects.toMatchObject({
      code: 'api_key_ip_not_allowed',
    });
  });

  it('supports a custom clientIpResolver', async () => {
    const clientIpResolver = jest.fn().mockResolvedValue('2001:db8::42');
    const { guard, service } = setup({ clientIpResolver });
    const { key } = await service.create({
      tenantId: 't1',
      name: 'restricted',
      scopes: [{ resource: 'reports', level: 'read' }],
      allowedIpCidrs: ['2001:db8::/48'],
    });
    const executionContext = ctx({ authorization: `Bearer ${key}` });

    await expect(guard.canActivate(executionContext)).resolves.toBe(true);
    expect(clientIpResolver).toHaveBeenCalledWith(executionContext.switchToHttp().getRequest());
  });
});
