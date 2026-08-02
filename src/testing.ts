import type { ApiKeysService } from './api-keys.service';
import type { ApiKeyContext, CreateApiKeyResult, Environment, Scope } from './types';

export interface CreateTestKeyOptions {
  tenantId?: string;
  name?: string;
  environment?: Environment;
  scopes?: Scope[];
  expiresAt?: Date;
  createdBy?: string;
  allowedIpCidrs?: string[];
}

export async function createTestKey(
  service: ApiKeysService,
  options: CreateTestKeyOptions = {},
): Promise<CreateApiKeyResult & { context: ApiKeyContext }> {
  const created = await service.create({
    tenantId: options.tenantId ?? 'tenant_test',
    name: options.name ?? 'Test API key',
    environment: options.environment ?? 'test',
    scopes: options.scopes ?? [{ resource: 'test', level: 'write' }],
    expiresAt: options.expiresAt,
    createdBy: options.createdBy,
    allowedIpCidrs: options.allowedIpCidrs,
  });
  const context = await service.verify(created.key);

  return { ...created, context };
}
