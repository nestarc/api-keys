import { ApiKeysService } from './api-keys.service';
import { Sha256Hasher } from './hasher';
import { InMemoryApiKeyStorage } from './storage/in-memory-storage';
import { createTestKey } from './testing';

function service(): ApiKeysService {
  return new ApiKeysService({
    storage: new InMemoryApiKeyStorage(),
    hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
    namespace: 'testkey',
  });
}

describe('createTestKey', () => {
  it('creates a useful test key with safe defaults', async () => {
    const result = await createTestKey(service());

    expect(result.key).toMatch(/^testkey_test_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);
    expect(result.context).toMatchObject({
      keyId: result.id,
      tenantId: 'tenant_test',
      environment: 'test',
      scopes: ['test:write'],
      allowedIpCidrs: [],
    });
  });

  it('passes consumer overrides through create and verify', async () => {
    const expiresAt = new Date('2030-01-01T00:00:00Z');
    const result = await createTestKey(service(), {
      tenantId: 'tenant_custom',
      name: 'Fixture key',
      environment: 'live',
      scopes: [{ resource: 'reports', level: 'read' }],
      expiresAt,
      createdBy: 'test_suite',
      allowedIpCidrs: ['203.0.113.42'],
    });

    expect(result.context).toMatchObject({
      tenantId: 'tenant_custom',
      environment: 'live',
      scopes: ['reports:read'],
      allowedIpCidrs: ['203.0.113.42/32'],
    });
  });
});
