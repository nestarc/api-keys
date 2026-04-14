import type { ApiKeyStorage } from '../../src/storage/api-key-storage.interface';
import type { ApiKeyRecord } from '../../src/types';

function fixture(overrides: Partial<ApiKeyRecord> = {}): ApiKeyRecord {
  return {
    id: 'key_1',
    tenantId: 'tenant_1',
    name: 'primary',
    environment: 'live',
    prefix: 'abcdefghijkl',
    hash: 'f'.repeat(64),
    pepperVersion: 1,
    scopes: ['invoices:read'],
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    createdBy: null,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

export function storageContract(name: string, factory: () => ApiKeyStorage): void {
  describe(`ApiKeyStorage contract: ${name}`, () => {
    let storage: ApiKeyStorage;

    beforeEach(() => {
      storage = factory();
    });

    it('insert then findByPrefix returns the record', async () => {
      const record = fixture();

      await storage.insert(record);

      const found = await storage.findByPrefix(record.prefix);
      expect(found?.id).toBe('key_1');
    });

    it('findByPrefix returns null when absent', async () => {
      await expect(storage.findByPrefix('missing______')).resolves.toBeNull();
    });

    it('listByTenant excludes revoked by default', async () => {
      await storage.insert(fixture({ id: 'a', prefix: 'aaaaaaaaaaaa' }));
      await storage.insert(
        fixture({ id: 'b', prefix: 'bbbbbbbbbbbb', revokedAt: new Date('2026-01-02T00:00:00Z') }),
      );

      const listed = await storage.listByTenant('tenant_1');
      expect(listed.map((record) => record.id)).toEqual(['a']);
    });

    it('listByTenant includes revoked when opted in', async () => {
      await storage.insert(fixture({ id: 'a', prefix: 'aaaaaaaaaaaa' }));
      await storage.insert(
        fixture({ id: 'b', prefix: 'bbbbbbbbbbbb', revokedAt: new Date('2026-01-02T00:00:00Z') }),
      );

      const listed = await storage.listByTenant('tenant_1', { includeRevoked: true });
      expect(listed.map((record) => record.id).sort()).toEqual(['a', 'b']);
    });

    it('markRevoked sets revokedAt', async () => {
      const record = fixture();
      const revokedAt = new Date('2026-02-01T00:00:00Z');

      await storage.insert(record);
      await storage.markRevoked(record.id, revokedAt);

      const found = await storage.findByPrefix(record.prefix);
      expect(found?.revokedAt?.toISOString()).toBe(revokedAt.toISOString());
    });

    it('touchLastUsed updates lastUsedAt', async () => {
      const record = fixture();
      const lastUsedAt = new Date('2026-02-02T00:00:00Z');

      await storage.insert(record);
      await storage.touchLastUsed(record.id, lastUsedAt);

      const found = await storage.findByPrefix(record.prefix);
      expect(found?.lastUsedAt?.toISOString()).toBe(lastUsedAt.toISOString());
    });
  });
}
