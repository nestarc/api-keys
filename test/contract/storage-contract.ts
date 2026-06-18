import type { ApiKeyStorage } from '../../src/storage/api-key-storage.interface';
import type { ApiKeyRecord } from '../../src/types';

interface RotatableStorage extends ApiKeyStorage {
  findById(id: string): Promise<ApiKeyRecord | null>;
  rotate(input: {
    oldKeyId: string;
    newRecord: ApiKeyRecord;
    oldExpiresAt: Date;
    rotatedAt: Date;
  }): Promise<void>;
}

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
    rotatedAt: null,
    replacedByKeyId: null,
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

    it('findById returns the record when present', async () => {
      const rotatable = storage as RotatableStorage;
      const record = fixture();

      await storage.insert(record);

      await expect(rotatable.findById(record.id)).resolves.toMatchObject({
        id: record.id,
        prefix: record.prefix,
      });
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

    it('rotate inserts the new record and expires the old record', async () => {
      const rotatable = storage as RotatableStorage;
      const oldRecord = fixture({
        id: 'old_key',
        prefix: 'oldprefix001',
      });
      const newRecord = fixture({
        id: 'new_key',
        prefix: 'newprefix001',
        name: 'rotated',
      });
      const rotatedAt = new Date('2026-02-01T00:00:00Z');
      const oldExpiresAt = new Date('2026-02-08T00:00:00Z');

      await storage.insert(oldRecord);
      await rotatable.rotate({
        oldKeyId: oldRecord.id,
        newRecord,
        oldExpiresAt,
        rotatedAt,
      });

      const oldFound = await rotatable.findById(oldRecord.id);
      const newFound = await rotatable.findById(newRecord.id);

      expect(oldFound).toMatchObject({
        id: oldRecord.id,
        expiresAt: oldExpiresAt,
        rotatedAt,
        replacedByKeyId: newRecord.id,
      });
      expect(newFound).toMatchObject({
        id: newRecord.id,
        prefix: newRecord.prefix,
        rotatedAt: null,
        replacedByKeyId: null,
      });
    });
  });
}
