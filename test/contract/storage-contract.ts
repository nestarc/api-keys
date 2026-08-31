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
    allowedIpCidrs: ['203.0.113.0/24'],
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

const recordDateFields = [
  'lastUsedAt',
  'expiresAt',
  'revokedAt',
  'rotatedAt',
  'createdAt',
] as const;

function mutateRecordDates(record: ApiKeyRecord): void {
  for (const field of recordDateFields) {
    record[field]?.setUTCFullYear(2040);
  }
}

function recordDateValues(
  record: ApiKeyRecord,
): Record<(typeof recordDateFields)[number], number | null> {
  return Object.fromEntries(
    recordDateFields.map((field) => [field, record[field]?.getTime() ?? null]),
  ) as Record<(typeof recordDateFields)[number], number | null>;
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
      expect(found?.allowedIpCidrs).toEqual(['203.0.113.0/24']);
    });

    it('copies record dates when inserting', async () => {
      const record = fixture({
        lastUsedAt: new Date('2026-01-02T00:00:00Z'),
        expiresAt: new Date('2026-02-01T00:00:00Z'),
        revokedAt: new Date('2026-01-05T00:00:00Z'),
        rotatedAt: new Date('2026-01-04T00:00:00Z'),
      });
      const expectedDates = recordDateValues(record);

      await storage.insert(record);
      mutateRecordDates(record);

      const stored = await storage.findById(record.id);
      expect(stored).not.toBeNull();
      expect(recordDateValues(stored!)).toEqual(expectedDates);
    });

    it.each([
      ['findById', async (record: ApiKeyRecord) => storage.findById(record.id)],
      ['findByPrefix', async (record: ApiKeyRecord) => storage.findByPrefix(record.prefix)],
      [
        'listByTenant',
        async (record: ApiKeyRecord) =>
          (await storage.listByTenant(record.tenantId, { includeRevoked: true }))[0] ?? null,
      ],
    ] as const)('copies record dates returned by %s', async (_method, loadRecord) => {
      const record = fixture({
        lastUsedAt: new Date('2026-01-02T00:00:00Z'),
        expiresAt: new Date('2026-02-01T00:00:00Z'),
        revokedAt: new Date('2026-01-05T00:00:00Z'),
        rotatedAt: new Date('2026-01-04T00:00:00Z'),
      });
      const expectedDates = recordDateValues(record);
      await storage.insert(record);

      const returned = await loadRecord(record);
      expect(returned).not.toBeNull();
      mutateRecordDates(returned!);

      const stored = await storage.findById(record.id);
      expect(stored).not.toBeNull();
      expect(recordDateValues(stored!)).toEqual(expectedDates);
    });

    it('findByPrefix returns null when absent', async () => {
      await expect(storage.findByPrefix('missing______')).resolves.toBeNull();
    });

    it('findById returns the record when present', async () => {
      const record = fixture();

      await storage.insert(record);

      await expect(storage.findById(record.id)).resolves.toMatchObject({
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

    it('keeps non-revoked lifecycle history and orders newest records first', async () => {
      await storage.insert(
        fixture({
          id: 'active_b',
          prefix: 'activeb00000',
          createdAt: new Date('2026-01-04T00:00:00Z'),
        }),
      );
      await storage.insert(
        fixture({
          id: 'grace',
          prefix: 'grace0000000',
          expiresAt: new Date('2026-02-08T00:00:00Z'),
          rotatedAt: new Date('2026-02-01T00:00:00Z'),
          replacedByKeyId: 'replacement',
          createdAt: new Date('2026-01-02T00:00:00Z'),
        }),
      );
      await storage.insert(
        fixture({
          id: 'expired',
          prefix: 'expired00000',
          expiresAt: new Date('2026-02-01T00:00:00Z'),
          createdAt: new Date('2026-01-03T00:00:00Z'),
        }),
      );
      await storage.insert(
        fixture({
          id: 'revoked',
          prefix: 'revoked00000',
          revokedAt: new Date('2026-02-01T00:00:00Z'),
          createdAt: new Date('2026-01-05T00:00:00Z'),
        }),
      );
      await storage.insert(
        fixture({
          id: 'active_a',
          prefix: 'activea00000',
          createdAt: new Date('2026-01-04T00:00:00Z'),
        }),
      );

      const currentAndHistory = await storage.listByTenant('tenant_1');
      expect(currentAndHistory.map((record) => record.id)).toEqual([
        'active_a',
        'active_b',
        'expired',
        'grace',
      ]);

      const completeHistory = await storage.listByTenant('tenant_1', {
        includeRevoked: true,
      });
      expect(completeHistory.map((record) => record.id)).toEqual([
        'revoked',
        'active_a',
        'active_b',
        'expired',
        'grace',
      ]);
    });

    it('markRevoked sets revokedAt', async () => {
      const record = fixture();
      const revokedAt = new Date('2026-02-01T00:00:00Z');

      await storage.insert(record);
      await storage.markRevoked(record.id, revokedAt);

      const found = await storage.findByPrefix(record.prefix);
      expect(found?.revokedAt?.toISOString()).toBe(revokedAt.toISOString());
    });

    it('copies the Date passed to markRevoked', async () => {
      const record = fixture();
      const revokedAt = new Date('2026-02-01T00:00:00Z');

      await storage.insert(record);
      await storage.markRevoked(record.id, revokedAt);
      revokedAt.setUTCFullYear(2040);

      await expect(storage.findById(record.id)).resolves.toMatchObject({
        revokedAt: new Date('2026-02-01T00:00:00Z'),
      });
    });

    it('tenant-bound revoke mutates only the exact tenant record', async () => {
      const record = fixture({ tenantId: 'tenant_a' });
      const revokedAt = new Date('2026-02-01T00:00:00Z');
      await storage.insert(record);

      if (!storage.revokeForTenant) {
        throw new Error('built-in storage must implement revokeForTenant');
      }

      await expect(
        storage.revokeForTenant({
          keyId: record.id,
          expectedTenantId: 'tenant_b',
          revokedAt,
        }),
      ).resolves.toBe('not_found');
      await expect(storage.findById(record.id)).resolves.toMatchObject({ revokedAt: null });

      await expect(
        storage.revokeForTenant({
          keyId: record.id,
          expectedTenantId: 'tenant_a',
          revokedAt,
        }),
      ).resolves.toBe('revoked');
      await expect(storage.findById(record.id)).resolves.toMatchObject({ revokedAt });
    });

    it('copies the Date passed to tenant-bound revoke', async () => {
      const record = fixture({ tenantId: 'tenant_a' });
      const revokedAt = new Date('2026-02-01T00:00:00Z');
      await storage.insert(record);

      if (!storage.revokeForTenant) {
        throw new Error('built-in storage must implement revokeForTenant');
      }

      await storage.revokeForTenant({
        keyId: record.id,
        expectedTenantId: record.tenantId,
        revokedAt,
      });
      revokedAt.setUTCFullYear(2040);

      await expect(storage.findById(record.id)).resolves.toMatchObject({
        revokedAt: new Date('2026-02-01T00:00:00Z'),
      });
    });

    it('touchLastUsed updates lastUsedAt', async () => {
      const record = fixture();
      const lastUsedAt = new Date('2026-02-02T00:00:00Z');

      await storage.insert(record);
      await storage.touchLastUsed(record.id, lastUsedAt);

      const found = await storage.findByPrefix(record.prefix);
      expect(found?.lastUsedAt?.toISOString()).toBe(lastUsedAt.toISOString());
    });

    it('copies the Date passed to touchLastUsed', async () => {
      const record = fixture();
      const lastUsedAt = new Date('2026-02-02T00:00:00Z');

      await storage.insert(record);
      await storage.touchLastUsed(record.id, lastUsedAt);
      lastUsedAt.setUTCFullYear(2040);

      await expect(storage.findById(record.id)).resolves.toMatchObject({
        lastUsedAt: new Date('2026-02-02T00:00:00Z'),
      });
    });

    it('rotate inserts the new record and expires the old record', async () => {
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
      await expect(
        storage.rotate({
          oldKeyId: oldRecord.id,
          newRecord,
          oldExpiresAt,
          rotatedAt,
        }),
      ).resolves.toBe('rotated');

      const oldFound = await storage.findById(oldRecord.id);
      const newFound = await storage.findById(newRecord.id);

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

    it('copies all Date inputs passed to rotate', async () => {
      const oldRecord = fixture({ id: 'old_key', prefix: 'oldprefix001' });
      const newRecord = fixture({
        id: 'new_key',
        prefix: 'newprefix001',
        lastUsedAt: new Date('2026-01-12T00:00:00Z'),
        expiresAt: new Date('2026-04-01T00:00:00Z'),
        revokedAt: new Date('2026-01-15T00:00:00Z'),
        rotatedAt: new Date('2026-01-14T00:00:00Z'),
        createdAt: new Date('2026-01-10T00:00:00Z'),
      });
      const expectedNewRecordDates = recordDateValues(newRecord);
      const rotatedAt = new Date('2026-02-01T00:00:00Z');
      const oldExpiresAt = new Date('2026-02-08T00:00:00Z');

      await storage.insert(oldRecord);
      await expect(
        storage.rotate({ oldKeyId: oldRecord.id, newRecord, oldExpiresAt, rotatedAt }),
      ).resolves.toBe('rotated');

      mutateRecordDates(newRecord);
      oldExpiresAt.setUTCFullYear(2040);
      rotatedAt.setUTCFullYear(2040);

      const storedOldRecord = await storage.findById(oldRecord.id);
      const storedNewRecord = await storage.findById(newRecord.id);
      expect(storedOldRecord).toMatchObject({
        expiresAt: new Date('2026-02-08T00:00:00Z'),
        rotatedAt: new Date('2026-02-01T00:00:00Z'),
      });
      expect(storedNewRecord).not.toBeNull();
      expect(recordDateValues(storedNewRecord!)).toEqual(expectedNewRecordDates);
    });

    it('tenant-bound rotation atomically rejects a different tenant', async () => {
      const oldRecord = fixture({
        id: 'old_key',
        tenantId: 'tenant_a',
        prefix: 'oldprefix001',
      });
      const newRecord = fixture({
        id: 'new_key',
        tenantId: 'tenant_a',
        prefix: 'newprefix001',
      });
      await storage.insert(oldRecord);

      if (!storage.rotateForTenant) {
        throw new Error('built-in storage must implement rotateForTenant');
      }

      await expect(
        storage.rotateForTenant({
          oldKeyId: oldRecord.id,
          expectedTenantId: 'tenant_b',
          newRecord,
          oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
          rotatedAt: new Date('2026-02-01T00:00:00Z'),
        }),
      ).resolves.toBe('not_rotatable');
      await expect(storage.findById(oldRecord.id)).resolves.toEqual(oldRecord);
      await expect(storage.findById(newRecord.id)).resolves.toBeNull();
    });

    it('allows exactly one concurrent rotation and stores exactly one linked replacement', async () => {
      const oldRecord = fixture({ id: 'old_key', prefix: 'oldprefix001' });
      const rotatedAt = new Date('2026-02-01T00:00:00Z');
      const oldExpiresAt = new Date('2026-02-08T00:00:00Z');
      const attemptCount = 8;
      let readyCount = 0;
      let releaseBarrier: (() => void) | undefined;
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });

      await storage.insert(oldRecord);

      const attempts = Array.from({ length: attemptCount }, (_, index) =>
        (async () => {
          readyCount += 1;
          if (readyCount === attemptCount) {
            releaseBarrier?.();
          }
          await barrier;

          return storage.rotate({
            oldKeyId: oldRecord.id,
            newRecord: fixture({
              id: `new_key_${index}`,
              prefix: `newprefix${String(index).padStart(3, '0')}`,
            }),
            oldExpiresAt,
            rotatedAt,
          });
        })(),
      );

      const results = await Promise.all(attempts);
      expect(results.filter((result) => result === 'rotated')).toHaveLength(1);
      expect(results.filter((result) => result === 'not_rotatable')).toHaveLength(attemptCount - 1);

      const oldFound = await storage.findById(oldRecord.id);
      expect(oldFound?.replacedByKeyId).not.toBeNull();

      const storedReplacements = await Promise.all(
        Array.from({ length: attemptCount }, (_, index) => storage.findById(`new_key_${index}`)),
      );
      const replacements = storedReplacements.filter(
        (record): record is ApiKeyRecord => record !== null,
      );
      expect(replacements).toHaveLength(1);
      expect(replacements[0].id).toBe(oldFound?.replacedByKeyId);
    });

    it.each([
      ['missing', null],
      ['revoked', { revokedAt: new Date('2026-01-31T00:00:00Z') }],
      ['rotated', { rotatedAt: new Date('2026-01-31T00:00:00Z') }],
      ['replaced', { replacedByKeyId: 'existing_replacement' }],
      ['expired', { expiresAt: new Date('2026-02-01T00:00:00Z') }],
    ] as const)(
      'returns not_rotatable and stores no replacement when the old record is %s',
      async (state, overrides) => {
        const oldRecord = fixture({
          id: `old_${state}`,
          prefix: `old${state}`.padEnd(12, '0'),
          ...(overrides ?? {}),
        });
        const newRecord = fixture({
          id: `new_${state}`,
          prefix: `new${state}`.padEnd(12, '0'),
        });
        if (overrides !== null) {
          await storage.insert(oldRecord);
        }

        await expect(
          storage.rotate({
            oldKeyId: oldRecord.id,
            newRecord,
            oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
            rotatedAt: new Date('2026-02-01T00:00:00Z'),
          }),
        ).resolves.toBe('not_rotatable');
        await expect(storage.findById(newRecord.id)).resolves.toBeNull();
      },
    );
  });
}
