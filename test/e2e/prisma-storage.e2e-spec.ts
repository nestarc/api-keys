import { PrismaApiKeyStorage, type PrismaLike } from '../../src/storage/prisma-storage';
import type { ApiKeyRecord } from '../../src/types';
import { storageContract } from '../contract/storage-contract';
import { PrismaClient } from './generated/prisma-client';

const prisma = new PrismaClient();

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

describe('PrismaApiKeyStorage PostgreSQL contract', () => {
  beforeAll(async () => {
    await prisma.$connect();
  });

  beforeEach(async () => {
    await prisma.apiKey.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  const createStorage = () => new PrismaApiKeyStorage(prisma as unknown as PrismaLike);

  storageContract('Prisma PostgreSQL', createStorage);

  it('maps dates, scopes, and allowed CIDRs without losing values', async () => {
    const storage = createStorage();
    const record = fixture({
      scopes: ['invoices:read', 'invoices:write'],
      allowedIpCidrs: ['203.0.113.0/24', '2001:db8::/48'],
      lastUsedAt: new Date('2026-02-01T01:02:03.000Z'),
      expiresAt: new Date('2026-03-01T01:02:03.000Z'),
      revokedAt: new Date('2026-02-15T01:02:03.000Z'),
      rotatedAt: new Date('2026-02-10T01:02:03.000Z'),
      createdAt: new Date('2026-01-15T01:02:03.000Z'),
    });

    await storage.insert(record);

    await expect(storage.findById(record.id)).resolves.toEqual(record);
  });

  it('never mixes records from different tenants', async () => {
    const storage = createStorage();
    await storage.insert(
      fixture({ id: 'tenant_a_key', tenantId: 'tenant_a', prefix: 'tenantakey01' }),
    );
    await storage.insert(
      fixture({ id: 'tenant_b_key', tenantId: 'tenant_b', prefix: 'tenantbkey01' }),
    );

    const tenantARecords = await storage.listByTenant('tenant_a');

    expect(tenantARecords.map((record) => record.id)).toEqual(['tenant_a_key']);
  });

  it('rolls back the new key when the old-key update fails during rotation', async () => {
    const storage = createStorage();
    const oldRecord = fixture({ id: 'old_key', prefix: 'oldprefix001' });
    const newRecord = fixture({ id: 'new_key', prefix: 'newprefix001' });
    await storage.insert(oldRecord);

    await expect(
      storage.rotate({
        oldKeyId: 'missing_old_key',
        newRecord,
        oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
        rotatedAt: new Date('2026-02-01T00:00:00Z'),
      }),
    ).rejects.toThrow();

    await expect(storage.findById(newRecord.id)).resolves.toBeNull();
    await expect(storage.findById(oldRecord.id)).resolves.toEqual(oldRecord);
  });
});
