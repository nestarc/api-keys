import { createRequire } from 'node:module';
import path from 'node:path';
import { ApiKeysService } from '../../src/api-keys.service';
import { ApiKeyErrorCode } from '../../src/errors';
import { Sha256Hasher } from '../../src/hasher';
import { PrismaApiKeyStorage, type PrismaLike } from '../../src/storage/prisma-storage';
import type { ApiKeyRecord } from '../../src/types';
import { storageContract } from '../contract/storage-contract';

type E2ePrismaClient = PrismaLike & {
  apiKey: PrismaLike['apiKey'] & { deleteMany(): Promise<unknown> };
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;
};

type PrismaClientConstructor = new (options?: unknown) => E2ePrismaClient;
type PrismaPgConstructor = new (options: { connectionString: string }) => unknown;
type GeneratedPrismaModule = {
  PrismaClient: PrismaClientConstructor;
  Prisma: { prismaVersion: { client: string } };
};
const loadModule = createRequire(__filename);

function createPrismaClient(): E2ePrismaClient {
  const major = Number.parseInt(process.env.PRISMA_E2E_MAJOR ?? '', 10);
  if (![5, 6, 7].includes(major)) {
    throw new Error(`PRISMA_E2E_MAJOR must be 5, 6, or 7; received ${String(major)}`);
  }

  const generatedEntry = path.join(
    __dirname,
    'generated',
    'prisma-client',
    major === 7 ? 'client' : 'index',
  );
  const generatedPrisma = loadModule(generatedEntry) as GeneratedPrismaModule;
  const expectedVersion = process.env.PRISMA_E2E_VERSION;
  if (!expectedVersion || generatedPrisma.Prisma.prismaVersion.client !== expectedVersion) {
    throw new Error(
      `Generated Prisma client version ${generatedPrisma.Prisma.prismaVersion.client} ` +
        `does not match expected ${expectedVersion ?? '<missing>'}`,
    );
  }
  const { PrismaClient } = generatedPrisma;

  if (major !== 7) {
    return new PrismaClient();
  }

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is required for the Prisma 7 PostgreSQL adapter');
  }
  const adapterLoader = process.env.PRISMA_E2E_RUNTIME_ROOT
    ? createRequire(path.join(process.env.PRISMA_E2E_RUNTIME_ROOT, 'package.json'))
    : loadModule;
  const { PrismaPg } = adapterLoader('@prisma/adapter-pg') as {
    PrismaPg: PrismaPgConstructor;
  };
  return new PrismaClient({ adapter: new PrismaPg({ connectionString }) });
}

const prisma = createPrismaClient();

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

  it('rejects a credential whose raw environment differs from its stored environment', async () => {
    const storage = createStorage();
    const service = new ApiKeysService({
      storage,
      hasher: new Sha256Hasher({
        peppers: { 1: 'prisma-environment-binding-pepper' },
        currentVersion: 1,
      }),
      namespace: 'nk',
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    });
    const created = await service.create({
      tenantId: 'tenant_environment_binding',
      name: 'environment binding',
      environment: 'test',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    const tampered = created.key.replace('_test_', '_live_');

    await expect(service.verify(tampered)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Invalid,
    });
    await expect(storage.findById(created.id)).resolves.toMatchObject({
      environment: 'test',
      lastUsedAt: null,
    });
  });

  it('returns not_rotatable without creating a key when the old key is missing', async () => {
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
    ).resolves.toBe('not_rotatable');

    await expect(storage.findById(newRecord.id)).resolves.toBeNull();
    await expect(storage.findById(oldRecord.id)).resolves.toEqual(oldRecord);
  });

  it('rolls back the old-key claim when replacement creation fails', async () => {
    const storage = createStorage();
    const oldRecord = fixture({ id: 'old_key', prefix: 'oldprefix001' });
    const conflictingRecord = fixture({ id: 'conflicting_key', prefix: 'newprefix001' });
    const newRecord = fixture({ id: 'new_key', prefix: conflictingRecord.prefix });
    await storage.insert(oldRecord);
    await storage.insert(conflictingRecord);

    await expect(
      storage.rotate({
        oldKeyId: oldRecord.id,
        newRecord,
        oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
        rotatedAt: new Date('2026-02-01T00:00:00Z'),
      }),
    ).rejects.toThrow();

    await expect(storage.findById(oldRecord.id)).resolves.toEqual(oldRecord);
    await expect(storage.findById(newRecord.id)).resolves.toBeNull();
  });
});
