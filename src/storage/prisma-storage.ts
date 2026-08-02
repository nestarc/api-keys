import type { ApiKeyRecord, Environment } from '../types';
import type {
  ApiKeyStorage,
  ListApiKeysOptions,
  RotateApiKeyStorageInput,
} from './api-key-storage.interface';

export interface PrismaLike {
  apiKey: {
    create(args: { data: unknown }): Promise<unknown>;
    findUnique(args: { where: { prefix: string } | { id: string } }): Promise<unknown>;
    findMany(args: { where: unknown; orderBy?: unknown }): Promise<unknown[]>;
    update(args: { where: { id: string }; data: unknown }): Promise<unknown>;
  };
  $transaction?<T>(operations: Promise<T>[]): Promise<T[]>;
}

export class PrismaApiKeyStorage implements ApiKeyStorage {
  constructor(private readonly prisma: PrismaLike) {}

  async insert(record: ApiKeyRecord): Promise<void> {
    await this.prisma.apiKey.create({ data: record });
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const row = (await this.prisma.apiKey.findUnique({ where: { id } })) as ApiKeyRecord | null;

    if (!row) {
      return null;
    }

    return mapRow(row);
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    const row = (await this.prisma.apiKey.findUnique({ where: { prefix } })) as ApiKeyRecord | null;

    if (!row) {
      return null;
    }

    return mapRow(row);
  }

  async listByTenant(
    tenantId: string,
    opts: ListApiKeysOptions = {},
  ): Promise<ApiKeyRecord[]> {
    const where: Record<string, unknown> = { tenantId };
    if (!opts.includeRevoked) {
      where.revokedAt = null;
    }

    const rows = (await this.prisma.apiKey.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    })) as ApiKeyRecord[];

    return rows.map(mapRow);
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { revokedAt: at } });
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { lastUsedAt: at } });
  }

  async rotate(input: RotateApiKeyStorageInput): Promise<void> {
    const createNew = this.prisma.apiKey.create({ data: input.newRecord });
    const updateOld = this.prisma.apiKey.update({
      where: { id: input.oldKeyId },
      data: {
        expiresAt: input.oldExpiresAt,
        rotatedAt: input.rotatedAt,
        replacedByKeyId: input.newRecord.id,
      },
    });

    if (this.prisma.$transaction) {
      await this.prisma.$transaction([createNew, updateOld]);
      return;
    }

    await createNew;
    await updateOld;
  }
}

function mapRow(row: ApiKeyRecord): ApiKeyRecord {
  return {
    ...row,
    environment: row.environment as Environment,
    scopes: [...row.scopes],
    allowedIpCidrs: [...(row.allowedIpCidrs ?? [])],
  };
}
