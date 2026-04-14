import type { ApiKeyRecord, Environment } from '../types';
import type { ApiKeyStorage } from './api-key-storage.interface';

export interface PrismaLike {
  apiKey: {
    create(args: { data: unknown }): Promise<unknown>;
    findUnique(args: { where: { prefix: string } }): Promise<unknown>;
    findMany(args: { where: unknown; orderBy?: unknown }): Promise<unknown[]>;
    update(args: { where: { id: string }; data: unknown }): Promise<unknown>;
  };
}

export class PrismaApiKeyStorage implements ApiKeyStorage {
  constructor(private readonly prisma: PrismaLike) {}

  async insert(record: ApiKeyRecord): Promise<void> {
    await this.prisma.apiKey.create({ data: record });
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    const row = (await this.prisma.apiKey.findUnique({ where: { prefix } })) as ApiKeyRecord | null;

    if (!row) {
      return null;
    }

    return {
      ...row,
      environment: row.environment as Environment,
    };
  }

  async listByTenant(
    tenantId: string,
    opts: { includeRevoked?: boolean } = {},
  ): Promise<ApiKeyRecord[]> {
    const where: Record<string, unknown> = { tenantId };
    if (!opts.includeRevoked) {
      where.revokedAt = null;
    }

    const rows = (await this.prisma.apiKey.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    })) as ApiKeyRecord[];

    return rows.map((row) => ({
      ...row,
      environment: row.environment as Environment,
    }));
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { revokedAt: at } });
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { lastUsedAt: at } });
  }
}
