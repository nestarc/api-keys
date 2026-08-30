import type { ApiKeyRecord, Environment } from '../types';
import type {
  ApiKeyStorage,
  ListApiKeysOptions,
  RotateApiKeyStorageInput,
  RotateApiKeyStorageResult,
  TenantBoundRevokeApiKeyStorageInput,
  TenantBoundRevokeApiKeyStorageResult,
  TenantBoundRotateApiKeyStorageInput,
} from './api-key-storage.interface';

interface PrismaApiKeyDelegate {
  create(args: { data: unknown }): Promise<unknown>;
  findUnique(args: { where: { prefix: string } | { id: string } }): Promise<unknown>;
  findMany(args: { where: unknown; orderBy?: unknown }): Promise<unknown[]>;
  update(args: { where: { id: string }; data: unknown }): Promise<unknown>;
  updateMany(args: { where: unknown; data: unknown }): Promise<{ count: number }>;
}

export interface PrismaTransactionLike {
  apiKey: PrismaApiKeyDelegate;
}

export interface PrismaLike extends PrismaTransactionLike {
  $transaction<T>(callback: (transaction: PrismaTransactionLike) => Promise<T>): Promise<T>;
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

  async revokeForTenant(
    input: TenantBoundRevokeApiKeyStorageInput,
  ): Promise<TenantBoundRevokeApiKeyStorageResult> {
    const result = await this.prisma.apiKey.updateMany({
      where: { id: input.keyId, tenantId: input.expectedTenantId },
      data: { revokedAt: input.revokedAt },
    });
    return result.count === 1 ? 'revoked' : 'not_found';
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { lastUsedAt: at } });
  }

  async rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatchingTenant(input);
  }

  async rotateForTenant(
    input: TenantBoundRotateApiKeyStorageInput,
  ): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatchingTenant(input, input.expectedTenantId);
  }

  private async rotateMatchingTenant(
    input: RotateApiKeyStorageInput,
    expectedTenantId?: string,
  ): Promise<RotateApiKeyStorageResult> {
    if (expectedTenantId !== undefined && input.newRecord.tenantId !== expectedTenantId) {
      return 'not_rotatable';
    }

    if (typeof this.prisma.$transaction !== 'function') {
      throw new Error(
        'PrismaApiKeyStorage.rotate() requires interactive transaction support',
      );
    }

    return this.prisma.$transaction(async (transaction) => {
      const claimed = await transaction.apiKey.updateMany({
        where: {
          id: input.oldKeyId,
          ...(expectedTenantId !== undefined ? { tenantId: expectedTenantId } : {}),
          revokedAt: null,
          rotatedAt: null,
          replacedByKeyId: null,
          OR: [{ expiresAt: null }, { expiresAt: { gt: input.rotatedAt } }],
        },
        data: {
          expiresAt: input.oldExpiresAt,
          rotatedAt: input.rotatedAt,
          replacedByKeyId: input.newRecord.id,
        },
      });

      if (claimed.count !== 1) {
        return 'not_rotatable';
      }

      await transaction.apiKey.create({ data: input.newRecord });
      return 'rotated';
    });
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
