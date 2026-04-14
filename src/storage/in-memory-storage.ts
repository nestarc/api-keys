import type { ApiKeyRecord } from '../types';
import type { ApiKeyStorage } from './api-key-storage.interface';

export class InMemoryApiKeyStorage implements ApiKeyStorage {
  private readonly records = new Map<string, ApiKeyRecord>();

  async insert(record: ApiKeyRecord): Promise<void> {
    if ([...this.records.values()].some((existingRecord) => existingRecord.prefix === record.prefix)) {
      throw new Error(`duplicate prefix: ${record.prefix}`);
    }

    this.records.set(record.id, { ...record });
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    for (const record of this.records.values()) {
      if (record.prefix === prefix) {
        return { ...record };
      }
    }

    return null;
  }

  async listByTenant(
    tenantId: string,
    opts: { includeRevoked?: boolean } = {},
  ): Promise<ApiKeyRecord[]> {
    const records = [...this.records.values()].filter((record) => record.tenantId === tenantId);
    const visibleRecords = opts.includeRevoked
      ? records
      : records.filter((record) => record.revokedAt === null);

    return visibleRecords.map((record) => ({ ...record }));
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    const record = this.records.get(id);
    if (!record) {
      throw new Error(`not found: ${id}`);
    }

    record.revokedAt = at;
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    const record = this.records.get(id);
    if (!record) {
      throw new Error(`not found: ${id}`);
    }

    record.lastUsedAt = at;
  }
}
