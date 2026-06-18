import type { ApiKeyRecord } from '../types';
import type {
  ApiKeyStorage,
  ListApiKeysOptions,
  RotateApiKeyStorageInput,
} from './api-key-storage.interface';

export class InMemoryApiKeyStorage implements ApiKeyStorage {
  private readonly records = new Map<string, ApiKeyRecord>();

  async insert(record: ApiKeyRecord): Promise<void> {
    if (this.records.has(record.id)) {
      throw new Error(`duplicate id: ${record.id}`);
    }

    if ([...this.records.values()].some((existingRecord) => existingRecord.prefix === record.prefix)) {
      throw new Error(`duplicate prefix: ${record.prefix}`);
    }

    this.records.set(record.id, { ...record });
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const record = this.records.get(id);
    return record ? { ...record } : null;
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
    opts: ListApiKeysOptions = {},
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

  async rotate(input: RotateApiKeyStorageInput): Promise<void> {
    const oldRecord = this.records.get(input.oldKeyId);
    if (!oldRecord) {
      throw new Error(`not found: ${input.oldKeyId}`);
    }

    if (this.records.has(input.newRecord.id)) {
      throw new Error(`duplicate id: ${input.newRecord.id}`);
    }

    if (
      [...this.records.values()].some(
        (existingRecord) => existingRecord.prefix === input.newRecord.prefix,
      )
    ) {
      throw new Error(`duplicate prefix: ${input.newRecord.prefix}`);
    }

    oldRecord.expiresAt = input.oldExpiresAt;
    oldRecord.rotatedAt = input.rotatedAt;
    oldRecord.replacedByKeyId = input.newRecord.id;
    this.records.set(input.newRecord.id, { ...input.newRecord });
  }
}
