import type { ApiKeyRecord } from '../types';
import type {
  ApiKeyStorage,
  ListApiKeysOptions,
  RotateApiKeyStorageInput,
  RotateApiKeyStorageResult,
  TenantBoundRevokeApiKeyStorageInput,
  TenantBoundRevokeApiKeyStorageResult,
  TenantBoundRotateApiKeyStorageInput,
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

    this.records.set(record.id, cloneRecord(record));
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const record = this.records.get(id);
    return record ? cloneRecord(record) : null;
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    for (const record of this.records.values()) {
      if (record.prefix === prefix) {
        return cloneRecord(record);
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

    return visibleRecords.sort(compareRecordsForList).map(cloneRecord);
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    const record = this.records.get(id);
    if (!record) {
      throw new Error(`not found: ${id}`);
    }

    record.revokedAt = at;
  }

  async revokeForTenant(
    input: TenantBoundRevokeApiKeyStorageInput,
  ): Promise<TenantBoundRevokeApiKeyStorageResult> {
    const record = this.records.get(input.keyId);
    if (!record || record.tenantId !== input.expectedTenantId) {
      return 'not_found';
    }

    record.revokedAt = input.revokedAt;
    return 'revoked';
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    const record = this.records.get(id);
    if (!record) {
      throw new Error(`not found: ${id}`);
    }

    record.lastUsedAt = at;
  }

  async rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatchingTenant(input);
  }

  async rotateForTenant(
    input: TenantBoundRotateApiKeyStorageInput,
  ): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatchingTenant(input, input.expectedTenantId);
  }

  private rotateMatchingTenant(
    input: RotateApiKeyStorageInput,
    expectedTenantId?: string,
  ): RotateApiKeyStorageResult {
    const oldRecord = this.records.get(input.oldKeyId);
    if (
      !oldRecord ||
      (expectedTenantId !== undefined && oldRecord.tenantId !== expectedTenantId) ||
      (expectedTenantId !== undefined && input.newRecord.tenantId !== expectedTenantId) ||
      oldRecord.revokedAt !== null ||
      oldRecord.rotatedAt !== null ||
      oldRecord.replacedByKeyId !== null ||
      (oldRecord.expiresAt !== null &&
        oldRecord.expiresAt.getTime() <= input.rotatedAt.getTime())
    ) {
      return 'not_rotatable';
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
    this.records.set(input.newRecord.id, cloneRecord(input.newRecord));
    return 'rotated';
  }
}

function compareRecordsForList(left: ApiKeyRecord, right: ApiKeyRecord): number {
  const createdAtDifference = right.createdAt.getTime() - left.createdAt.getTime();
  if (createdAtDifference !== 0) {
    return createdAtDifference;
  }

  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function cloneRecord(record: ApiKeyRecord): ApiKeyRecord {
  return {
    ...record,
    scopes: [...record.scopes],
    allowedIpCidrs: [...(record.allowedIpCidrs ?? [])],
  };
}
