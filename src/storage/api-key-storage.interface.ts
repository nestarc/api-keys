import type { ApiKeyRecord } from '../types';

export interface ApiKeyStorage {
  insert(record: ApiKeyRecord): Promise<void>;
  findByPrefix(prefix: string): Promise<ApiKeyRecord | null>;
  listByTenant(
    tenantId: string,
    opts?: { includeRevoked?: boolean },
  ): Promise<ApiKeyRecord[]>;
  markRevoked(id: string, at: Date): Promise<void>;
  touchLastUsed(id: string, at: Date): Promise<void>;
}
