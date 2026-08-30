import type { ApiKeyRecord } from '../types';

export interface ListApiKeysOptions {
  includeRevoked?: boolean;
}

export interface RotateApiKeyStorageInput {
  oldKeyId: string;
  newRecord: ApiKeyRecord;
  oldExpiresAt: Date;
  rotatedAt: Date;
}

export type RotateApiKeyStorageResult = 'rotated' | 'not_rotatable';

export interface ApiKeyStorage {
  insert(record: ApiKeyRecord): Promise<void>;
  findById(id: string): Promise<ApiKeyRecord | null>;
  findByPrefix(prefix: string): Promise<ApiKeyRecord | null>;
  listByTenant(tenantId: string, opts?: ListApiKeysOptions): Promise<ApiKeyRecord[]>;
  markRevoked(id: string, at: Date): Promise<void>;
  touchLastUsed(id: string, at: Date): Promise<void>;
  rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult>;
}
