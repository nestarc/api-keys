import type { ApiKeyRecord } from '../types';

export interface ListApiKeysOptions {
  /** Include records with a non-null `revokedAt`. Expired and rotated records are always included. */
  includeRevoked?: boolean;
}

export interface RotateApiKeyStorageInput {
  oldKeyId: string;
  newRecord: ApiKeyRecord;
  oldExpiresAt: Date;
  rotatedAt: Date;
}

export interface TenantBoundRevokeApiKeyStorageInput {
  keyId: string;
  expectedTenantId: string;
  revokedAt: Date;
}

export type TenantBoundRevokeApiKeyStorageResult = 'revoked' | 'not_found';

export interface TenantBoundRotateApiKeyStorageInput extends RotateApiKeyStorageInput {
  expectedTenantId: string;
}

export type RotateApiKeyStorageResult = 'rotated' | 'not_rotatable';

export interface ApiKeyStorage {
  insert(record: ApiKeyRecord): Promise<void>;
  findById(id: string): Promise<ApiKeyRecord | null>;
  findByPrefix(prefix: string): Promise<ApiKeyRecord | null>;
  /** Return tenant records ordered by `createdAt` descending, then `id` ascending. */
  listByTenant(tenantId: string, opts?: ListApiKeysOptions): Promise<ApiKeyRecord[]>;
  markRevoked(id: string, at: Date): Promise<void>;
  revokeForTenant?(
    input: TenantBoundRevokeApiKeyStorageInput,
  ): Promise<TenantBoundRevokeApiKeyStorageResult>;
  touchLastUsed(id: string, at: Date): Promise<void>;
  rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult>;
  rotateForTenant?(
    input: TenantBoundRotateApiKeyStorageInput,
  ): Promise<RotateApiKeyStorageResult>;
}
