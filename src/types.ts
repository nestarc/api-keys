import type { ApiKeyErrorCode } from './errors';

export type Environment = 'live' | 'test';

export type ScopeLevel = 'read' | 'write';

export interface Scope {
  resource: string;
  level: ScopeLevel;
}

export interface ApiKeyRecord {
  id: string;
  tenantId: string;
  name: string;
  environment: Environment;
  prefix: string;
  hash: string;
  pepperVersion: number;
  scopes: string[];
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  rotatedAt: Date | null;
  replacedByKeyId: string | null;
  createdBy: string | null;
  createdAt: Date;
}

export interface ApiKeyContext {
  keyId: string;
  tenantId: string;
  environment: Environment;
  scopes: string[];
  prefix: string;
}

export interface CreateApiKeyInput {
  tenantId: string;
  name: string;
  environment?: Environment;
  scopes: Scope[];
  expiresAt?: Date;
  createdBy?: string;
}

export interface CreateApiKeyResult {
  id: string;
  key: string;
}

export interface RotateApiKeyInput {
  gracePeriodMs?: number;
  name?: string;
  createdBy?: string;
  expiresAt?: Date | null;
}

export interface RotateApiKeyResult {
  id: string;
  key: string;
  replacedKeyId: string;
  graceExpiresAt: Date;
}

export interface ApiKeyEventBase {
  at: Date;
}

export interface ApiKeyCreatedEvent extends ApiKeyEventBase {
  type: 'api_key.created';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
  scopes: string[];
  createdBy: string | null;
}

export interface ApiKeyRevokedEvent extends ApiKeyEventBase {
  type: 'api_key.revoked';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
}

export interface ApiKeyRotatedEvent extends ApiKeyEventBase {
  type: 'api_key.rotated';
  tenantId: string;
  oldKeyId: string;
  oldPrefix: string;
  newKeyId: string;
  newPrefix: string;
  environment: Environment;
  scopes: string[];
  graceExpiresAt: Date;
  createdBy: string | null;
}

export interface ApiKeyAuthFailedEvent extends ApiKeyEventBase {
  type: 'api_key.auth_failed';
  prefix: string | null;
  code: ApiKeyErrorCode;
  tenantId?: string;
  keyId?: string;
  environment?: Environment;
}

export interface ApiKeyUsedEvent extends ApiKeyEventBase {
  type: 'api_key.used';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
  scopes: string[];
}

export type ApiKeyEvent =
  | ApiKeyCreatedEvent
  | ApiKeyRevokedEvent
  | ApiKeyRotatedEvent
  | ApiKeyAuthFailedEvent
  | ApiKeyUsedEvent;

export type ApiKeyEventSink = (event: ApiKeyEvent) => void | Promise<void>;

export interface ApiKeyTtlPolicy {
  defaultExpiresInMs?: number;
  maxExpiresInMs?: number;
  allowNeverExpires?: boolean;
}
