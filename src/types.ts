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
  createdBy: string | null;
  createdAt: Date;
}

export interface ApiKeyContext {
  keyId: string;
  tenantId: string;
  environment: Environment;
  scopes: string[];
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
