import { randomUUID } from 'node:crypto';
import { ApiKeyError, ApiKeyErrorCode } from './errors';
import { generateKey, parseKey } from './key-format';
import { flattenScopes } from './scope-matcher';
import type { ApiKeyStorage } from './storage/api-key-storage.interface';
import type {
  ApiKeyContext,
  ApiKeyRecord,
  CreateApiKeyInput,
  CreateApiKeyResult,
} from './types';
import { Sha256Hasher } from './hasher';

export interface ApiKeysServiceDeps {
  storage: ApiKeyStorage;
  hasher: Sha256Hasher;
  namespace: string;
  idFactory?: () => string;
  clock?: () => Date;
  debounceMs?: number;
  onAuthFailed?: (prefix: string | null, code: string) => void;
}

export class ApiKeysService {
  private readonly storage: ApiKeyStorage;
  private readonly hasher: Sha256Hasher;
  private readonly namespace: string;
  private readonly idFactory: () => string;
  private readonly clock: () => Date;
  private readonly debounceMs: number;
  private readonly onAuthFailed: (prefix: string | null, code: string) => void;

  constructor(deps: ApiKeysServiceDeps) {
    this.storage = deps.storage;
    this.hasher = deps.hasher;
    this.namespace = deps.namespace;
    this.idFactory = deps.idFactory ?? (() => randomUUID());
    this.clock = deps.clock ?? (() => new Date());
    this.debounceMs = deps.debounceMs ?? 60_000;
    this.onAuthFailed = deps.onAuthFailed ?? (() => undefined);
  }

  async create(input: CreateApiKeyInput): Promise<CreateApiKeyResult> {
    const environment = input.environment ?? 'live';
    const scopes = flattenScopes(input.scopes);
    const generatedKey = generateKey({ namespace: this.namespace, environment });
    const hashed = this.hasher.hash(generatedKey.secret);

    const record: ApiKeyRecord = {
      id: this.idFactory(),
      tenantId: input.tenantId,
      name: input.name,
      environment,
      prefix: generatedKey.prefix,
      hash: hashed.hash,
      pepperVersion: hashed.pepperVersion,
      scopes,
      lastUsedAt: null,
      expiresAt: input.expiresAt ?? null,
      revokedAt: null,
      createdBy: input.createdBy ?? null,
      createdAt: this.clock(),
    };

    await this.storage.insert(record);

    return {
      id: record.id,
      key: generatedKey.raw,
    };
  }

  async verify(rawKey: string): Promise<ApiKeyContext> {
    let parsedKey;

    try {
      parsedKey = parseKey(rawKey);
    } catch (error) {
      this.onAuthFailed(null, ApiKeyErrorCode.Malformed);
      throw error;
    }

    if (parsedKey.namespace !== this.namespace) {
      this.hasher.dummyVerify(parsedKey.secret);
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    const record = await this.storage.findByPrefix(parsedKey.prefix);
    if (!record) {
      this.hasher.dummyVerify(parsedKey.secret);
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    if (record.revokedAt !== null) {
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Revoked);
      throw new ApiKeyError(ApiKeyErrorCode.Revoked);
    }

    if (record.expiresAt !== null && record.expiresAt.getTime() <= this.clock().getTime()) {
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Expired);
      throw new ApiKeyError(ApiKeyErrorCode.Expired);
    }

    const matches = this.hasher.verify(parsedKey.secret, record.hash, record.pepperVersion);
    if (!matches) {
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    void this.scheduleTouch(record);

    return {
      keyId: record.id,
      tenantId: record.tenantId,
      environment: record.environment,
      scopes: record.scopes,
    };
  }

  async revoke(id: string): Promise<void> {
    await this.storage.markRevoked(id, this.clock());
  }

  async list(
    tenantId: string,
    opts: { includeRevoked?: boolean } = {},
  ): Promise<ApiKeyRecord[]> {
    return this.storage.listByTenant(tenantId, opts);
  }

  private async scheduleTouch(record: ApiKeyRecord): Promise<void> {
    const now = this.clock();
    if (record.lastUsedAt && now.getTime() - record.lastUsedAt.getTime() < this.debounceMs) {
      return;
    }

    try {
      await this.storage.touchLastUsed(record.id, now);
    } catch {
      // Best-effort usage tracking should not break authentication.
    }
  }
}
