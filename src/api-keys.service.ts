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
  private static readonly CREATE_MAX_ATTEMPTS = 3;

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
    for (let attempt = 0; attempt < ApiKeysService.CREATE_MAX_ATTEMPTS; attempt += 1) {
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

      try {
        await this.storage.insert(record);
      } catch (error) {
        if (isDuplicatePrefixError(error) && attempt < ApiKeysService.CREATE_MAX_ATTEMPTS - 1) {
          continue;
        }

        throw error;
      }

      return {
        id: record.id,
        key: generatedKey.raw,
      };
    }

    throw new Error('failed to generate a unique API key prefix');
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

    let matches: boolean;
    try {
      matches = this.hasher.verify(parsedKey.secret, record.hash, record.pepperVersion);
    } catch {
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    if (!matches) {
      this.onAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    // Usage tracking is intentionally best-effort. A concurrent revoke may still win
    // after this verification and leave a later lastUsedAt update behind, which is
    // acceptable because it is telemetry and must not block successful auth.
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

function isDuplicatePrefixError(error: unknown): boolean {
  if (error instanceof Error && error.message.toLowerCase().includes('duplicate prefix')) {
    return true;
  }

  if (!error || typeof error !== 'object') {
    return false;
  }

  const prismaLikeError = error as {
    code?: unknown;
    meta?: { target?: unknown };
  };
  if (prismaLikeError.code !== 'P2002') {
    return false;
  }

  const target = prismaLikeError.meta?.target;
  return Array.isArray(target) && target.includes('prefix');
}
