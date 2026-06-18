import { randomUUID } from 'node:crypto';
import {
  ApiKeyError,
  ApiKeyErrorCode,
  ApiKeyOperationError,
  ApiKeyOperationErrorCode,
} from './errors';
import { generateKey, parseKey } from './key-format';
import { flattenScopes } from './scope-matcher';
import type { ApiKeyStorage } from './storage/api-key-storage.interface';
import type {
  ApiKeyContext,
  ApiKeyEvent,
  ApiKeyEventSink,
  ApiKeyTtlPolicy,
  ApiKeyRecord,
  CreateApiKeyInput,
  CreateApiKeyResult,
  RotateApiKeyInput,
  RotateApiKeyResult,
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
  onEvent?: ApiKeyEventSink;
  onEventError?: (error: unknown, event: ApiKeyEvent) => void;
  emitUsageEvents?: boolean;
  ttlPolicy?: ApiKeyTtlPolicy;
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
  private readonly onEvent?: ApiKeyEventSink;
  private readonly onEventError?: (error: unknown, event: ApiKeyEvent) => void;
  private readonly emitUsageEvents: boolean;
  private readonly ttlPolicy?: ApiKeyTtlPolicy;

  constructor(deps: ApiKeysServiceDeps) {
    this.storage = deps.storage;
    this.hasher = deps.hasher;
    this.namespace = deps.namespace;
    this.idFactory = deps.idFactory ?? (() => randomUUID());
    this.clock = deps.clock ?? (() => new Date());
    this.debounceMs = deps.debounceMs ?? 60_000;
    this.onAuthFailed = deps.onAuthFailed ?? (() => undefined);
    this.onEvent = deps.onEvent;
    this.onEventError = deps.onEventError;
    this.emitUsageEvents = deps.emitUsageEvents ?? false;
    this.ttlPolicy = deps.ttlPolicy;
  }

  async create(input: CreateApiKeyInput): Promise<CreateApiKeyResult> {
    const environment = input.environment ?? 'live';
    const scopes = flattenScopes(input.scopes);
    const now = this.clock();
    const expiresAt = this.resolveExpiresAt(input.expiresAt, now);

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
        expiresAt,
        revokedAt: null,
        rotatedAt: null,
        replacedByKeyId: null,
        createdBy: input.createdBy ?? null,
        createdAt: now,
      };

      try {
        await this.storage.insert(record);
      } catch (error) {
        if (isDuplicatePrefixError(error) && attempt < ApiKeysService.CREATE_MAX_ATTEMPTS - 1) {
          continue;
        }

        throw error;
      }

      this.emitEvent({
        type: 'api_key.created',
        at: now,
        keyId: record.id,
        tenantId: record.tenantId,
        prefix: record.prefix,
        environment: record.environment,
        scopes: record.scopes,
        createdBy: record.createdBy,
      });

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
      this.reportAuthFailed(null, ApiKeyErrorCode.Malformed);
      throw error;
    }

    if (parsedKey.namespace !== this.namespace) {
      this.hasher.dummyVerify(parsedKey.secret);
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    const record = await this.storage.findByPrefix(parsedKey.prefix);
    if (!record) {
      this.hasher.dummyVerify(parsedKey.secret);
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    if (record.revokedAt !== null) {
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Revoked, record);
      throw new ApiKeyError(ApiKeyErrorCode.Revoked);
    }

    if (record.expiresAt !== null && record.expiresAt.getTime() <= this.clock().getTime()) {
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Expired, record);
      throw new ApiKeyError(ApiKeyErrorCode.Expired);
    }

    let matches: boolean;
    try {
      matches = this.hasher.verify(parsedKey.secret, record.hash, record.pepperVersion);
    } catch {
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid, record);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    if (!matches) {
      this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid, record);
      throw new ApiKeyError(ApiKeyErrorCode.Invalid);
    }

    // Usage tracking is intentionally best-effort. A concurrent revoke may still win
    // after this verification and leave a later lastUsedAt update behind, which is
    // acceptable because it is telemetry and must not block successful auth.
    void this.scheduleTouch(record);
    if (this.emitUsageEvents) {
      this.emitEvent({
        type: 'api_key.used',
        at: this.clock(),
        keyId: record.id,
        tenantId: record.tenantId,
        prefix: record.prefix,
        environment: record.environment,
        scopes: record.scopes,
      });
    }

    return {
      keyId: record.id,
      tenantId: record.tenantId,
      environment: record.environment,
      scopes: record.scopes,
      prefix: record.prefix,
    };
  }

  async revoke(id: string): Promise<void> {
    const record = await this.storage.findById(id);
    await this.storage.markRevoked(id, this.clock());
    if (record) {
      this.emitEvent({
        type: 'api_key.revoked',
        at: this.clock(),
        keyId: record.id,
        tenantId: record.tenantId,
        prefix: record.prefix,
        environment: record.environment,
      });
    }
  }

  async rotate(
    id: string,
    input: RotateApiKeyInput = {},
  ): Promise<RotateApiKeyResult> {
    const oldRecord = await this.storage.findById(id);
    if (!oldRecord) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotFound);
    }

    const now = this.clock();
    if (
      oldRecord.revokedAt !== null ||
      oldRecord.replacedByKeyId !== null ||
      (oldRecord.expiresAt !== null && oldRecord.expiresAt.getTime() <= now.getTime())
    ) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotRotatable);
    }

    const requestedGraceExpiresAt = new Date(now.getTime() + (input.gracePeriodMs ?? 0));
    const oldExpiresAt =
      oldRecord.expiresAt !== null &&
      oldRecord.expiresAt.getTime() < requestedGraceExpiresAt.getTime()
        ? oldRecord.expiresAt
        : requestedGraceExpiresAt;

    for (let attempt = 0; attempt < ApiKeysService.CREATE_MAX_ATTEMPTS; attempt += 1) {
      const generatedKey = generateKey({
        namespace: this.namespace,
        environment: oldRecord.environment,
      });
      const hashed = this.hasher.hash(generatedKey.secret);
      const newRecord: ApiKeyRecord = {
        id: this.idFactory(),
        tenantId: oldRecord.tenantId,
        name: input.name ?? oldRecord.name,
        environment: oldRecord.environment,
        prefix: generatedKey.prefix,
        hash: hashed.hash,
        pepperVersion: hashed.pepperVersion,
        scopes: [...oldRecord.scopes],
        lastUsedAt: null,
        expiresAt: this.resolveExpiresAt(input.expiresAt, now, oldRecord.expiresAt),
        revokedAt: null,
        rotatedAt: null,
        replacedByKeyId: null,
        createdBy: input.createdBy ?? oldRecord.createdBy,
        createdAt: now,
      };

      try {
        await this.storage.rotate({
          oldKeyId: oldRecord.id,
          newRecord,
          oldExpiresAt,
          rotatedAt: now,
        });
      } catch (error) {
        if (isDuplicatePrefixError(error) && attempt < ApiKeysService.CREATE_MAX_ATTEMPTS - 1) {
          continue;
        }

        throw error;
      }

      this.emitEvent({
        type: 'api_key.rotated',
        at: now,
        tenantId: oldRecord.tenantId,
        oldKeyId: oldRecord.id,
        oldPrefix: oldRecord.prefix,
        newKeyId: newRecord.id,
        newPrefix: newRecord.prefix,
        environment: newRecord.environment,
        scopes: newRecord.scopes,
        graceExpiresAt: oldExpiresAt,
        createdBy: newRecord.createdBy,
      });

      return {
        id: newRecord.id,
        key: generatedKey.raw,
        replacedKeyId: oldRecord.id,
        graceExpiresAt: oldExpiresAt,
      };
    }

    throw new Error('failed to generate a unique API key prefix');
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

  private resolveExpiresAt(
    inputExpiresAt: Date | null | undefined,
    now: Date,
    fallbackExpiresAt?: Date | null,
  ): Date | null {
    let expiresAt: Date | null;
    if (inputExpiresAt !== undefined) {
      expiresAt = inputExpiresAt;
    } else if (fallbackExpiresAt) {
      expiresAt = fallbackExpiresAt;
    } else if (this.ttlPolicy?.defaultExpiresInMs !== undefined) {
      expiresAt = new Date(now.getTime() + this.ttlPolicy.defaultExpiresInMs);
    } else {
      expiresAt = null;
    }

    if (expiresAt === null && this.ttlPolicy?.allowNeverExpires === false) {
      throw new Error('expiration is required by ttlPolicy');
    }

    if (
      expiresAt !== null &&
      this.ttlPolicy?.maxExpiresInMs !== undefined &&
      expiresAt.getTime() > now.getTime() + this.ttlPolicy.maxExpiresInMs
    ) {
      throw new Error('expiration exceeds maximum ttlPolicy');
    }

    return expiresAt;
  }

  private reportAuthFailed(
    prefix: string | null,
    code: ApiKeyErrorCode,
    record?: ApiKeyRecord,
  ): void {
    this.onAuthFailed(prefix, code);
    this.emitEvent({
      type: 'api_key.auth_failed',
      at: this.clock(),
      prefix,
      code,
      ...(record
        ? {
            tenantId: record.tenantId,
            keyId: record.id,
            environment: record.environment,
          }
        : {}),
    });
  }

  private emitEvent(event: ApiKeyEvent): void {
    if (!this.onEvent) {
      return;
    }

    try {
      const result = this.onEvent(event);
      if (result && typeof result === 'object' && 'then' in result) {
        void result.catch((error: unknown) => this.handleEventError(error, event));
      }
    } catch (error) {
      this.handleEventError(error, event);
    }
  }

  private handleEventError(error: unknown, event: ApiKeyEvent): void {
    try {
      this.onEventError?.(error, event);
    } catch {
      // Event failure reporting must not break API key operations.
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
