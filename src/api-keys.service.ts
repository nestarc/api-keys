import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  ApiKeyError,
  ApiKeyErrorCode,
  ApiKeyOperationError,
  ApiKeyOperationErrorCode,
} from './errors';
import { generateKey, parseKey } from './key-format';
import {
  defaultApiKeyClientIpResolver,
  isIpAllowed,
  normalizeAllowedIpCidrs,
} from './ip-allowlist';
import {
  isValidTenantId,
  validateEnvironment,
  validateNamespace,
  validateTenantId,
} from './input-validation';
import {
  copyApiKeyAuthorizationMetric,
  copyApiKeyContext,
  copyApiKeyEvent,
  copyApiKeyOperationMetric,
  copyApiKeyVerificationMetric,
} from './payload-copy';
import { flattenScopes, scopeSatisfies } from './scope-matcher';
import type { ApiKeyStorage, ListApiKeysOptions } from './storage/api-key-storage.interface';
import type {
  ApiKeyContext,
  ApiKeyAuthorizationMetric,
  ApiKeyAuthorizationMetricSink,
  ApiKeyAuthorizationOutcome,
  ApiKeyEvent,
  ApiKeyEventSink,
  ApiKeyMetricSink,
  ApiKeyOperationMetric,
  ApiKeyOperationMetricOperation,
  ApiKeyOperationMetricSink,
  ApiKeyTtlPolicy,
  ApiKeyRecord,
  ApiKeySummary,
  ApiKeyVerificationMetric,
  ApiKeyVerificationOutcome,
  ApiKeyRequestAuthorizationInput,
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
  /**
   * @deprecated Use `onEvent` and handle `api_key.auth_failed` events instead.
   */
  onAuthFailed?: (
    prefix: string | null,
    code: string,
  ) => void | PromiseLike<void>;
  onEvent?: ApiKeyEventSink;
  onEventError?: (error: unknown, event: ApiKeyEvent) => void;
  onMetric?: ApiKeyMetricSink;
  onMetricError?: (error: unknown, metric: ApiKeyVerificationMetric) => void;
  onAuthorizationMetric?: ApiKeyAuthorizationMetricSink;
  onAuthorizationMetricError?: (error: unknown, metric: ApiKeyAuthorizationMetric) => void;
  onOperationMetric?: ApiKeyOperationMetricSink;
  onOperationMetricError?: (error: unknown, metric: ApiKeyOperationMetric) => void;
  emitUsageEvents?: boolean;
  ttlPolicy?: ApiKeyTtlPolicy;
  monotonicClock?: () => number;
}

export class ApiKeysService {
  private static readonly CREATE_MAX_ATTEMPTS = 3;

  private readonly storage: ApiKeyStorage;
  private readonly hasher: Sha256Hasher;
  private readonly namespace: string;
  private readonly idFactory: () => string;
  private readonly clock: () => Date;
  private readonly debounceMs: number;
  private readonly onAuthFailed: (
    prefix: string | null,
    code: string,
  ) => void | PromiseLike<void>;
  private readonly onEvent?: ApiKeyEventSink;
  private readonly onEventError?: (error: unknown, event: ApiKeyEvent) => void;
  private readonly onMetric?: ApiKeyMetricSink;
  private readonly onMetricError?: (error: unknown, metric: ApiKeyVerificationMetric) => void;
  private readonly onAuthorizationMetric?: ApiKeyAuthorizationMetricSink;
  private readonly onAuthorizationMetricError?: (
    error: unknown,
    metric: ApiKeyAuthorizationMetric,
  ) => void;
  private readonly onOperationMetric?: ApiKeyOperationMetricSink;
  private readonly onOperationMetricError?: (
    error: unknown,
    metric: ApiKeyOperationMetric,
  ) => void;
  private readonly emitUsageEvents: boolean;
  private readonly ttlPolicy?: ApiKeyTtlPolicy;
  private readonly monotonicClock: () => number;

  constructor(deps: ApiKeysServiceDeps) {
    this.storage = deps.storage;
    this.hasher = deps.hasher;
    this.namespace = validateNamespace(deps.namespace);
    this.idFactory = deps.idFactory ?? (() => randomUUID());
    this.clock = deps.clock ?? (() => new Date());
    this.debounceMs = validateDuration(deps.debounceMs ?? 60_000, 'debounceMs');
    this.onAuthFailed = deps.onAuthFailed ?? (() => undefined);
    this.onEvent = deps.onEvent;
    this.onEventError = deps.onEventError;
    this.onMetric = deps.onMetric;
    this.onMetricError = deps.onMetricError;
    this.onAuthorizationMetric = deps.onAuthorizationMetric;
    this.onAuthorizationMetricError = deps.onAuthorizationMetricError;
    this.onOperationMetric = deps.onOperationMetric;
    this.onOperationMetricError = deps.onOperationMetricError;
    this.emitUsageEvents = deps.emitUsageEvents ?? false;
    this.ttlPolicy = deps.ttlPolicy
      ? {
          ...deps.ttlPolicy,
          ...(deps.ttlPolicy.defaultExpiresInMs !== undefined
            ? {
                defaultExpiresInMs: validateDuration(
                  deps.ttlPolicy.defaultExpiresInMs,
                  'ttlPolicy.defaultExpiresInMs',
                ),
              }
            : {}),
          ...(deps.ttlPolicy.maxExpiresInMs !== undefined
            ? {
                maxExpiresInMs: validateDuration(
                  deps.ttlPolicy.maxExpiresInMs,
                  'ttlPolicy.maxExpiresInMs',
                ),
              }
            : {}),
        }
      : undefined;
    this.monotonicClock = deps.monotonicClock ?? (() => performance.now());
  }

  async create(input: CreateApiKeyInput): Promise<CreateApiKeyResult> {
    const tenantId = validateTenantId(input.tenantId);
    const environment = validateEnvironment(input.environment ?? 'live');
    const scopes = flattenScopes(input.scopes);
    const now = this.currentTime();
    const expiresAt = this.resolveExpiresAt(input.expiresAt, now);
    const allowedIpCidrs = normalizeAllowedIpCidrs(input.allowedIpCidrs);

    for (let attempt = 0; attempt < ApiKeysService.CREATE_MAX_ATTEMPTS; attempt += 1) {
      const generatedKey = generateKey({ namespace: this.namespace, environment });
      const hashed = this.hasher.hash(generatedKey.secret);

      const record: ApiKeyRecord = {
        id: this.idFactory(),
        tenantId,
        name: input.name,
        environment,
        prefix: generatedKey.prefix,
        hash: hashed.hash,
        pepperVersion: hashed.pepperVersion,
        scopes,
        allowedIpCidrs,
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
        if (isDuplicatePrefixError(error)) {
          if (attempt < ApiKeysService.CREATE_MAX_ATTEMPTS - 1) {
            continue;
          }

          throw this.prefixCollisionError('create', error);
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
    const verified = await this.verifyCredential(rawKey);
    this.recordSuccessfulUse(verified.record);
    return copyApiKeyContext(verified.context);
  }

  async authorizeRequest(input: ApiKeyRequestAuthorizationInput): Promise<ApiKeyContext> {
    const startedAt = this.onAuthorizationMetric ? this.monotonicClock() : 0;
    let metricEnvironment: ApiKeyContext['environment'] | undefined;

    try {
      if (input.rawKey === undefined || input.rawKey === null) {
        throw new ApiKeyError(ApiKeyErrorCode.Missing);
      }

      const verified = await this.verifyCredential(input.rawKey);
      const apiKeyContext = verified.context;
      metricEnvironment = apiKeyContext.environment;

      if (input.requiredEnvironment && apiKeyContext.environment !== input.requiredEnvironment) {
        throw new ApiKeyError(ApiKeyErrorCode.EnvironmentMismatch);
      }

      const allowedIpCidrs = apiKeyContext.allowedIpCidrs ?? [];
      if (allowedIpCidrs.length > 0) {
        let clientIp = input.clientIp;
        if (clientIp === undefined) {
          const resolver =
            input.clientIpResolver ??
            (input.request === undefined ? undefined : defaultApiKeyClientIpResolver);
          clientIp = await resolver?.(input.request);
        }
        if (!isIpAllowed(clientIp, allowedIpCidrs)) {
          throw new ApiKeyError(ApiKeyErrorCode.IpNotAllowed);
        }
      }

      if (
        input.requiredScope &&
        !scopeSatisfies(
          apiKeyContext.scopes,
          input.requiredScope.resource,
          input.requiredScope.level,
        )
      ) {
        throw new ApiKeyError(ApiKeyErrorCode.ScopeInsufficient);
      }

      this.recordSuccessfulUse(verified.record);
      this.recordAuthorizationMetric('success', startedAt, metricEnvironment);
      return copyApiKeyContext(apiKeyContext);
    } catch (error) {
      if (error instanceof ApiKeyError) {
        this.emitEvent({
          type: 'api_key.authorization_denied',
          at: this.clock(),
          code: error.code,
        });
      }
      this.recordAuthorizationMetric(
        authorizationOutcomeFromError(error),
        startedAt,
        metricEnvironment,
      );
      throw error;
    }
  }

  private async verifyCredential(
    rawKey: string,
  ): Promise<{ context: ApiKeyContext; record: ApiKeyRecord }> {
    const startedAt = this.onMetric ? this.monotonicClock() : 0;
    let metricEnvironment: ApiKeyContext['environment'] | undefined;

    try {
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
      metricEnvironment = record.environment;

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

      if (parsedKey.environment !== record.environment) {
        metricEnvironment = undefined;
        this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
        throw new ApiKeyError(ApiKeyErrorCode.Invalid);
      }

      if (!isValidTenantId(record.tenantId)) {
        this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid);
        throw new ApiKeyError(ApiKeyErrorCode.Invalid);
      }

      if (record.revokedAt !== null) {
        this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Revoked, record);
        throw new ApiKeyError(ApiKeyErrorCode.Revoked);
      }

      if (record.expiresAt !== null) {
        let expiresAtMs: number;
        let nowMs: number;
        try {
          expiresAtMs = dateTimestamp(record.expiresAt, 'persisted expiresAt');
          nowMs = this.currentTime().getTime();
        } catch {
          this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Invalid, record);
          throw new ApiKeyError(ApiKeyErrorCode.Invalid);
        }

        if (expiresAtMs <= nowMs) {
          this.reportAuthFailed(parsedKey.prefix, ApiKeyErrorCode.Expired, record);
          throw new ApiKeyError(ApiKeyErrorCode.Expired);
        }
      }

      const apiKeyContext: ApiKeyContext = {
        keyId: record.id,
        tenantId: record.tenantId,
        environment: record.environment,
        scopes: [...record.scopes],
        prefix: record.prefix,
        allowedIpCidrs: [...(record.allowedIpCidrs ?? [])],
      };
      this.recordVerificationMetric('success', startedAt, metricEnvironment);
      return { context: copyApiKeyContext(apiKeyContext), record };
    } catch (error) {
      this.recordVerificationMetric(
        verificationOutcomeFromError(error),
        startedAt,
        metricEnvironment,
      );
      throw error;
    }
  }

  async revoke(id: string): Promise<void> {
    const record = await this.storage.findById(id);
    if (record) {
      validateTenantId(record.tenantId);
    }
    await this.storage.markRevoked(id, this.currentTime());
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

  async revokeForTenant(tenantId: string, id: string): Promise<void> {
    const expectedTenantId = validateTenantId(tenantId);
    const revokeForTenant = this.storage.revokeForTenant?.bind(this.storage);
    if (!revokeForTenant) {
      throw new Error(
        'ApiKeyStorage.revokeForTenant() is required for tenant-bound revocation',
      );
    }

    const record = await this.storage.findById(id);
    if (!record || !isValidTenantId(record.tenantId) || record.tenantId !== expectedTenantId) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotFound);
    }

    const revokedAt = this.currentTime();
    const result = await revokeForTenant({
      keyId: id,
      expectedTenantId,
      revokedAt,
    });
    if (result === 'not_found') {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotFound);
    }
    if (result !== 'revoked') {
      throw new Error(
        'ApiKeyStorage.revokeForTenant() must atomically return "revoked" or "not_found"',
      );
    }

    this.emitEvent({
      type: 'api_key.revoked',
      at: revokedAt,
      keyId: record.id,
      tenantId: record.tenantId,
      prefix: record.prefix,
      environment: record.environment,
    });
  }

  async rotate(
    id: string,
    input: RotateApiKeyInput = {},
  ): Promise<RotateApiKeyResult> {
    return this.rotateInternal(id, input);
  }

  async rotateForTenant(
    tenantId: string,
    id: string,
    input: RotateApiKeyInput = {},
  ): Promise<RotateApiKeyResult> {
    const expectedTenantId = validateTenantId(tenantId);
    if (!this.storage.rotateForTenant) {
      throw new Error(
        'ApiKeyStorage.rotateForTenant() is required for tenant-bound rotation',
      );
    }

    return this.rotateInternal(id, input, expectedTenantId);
  }

  private async rotateInternal(
    id: string,
    input: RotateApiKeyInput,
    expectedTenantId?: string,
  ): Promise<RotateApiKeyResult> {
    const gracePeriodMs = validateDuration(input.gracePeriodMs ?? 0, 'gracePeriodMs');
    if (input.expiresAt !== undefined && input.expiresAt !== null) {
      dateTimestamp(input.expiresAt, 'expiresAt');
    }

    const oldRecord = await this.storage.findById(id);
    if (!oldRecord) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotFound);
    }
    if (expectedTenantId !== undefined && oldRecord.tenantId !== expectedTenantId) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotFound);
    }
    if (!isValidTenantId(oldRecord.tenantId)) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotRotatable);
    }

    const now = this.currentTime();
    let oldExpiresAtMs: number | null = null;
    if (oldRecord.expiresAt !== null) {
      try {
        oldExpiresAtMs = dateTimestamp(oldRecord.expiresAt, 'persisted expiresAt');
      } catch {
        throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotRotatable);
      }
    }
    if (
      oldRecord.revokedAt !== null ||
      oldRecord.rotatedAt !== null ||
      oldRecord.replacedByKeyId !== null ||
      (oldExpiresAtMs !== null && oldExpiresAtMs <= now.getTime())
    ) {
      throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotRotatable);
    }

    const requestedGraceExpiresAt = addDuration(now, gracePeriodMs, 'gracePeriodMs');
    const oldExpiresAt =
      oldRecord.expiresAt !== null &&
      oldExpiresAtMs !== null &&
      oldExpiresAtMs < requestedGraceExpiresAt.getTime()
        ? oldRecord.expiresAt
        : requestedGraceExpiresAt;
    const allowedIpCidrs =
      input.allowedIpCidrs === undefined
        ? [...(oldRecord.allowedIpCidrs ?? [])]
        : normalizeAllowedIpCidrs(input.allowedIpCidrs);
    const replacementExpiresAt = this.resolveExpiresAt(
      input.expiresAt,
      now,
      oldRecord.expiresAt,
    );

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
        allowedIpCidrs,
        lastUsedAt: null,
        expiresAt: replacementExpiresAt,
        revokedAt: null,
        rotatedAt: null,
        replacedByKeyId: null,
        createdBy: input.createdBy ?? oldRecord.createdBy,
        createdAt: now,
      };

      try {
        const rotationInput = {
          oldKeyId: oldRecord.id,
          newRecord,
          oldExpiresAt,
          rotatedAt: now,
        };
        const rotationResult =
          expectedTenantId === undefined
            ? await this.storage.rotate(rotationInput)
            : await this.storage.rotateForTenant!({
                ...rotationInput,
                expectedTenantId,
              });
        if (rotationResult === 'not_rotatable') {
          throw new ApiKeyOperationError(ApiKeyOperationErrorCode.NotRotatable);
        }
        if (rotationResult !== 'rotated') {
          throw new Error(
            'ApiKeyStorage.rotate() must atomically return "rotated" or "not_rotatable"',
          );
        }
      } catch (error) {
        if (isDuplicatePrefixError(error)) {
          if (attempt < ApiKeysService.CREATE_MAX_ATTEMPTS - 1) {
            continue;
          }

          throw this.prefixCollisionError('rotate', error);
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

  async list(tenantId: string, opts: ListApiKeysOptions = {}): Promise<ApiKeySummary[]> {
    const canonicalTenantId = validateTenantId(tenantId);
    const records = await this.storage.listByTenant(canonicalTenantId, opts);
    for (const record of records) {
      if (!isValidTenantId(record.tenantId) || record.tenantId !== canonicalTenantId) {
        throw new ApiKeyOperationError(
          ApiKeyOperationErrorCode.InvalidInput,
          'storage returned a record outside the exact tenant boundary',
        );
      }
    }
    return records.map(toApiKeySummary);
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

  private recordSuccessfulUse(record: ApiKeyRecord): void {
    // Usage tracking is intentionally best-effort. A concurrent revoke may still win
    // after an accepted use and leave a later lastUsedAt update behind, which is
    // acceptable because telemetry must not block authentication or authorization.
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
      expiresAt = addDuration(
        now,
        this.ttlPolicy.defaultExpiresInMs,
        'ttlPolicy.defaultExpiresInMs',
      );
    } else {
      expiresAt = null;
    }

    if (expiresAt === null && this.ttlPolicy?.allowNeverExpires === false) {
      throw new ApiKeyOperationError(
        ApiKeyOperationErrorCode.InvalidTime,
        'expiration is required by ttlPolicy',
      );
    }

    if (expiresAt !== null) {
      const expiresAtMs = dateTimestamp(expiresAt, 'expiresAt');
      if (this.ttlPolicy?.maxExpiresInMs !== undefined) {
        const maximumExpiresAt = addDuration(
          now,
          this.ttlPolicy.maxExpiresInMs,
          'ttlPolicy.maxExpiresInMs',
        );
        if (expiresAtMs > maximumExpiresAt.getTime()) {
          throw new ApiKeyOperationError(
            ApiKeyOperationErrorCode.InvalidTime,
            'expiration exceeds maximum ttlPolicy',
          );
        }
      }
    }

    return expiresAt;
  }

  private currentTime(): Date {
    const now = this.clock();
    dateTimestamp(now, 'clock');
    return now;
  }

  private reportAuthFailed(
    prefix: string | null,
    code: ApiKeyErrorCode,
    record?: ApiKeyRecord,
  ): void {
    invokeObserver(() => this.onAuthFailed(prefix, code));
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

    invokeObserver(
      () => this.onEvent?.(copyApiKeyEvent(event)),
      (error) => this.handleEventError(error, event),
    );
  }

  private handleEventError(
    error: unknown,
    event: ApiKeyEvent,
  ): void | PromiseLike<void> {
    return this.onEventError?.(error, copyApiKeyEvent(event));
  }

  private recordVerificationMetric(
    outcome: ApiKeyVerificationOutcome,
    startedAt: number,
    environment?: ApiKeyContext['environment'],
  ): void {
    if (!this.onMetric) {
      return;
    }

    const metric: ApiKeyVerificationMetric = {
      type: 'api_key.verification',
      outcome,
      durationMs: Math.max(0, this.monotonicClock() - startedAt),
      ...(environment ? { environment } : {}),
    };

    invokeObserver(
      () => this.onMetric?.(copyApiKeyVerificationMetric(metric)),
      (error) => this.handleMetricError(error, metric),
    );
  }

  private handleMetricError(
    error: unknown,
    metric: ApiKeyVerificationMetric,
  ): void | PromiseLike<void> {
    return this.onMetricError?.(error, copyApiKeyVerificationMetric(metric));
  }

  private recordAuthorizationMetric(
    outcome: ApiKeyAuthorizationOutcome,
    startedAt: number,
    environment?: ApiKeyContext['environment'],
  ): void {
    if (!this.onAuthorizationMetric) {
      return;
    }

    const metric: ApiKeyAuthorizationMetric = {
      type: 'api_key.authorization',
      outcome,
      durationMs: Math.max(0, this.monotonicClock() - startedAt),
      ...(environment ? { environment } : {}),
    };

    invokeObserver(
      () => this.onAuthorizationMetric?.(copyApiKeyAuthorizationMetric(metric)),
      (error) => this.handleAuthorizationMetricError(error, metric),
    );
  }

  private handleAuthorizationMetricError(
    error: unknown,
    metric: ApiKeyAuthorizationMetric,
  ): void | PromiseLike<void> {
    return this.onAuthorizationMetricError?.(
      error,
      copyApiKeyAuthorizationMetric(metric),
    );
  }

  private prefixCollisionError(
    operation: ApiKeyOperationMetricOperation,
    cause: unknown,
  ): ApiKeyOperationError {
    const metric: ApiKeyOperationMetric = {
      type: 'api_key.operation',
      operation,
      outcome: 'prefix_collision_exhausted',
      attempts: ApiKeysService.CREATE_MAX_ATTEMPTS,
    };
    if (this.onOperationMetric) {
      invokeObserver(
        () => this.onOperationMetric?.(copyApiKeyOperationMetric(metric)),
        (error) =>
          this.onOperationMetricError?.(error, copyApiKeyOperationMetric(metric)),
      );
    }

    return new ApiKeyOperationError(
      ApiKeyOperationErrorCode.PrefixCollision,
      `could not allocate a unique prefix after ${ApiKeysService.CREATE_MAX_ATTEMPTS} attempts`,
      { cause },
    );
  }
}

function toApiKeySummary(record: ApiKeyRecord): ApiKeySummary {
  return {
    id: record.id,
    tenantId: record.tenantId,
    name: record.name,
    environment: record.environment,
    prefix: record.prefix,
    scopes: [...record.scopes],
    ...(record.allowedIpCidrs
      ? { allowedIpCidrs: [...record.allowedIpCidrs] }
      : {}),
    lastUsedAt: copyNullableDate(record.lastUsedAt),
    expiresAt: copyNullableDate(record.expiresAt),
    revokedAt: copyNullableDate(record.revokedAt),
    rotatedAt: copyNullableDate(record.rotatedAt),
    replacedByKeyId: record.replacedByKeyId,
    createdBy: record.createdBy,
    createdAt: new Date(record.createdAt.getTime()),
  };
}

function copyNullableDate(value: Date | null): Date | null {
  return value === null ? null : new Date(value.getTime());
}

function invokeObserver(
  observer: () => void | PromiseLike<void>,
  reportError?: (error: unknown) => void | PromiseLike<void>,
): void {
  let result: void | PromiseLike<void>;
  try {
    result = observer();
  } catch (error) {
    reportObserverError(reportError, error);
    return;
  }

  void Promise.resolve(result).catch((error: unknown) => {
    reportObserverError(reportError, error);
  });
}

function reportObserverError(
  reportError: ((error: unknown) => void | PromiseLike<void>) | undefined,
  error: unknown,
): void {
  if (!reportError) {
    return;
  }

  try {
    void Promise.resolve(reportError(error)).catch(() => undefined);
  } catch {
    // Observer failure reporting must not break API key operations.
  }
}

function verificationOutcomeFromError(error: unknown): ApiKeyVerificationOutcome {
  if (!(error instanceof ApiKeyError)) {
    return 'error';
  }

  switch (error.code) {
    case ApiKeyErrorCode.Malformed:
      return 'malformed';
    case ApiKeyErrorCode.Invalid:
      return 'invalid';
    case ApiKeyErrorCode.Revoked:
      return 'revoked';
    case ApiKeyErrorCode.Expired:
      return 'expired';
    default:
      return 'error';
  }
}

function authorizationOutcomeFromError(error: unknown): ApiKeyAuthorizationOutcome {
  if (!(error instanceof ApiKeyError)) {
    return 'error';
  }

  switch (error.code) {
    case ApiKeyErrorCode.Missing:
      return 'missing';
    case ApiKeyErrorCode.Malformed:
    case ApiKeyErrorCode.Invalid:
    case ApiKeyErrorCode.Revoked:
    case ApiKeyErrorCode.Expired:
      return 'credential_rejected';
    case ApiKeyErrorCode.EnvironmentMismatch:
      return 'environment_denied';
    case ApiKeyErrorCode.IpNotAllowed:
      return 'ip_denied';
    case ApiKeyErrorCode.ScopeInsufficient:
      return 'scope_denied';
  }
}

function validateDuration(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new ApiKeyOperationError(
      ApiKeyOperationErrorCode.InvalidTime,
      `${label} must be a finite, non-negative duration`,
    );
  }

  return value;
}

function dateTimestamp(value: Date, label: string): number {
  if (!(value instanceof Date)) {
    throw new ApiKeyOperationError(
      ApiKeyOperationErrorCode.InvalidTime,
      `${label} must be a valid Date`,
    );
  }

  const timestamp = value.getTime();
  if (!Number.isFinite(timestamp)) {
    throw new ApiKeyOperationError(
      ApiKeyOperationErrorCode.InvalidTime,
      `${label} must be a valid Date`,
    );
  }

  return timestamp;
}

function addDuration(now: Date, durationMs: number, label: string): Date {
  const result = new Date(dateTimestamp(now, 'clock') + validateDuration(durationMs, label));
  if (!Number.isFinite(result.getTime())) {
    throw new ApiKeyOperationError(
      ApiKeyOperationErrorCode.InvalidTime,
      `${label} exceeds the supported Date range`,
    );
  }

  return result;
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
