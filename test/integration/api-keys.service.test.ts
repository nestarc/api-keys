import { ApiKeyErrorCode } from '../../src/errors';
import { ApiKeysService } from '../../src/api-keys.service';
import { Sha256Hasher } from '../../src/hasher';
import type { ApiKeyStorage } from '../../src/storage/api-key-storage.interface';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';
import type { ApiKeyRecord, ApiKeyVerificationMetric } from '../../src/types';

interface RotatableService extends ApiKeysService {
  rotate(
    id: string,
    input?: {
      gracePeriodMs?: number;
      name?: string;
      createdBy?: string;
      expiresAt?: Date | null;
    },
  ): Promise<{ id: string; key: string; replacedKeyId: string; graceExpiresAt: Date }>;
}

function svc(
  overrides: Partial<{
    hasher: Sha256Hasher;
    onAuthFailed: (prefix: string | null, code: string) => void;
    clock: () => Date;
    onEvent: (event: Record<string, unknown>) => void | Promise<void>;
    onEventError: (error: unknown, event: Record<string, unknown>) => void;
    onMetric: (metric: ApiKeyVerificationMetric) => void | Promise<void>;
    onMetricError: (error: unknown, metric: ApiKeyVerificationMetric) => void;
    monotonicClock: () => number;
    emitUsageEvents: boolean;
    ttlPolicy: {
      defaultExpiresInMs?: number;
      maxExpiresInMs?: number;
      allowNeverExpires?: boolean;
    };
  }> = {},
) {
  const storage = new InMemoryApiKeyStorage();
  const hasher =
    overrides.hasher ?? new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
  const service = new ApiKeysService({
    storage,
    hasher,
    namespace: 'nk',
    idFactory: (() => {
      let counter = 0;
      return () => `key_${++counter}`;
    })(),
    clock: overrides.clock ?? (() => new Date('2026-01-01T00:00:00Z')),
    debounceMs: 60_000,
    onAuthFailed: overrides.onAuthFailed,
    onEvent: overrides.onEvent,
    onEventError: overrides.onEventError,
    onMetric: overrides.onMetric,
    onMetricError: overrides.onMetricError,
    monotonicClock: overrides.monotonicClock,
    emitUsageEvents: overrides.emitUsageEvents,
    ttlPolicy: overrides.ttlPolicy,
  } as ConstructorParameters<typeof ApiKeysService>[0] & Record<string, unknown>);

  return { service, storage };
}

describe('ApiKeysService.create', () => {
  it('returns a key and stores a hashed record', async () => {
    const { service, storage } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'invoices', level: 'write' }],
    });

    expect(result.key).toMatch(/^nk_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);

    const stored = (await storage.listByTenant('t1'))[0];
    expect(stored.name).toBe('primary');
    expect(stored.hash).not.toContain(result.key);
    expect(stored.scopes).toEqual(['invoices:write']);
    expect(stored.environment).toBe('live');
  });

  it('defaults environment to live', async () => {
    const { service } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    expect(result.key.split('_')[1]).toBe('live');
  });

  it('supports test environment', async () => {
    const { service } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'x',
      environment: 'test',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    expect(result.key.split('_')[1]).toBe('test');
  });

  it('normalizes and persists an IP allowlist in the verification context', async () => {
    const { service, storage } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'restricted',
      scopes: [{ resource: 'r', level: 'read' }],
      allowedIpCidrs: ['203.0.113.42', '10.0.0.42/24', '10.0.0.0/24'],
    });

    await expect(service.verify(result.key)).resolves.toMatchObject({
      allowedIpCidrs: ['203.0.113.42/32', '10.0.0.0/24'],
    });
    await expect(storage.findById(result.id)).resolves.toMatchObject({
      allowedIpCidrs: ['203.0.113.42/32', '10.0.0.0/24'],
    });
  });

  it('rejects an invalid IP allowlist before inserting a record', async () => {
    const { service, storage } = svc();

    await expect(
      service.create({
        tenantId: 't1',
        name: 'invalid',
        scopes: [{ resource: 'r', level: 'read' }],
        allowedIpCidrs: ['not-an-ip'],
      }),
    ).rejects.toThrow('invalid IP allowlist entry: not-an-ip');
    await expect(storage.listByTenant('t1')).resolves.toEqual([]);
  });

  it('rejects empty scopes', async () => {
    const { service } = svc();

    await expect(service.create({ tenantId: 't1', name: 'x', scopes: [] })).rejects.toThrow(
      /at least one scope/,
    );
  });

  it('retries when storage reports a duplicate prefix', async () => {
    const insert = jest
      .fn<ReturnType<ApiKeyStorage['insert']>, Parameters<ApiKeyStorage['insert']>>()
      .mockRejectedValueOnce(new Error('duplicate prefix: abcdefghijkl'))
      .mockResolvedValue(undefined);
    const storage: ApiKeyStorage = {
      insert,
      findById: jest.fn().mockResolvedValue(null),
      findByPrefix: jest.fn().mockResolvedValue(null),
      listByTenant: jest.fn().mockResolvedValue([]),
      markRevoked: jest.fn().mockResolvedValue(undefined),
      touchLastUsed: jest.fn().mockResolvedValue(undefined),
      rotate: jest.fn().mockResolvedValue(undefined),
    };
    const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
    const service = new ApiKeysService({
      storage,
      hasher,
      namespace: 'nk',
      idFactory: (() => {
        let counter = 0;
        return () => `key_${++counter}`;
      })(),
      clock: () => new Date('2026-01-01T00:00:00Z'),
    });

    const result = await service.create({
      tenantId: 't1',
      name: 'retry-me',
      scopes: [{ resource: 'reports', level: 'read' }],
    });

    expect(insert).toHaveBeenCalledTimes(2);
    expect(result.key).toMatch(/^nk_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);
  });
});

describe('ApiKeysService.rotate', () => {
  it('creates a replacement key and keeps both keys valid during the grace period', async () => {
    const { service, storage } = svc();
    const rotatable = service as RotatableService;
    const created = await service.create({
      tenantId: 't1',
      name: 'old key',
      environment: 'test',
      scopes: [{ resource: 'reports', level: 'write' }],
      createdBy: 'user_1',
    });

    const rotated = await rotatable.rotate(created.id, {
      gracePeriodMs: 7 * 24 * 60 * 60 * 1000,
      name: 'new key',
      createdBy: 'user_2',
    });

    expect(rotated.id).toBe('key_2');
    expect(rotated.replacedKeyId).toBe(created.id);
    expect(rotated.key).toMatch(/^nk_test_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);
    expect(rotated.key).not.toBe(created.key);
    expect(rotated.graceExpiresAt.toISOString()).toBe('2026-01-08T00:00:00.000Z');

    await expect(service.verify(created.key)).resolves.toMatchObject({
      keyId: created.id,
      tenantId: 't1',
      environment: 'test',
      scopes: ['reports:write'],
    });
    await expect(service.verify(rotated.key)).resolves.toMatchObject({
      keyId: rotated.id,
      tenantId: 't1',
      environment: 'test',
      scopes: ['reports:write'],
    });

    const records = await storage.listByTenant('t1');
    expect(records).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: created.id,
          expiresAt: rotated.graceExpiresAt,
          rotatedAt: new Date('2026-01-01T00:00:00Z'),
          replacedByKeyId: rotated.id,
        }),
        expect.objectContaining({
          id: rotated.id,
          name: 'new key',
          createdBy: 'user_2',
          rotatedAt: null,
          replacedByKeyId: null,
        }),
      ]),
    );
  });

  it('expires the old key after the grace period while the replacement remains valid', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const { service } = svc({ clock: () => now });
    const rotatable = service as RotatableService;
    const created = await service.create({
      tenantId: 't1',
      name: 'old key',
      scopes: [{ resource: 'reports', level: 'read' }],
    });

    const rotated = await rotatable.rotate(created.id, { gracePeriodMs: 1_000 });

    now = new Date('2026-01-01T00:00:02Z');

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Expired,
    });
    await expect(service.verify(rotated.key)).resolves.toMatchObject({
      keyId: rotated.id,
    });
  });

  it('preserves or explicitly clears the IP allowlist during rotation', async () => {
    const { service } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'old key',
      scopes: [{ resource: 'reports', level: 'read' }],
      allowedIpCidrs: ['203.0.113.0/24'],
    });

    const preserved = await service.rotate(created.id, { gracePeriodMs: 1_000 });
    await expect(service.verify(preserved.key)).resolves.toMatchObject({
      allowedIpCidrs: ['203.0.113.0/24'],
    });

    const cleared = await service.rotate(preserved.id, { allowedIpCidrs: [] });
    await expect(service.verify(cleared.key)).resolves.toMatchObject({
      allowedIpCidrs: [],
    });
  });

  it('rejects rotation for a revoked key', async () => {
    const { service } = svc();
    const rotatable = service as RotatableService;
    const created = await service.create({
      tenantId: 't1',
      name: 'old key',
      scopes: [{ resource: 'reports', level: 'read' }],
    });

    await service.revoke(created.id);

    await expect(rotatable.rotate(created.id)).rejects.toMatchObject({
      code: 'api_key_not_rotatable',
    });
  });

  it('allows exactly one concurrent rotation and rejects every loser as not rotatable', async () => {
    const { service, storage } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'old key',
      scopes: [{ resource: 'reports', level: 'read' }],
    });

    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => service.rotate(created.id, { gracePeriodMs: 1_000 })),
    );
    const successes = results.filter(
      (result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof service.rotate>>> =>
        result.status === 'fulfilled',
    );
    const failures = results.filter(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );

    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(7);
    for (const failure of failures) {
      expect(failure.reason).toMatchObject({
        code: 'api_key_not_rotatable',
      });
    }

    const records = await storage.listByTenant('t1');
    const oldRecord = records.find((record) => record.id === created.id);
    const replacements = records.filter((record) => record.id !== created.id);
    expect(replacements).toHaveLength(1);
    expect(oldRecord?.replacedByKeyId).toBe(successes[0].value.id);
    await expect(service.verify(successes[0].value.key)).resolves.toMatchObject({
      keyId: successes[0].value.id,
    });
  });

  it('retries when storage reports a duplicate prefix during rotation', async () => {
    const oldRecord: ApiKeyRecord = {
      id: 'key_1',
      tenantId: 't1',
      name: 'old key',
      environment: 'live',
      prefix: 'abcdefghijkl',
      hash: 'f'.repeat(64),
      pepperVersion: 1,
      scopes: ['reports:read'],
      lastUsedAt: null,
      expiresAt: null,
      revokedAt: null,
      rotatedAt: null,
      replacedByKeyId: null,
      createdBy: 'user_1',
      createdAt: new Date('2026-01-01T00:00:00Z'),
    };
    const rotate = jest
      .fn<ReturnType<ApiKeyStorage['rotate']>, Parameters<ApiKeyStorage['rotate']>>()
      .mockRejectedValueOnce(new Error('duplicate prefix: abcdefghijkl'))
      .mockResolvedValue('rotated');
    const storage: ApiKeyStorage = {
      insert: jest.fn().mockResolvedValue(undefined),
      findById: jest.fn().mockResolvedValue(oldRecord),
      findByPrefix: jest.fn().mockResolvedValue(null),
      listByTenant: jest.fn().mockResolvedValue([]),
      markRevoked: jest.fn().mockResolvedValue(undefined),
      touchLastUsed: jest.fn().mockResolvedValue(undefined),
      rotate,
    };
    const service = new ApiKeysService({
      storage,
      hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
      namespace: 'nk',
      idFactory: (() => {
        let counter = 1;
        return () => `key_${++counter}`;
      })(),
      clock: () => new Date('2026-01-01T00:00:00Z'),
    });
    const rotatable = service as RotatableService;

    const rotated = await rotatable.rotate(oldRecord.id);

    expect(rotate).toHaveBeenCalledTimes(2);
    expect(rotated.id).toBe('key_3');
    expect(rotated.key).toMatch(/^nk_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);
  });

  it('fails fast when a legacy custom storage returns no atomic rotation result', async () => {
    const oldRecord: ApiKeyRecord = {
      id: 'key_1',
      tenantId: 't1',
      name: 'old key',
      environment: 'live',
      prefix: 'abcdefghijkl',
      hash: 'f'.repeat(64),
      pepperVersion: 1,
      scopes: ['reports:read'],
      lastUsedAt: null,
      expiresAt: null,
      revokedAt: null,
      rotatedAt: null,
      replacedByKeyId: null,
      createdBy: null,
      createdAt: new Date('2026-01-01T00:00:00Z'),
    };
    const legacyStorage = {
      insert: jest.fn().mockResolvedValue(undefined),
      findById: jest.fn().mockResolvedValue(oldRecord),
      findByPrefix: jest.fn().mockResolvedValue(null),
      listByTenant: jest.fn().mockResolvedValue([]),
      markRevoked: jest.fn().mockResolvedValue(undefined),
      touchLastUsed: jest.fn().mockResolvedValue(undefined),
      rotate: jest.fn().mockResolvedValue(undefined),
    } as unknown as ApiKeyStorage;
    const service = new ApiKeysService({
      storage: legacyStorage,
      hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
      namespace: 'nk',
      idFactory: () => 'key_2',
      clock: () => new Date('2026-01-01T00:00:00Z'),
    });

    await expect(service.rotate(oldRecord.id)).rejects.toThrow(
      'ApiKeyStorage.rotate() must atomically return "rotated" or "not_rotatable"',
    );
  });
});

describe('ApiKeysService lifecycle events and TTL policy', () => {
  it('emits created revoked rotated and auth_failed events without raw key material', async () => {
    const events: Record<string, unknown>[] = [];
    const { service, storage } = svc({
      onEvent: (event) => {
        events.push(event);
      },
    });
    const rotatable = service as RotatableService;

    const created = await service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'reports', level: 'read' }],
      createdBy: 'user_1',
    });
    const [createdRecord] = await storage.listByTenant('t1');

    const rotated = await rotatable.rotate(created.id, {
      gracePeriodMs: 1_000,
      createdBy: 'user_2',
    });
    await service.revoke(rotated.id);

    await expect(
      service.verify(`nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`),
    ).rejects.toMatchObject({
      code: ApiKeyErrorCode.Invalid,
    });

    expect(events.map((event) => event.type)).toEqual([
      'api_key.created',
      'api_key.rotated',
      'api_key.revoked',
      'api_key.auth_failed',
    ]);
    expect(events[0]).toMatchObject({
      type: 'api_key.created',
      keyId: created.id,
      tenantId: 't1',
      prefix: createdRecord.prefix,
      environment: 'live',
      scopes: ['reports:read'],
      createdBy: 'user_1',
    });
    expect(events[1]).toMatchObject({
      type: 'api_key.rotated',
      tenantId: 't1',
      oldKeyId: created.id,
      newKeyId: rotated.id,
      environment: 'live',
      scopes: ['reports:read'],
      createdBy: 'user_2',
    });
    expect(events[2]).toMatchObject({
      type: 'api_key.revoked',
      keyId: rotated.id,
      tenantId: 't1',
      environment: 'live',
    });
    expect(events[3]).toMatchObject({
      type: 'api_key.auth_failed',
      prefix: 'zzzzzzzzzzzz',
      code: ApiKeyErrorCode.Invalid,
    });

    const serializedEvents = JSON.stringify(events);
    expect(serializedEvents).not.toContain(created.key);
    expect(serializedEvents).not.toContain(rotated.key);
    expect(serializedEvents).not.toContain(createdRecord.hash);
  });

  it('isolates lifecycle event hook failures and reports them to onEventError', async () => {
    const onEventError = jest.fn();
    const { service } = svc({
      onEvent: () => {
        throw new Error('sink down');
      },
      onEventError,
    });

    await expect(
      service.create({
        tenantId: 't1',
        name: 'primary',
        scopes: [{ resource: 'reports', level: 'read' }],
      }),
    ).resolves.toMatchObject({ id: 'key_1' });

    expect(onEventError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({
        type: 'api_key.created',
      }),
    );
  });

  it('emits api_key_used only when usage events are enabled', async () => {
    const disabledEvents: Record<string, unknown>[] = [];
    const disabled = svc({
      onEvent: (event) => {
        disabledEvents.push(event);
      },
    });
    const disabledCreated = await disabled.service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    await disabled.service.verify(disabledCreated.key);

    const enabledEvents: Record<string, unknown>[] = [];
    const enabled = svc({
      onEvent: (event) => {
        enabledEvents.push(event);
      },
      emitUsageEvents: true,
    });
    const enabledCreated = await enabled.service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    await enabled.service.verify(enabledCreated.key);

    expect(disabledEvents.map((event) => event.type)).toEqual(['api_key.created']);
    expect(enabledEvents.map((event) => event.type)).toEqual(['api_key.created', 'api_key.used']);
    expect(enabledEvents[1]).toMatchObject({
      type: 'api_key.used',
      keyId: enabledCreated.id,
      tenantId: 't1',
      environment: 'live',
      scopes: ['reports:read'],
    });
  });

  it('applies a default expiration from ttlPolicy', async () => {
    const { service, storage } = svc({
      ttlPolicy: { defaultExpiresInMs: 60_000 },
    });

    await service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'reports', level: 'read' }],
    });

    const [record] = await storage.listByTenant('t1');
    expect(record.expiresAt?.toISOString()).toBe('2026-01-01T00:01:00.000Z');
  });

  it('rejects never-expiring keys when ttlPolicy disallows them', async () => {
    const { service } = svc({
      ttlPolicy: { allowNeverExpires: false },
    });

    await expect(
      service.create({
        tenantId: 't1',
        name: 'primary',
        scopes: [{ resource: 'reports', level: 'read' }],
      }),
    ).rejects.toThrow(/expiration is required/);
  });

  it('rejects create and rotate expirations beyond ttlPolicy maxExpiresInMs', async () => {
    const { service } = svc({
      ttlPolicy: { maxExpiresInMs: 60_000 },
    });
    const created = await service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'reports', level: 'read' }],
      expiresAt: new Date('2026-01-01T00:01:00Z'),
    });
    const rotatable = service as RotatableService;

    await expect(
      service.create({
        tenantId: 't1',
        name: 'too long',
        scopes: [{ resource: 'reports', level: 'read' }],
        expiresAt: new Date('2026-01-01T00:01:01Z'),
      }),
    ).rejects.toThrow(/expiration exceeds maximum/);

    await expect(
      rotatable.rotate(created.id, {
        expiresAt: new Date('2026-01-01T00:01:01Z'),
      }),
    ).rejects.toThrow(/expiration exceeds maximum/);
  });
});

describe('ApiKeysService verification metrics', () => {
  it('emits bounded-cardinality metrics for stable verification outcomes', async () => {
    const metrics: ApiKeyVerificationMetric[] = [];
    let monotonicTime = 0;
    const { service } = svc({
      onMetric: (metric) => {
        metrics.push(metric);
      },
      monotonicClock: () => {
        monotonicTime += 5;
        return monotonicTime;
      },
    });

    const valid = await service.create({
      tenantId: 'tenant_metrics',
      name: 'valid',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    await service.verify(valid.key);

    await expect(service.verify('garbage')).rejects.toMatchObject({
      code: ApiKeyErrorCode.Malformed,
    });
    await expect(
      service.verify(`nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`),
    ).rejects.toMatchObject({ code: ApiKeyErrorCode.Invalid });

    const revoked = await service.create({
      tenantId: 'tenant_metrics',
      name: 'revoked',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    await service.revoke(revoked.id);
    await expect(service.verify(revoked.key)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Revoked,
    });

    const expired = await service.create({
      tenantId: 'tenant_metrics',
      name: 'expired',
      scopes: [{ resource: 'reports', level: 'read' }],
      expiresAt: new Date('2025-01-01T00:00:00Z'),
    });
    await expect(service.verify(expired.key)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Expired,
    });

    expect(metrics.map((metric) => metric.outcome)).toEqual([
      'success',
      'malformed',
      'invalid',
      'revoked',
      'expired',
    ]);
    expect(metrics[0]).toEqual({
      type: 'api_key.verification',
      outcome: 'success',
      durationMs: 5,
      environment: 'live',
    });
    expect(Object.keys(metrics[0]).sort()).toEqual([
      'durationMs',
      'environment',
      'outcome',
      'type',
    ]);
    expect(JSON.stringify(metrics)).not.toContain(valid.id);
    expect(JSON.stringify(metrics)).not.toContain('tenant_metrics');
    expect(JSON.stringify(metrics)).not.toContain(valid.key);
  });

  it('isolates synchronous and asynchronous metric sink failures', async () => {
    const syncMetricError = jest.fn();
    const sync = svc({
      onMetric: () => {
        throw new Error('sync metric sink down');
      },
      onMetricError: syncMetricError,
    });
    const syncKey = await sync.service.create({
      tenantId: 't1',
      name: 'sync',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await expect(sync.service.verify(syncKey.key)).resolves.toMatchObject({ keyId: syncKey.id });
    expect(syncMetricError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({ outcome: 'success' }),
    );

    const asyncMetricError = jest.fn();
    const asyncSink = svc({
      onMetric: () => Promise.reject(new Error('async metric sink down')),
      onMetricError: asyncMetricError,
    });
    const asyncKey = await asyncSink.service.create({
      tenantId: 't1',
      name: 'async',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await expect(asyncSink.service.verify(asyncKey.key)).resolves.toMatchObject({
      keyId: asyncKey.id,
    });
    await Promise.resolve();
    expect(asyncMetricError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({ outcome: 'success' }),
    );
  });

  it('reports unexpected verification failures as error metrics', async () => {
    class FailingLookupStorage extends InMemoryApiKeyStorage {
      override async findByPrefix(): Promise<ApiKeyRecord | null> {
        throw new Error('storage unavailable');
      }
    }

    const metrics: ApiKeyVerificationMetric[] = [];
    const service = new ApiKeysService({
      storage: new FailingLookupStorage(),
      hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
      namespace: 'nk',
      onMetric: (metric) => {
        metrics.push(metric);
      },
    });

    await expect(service.verify(`nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`)).rejects.toThrow(
      'storage unavailable',
    );
    expect(metrics).toEqual([
      expect.objectContaining({
        type: 'api_key.verification',
        outcome: 'error',
      }),
    ]);
  });
});

describe('ApiKeysService.verify', () => {
  it('returns context for a valid key', async () => {
    const { service } = svc();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'invoices', level: 'write' }],
    });

    const context = await service.verify(key);

    expect(context.tenantId).toBe('t1');
    expect(context.scopes).toEqual(['invoices:write']);
    expect(context.environment).toBe('live');
  });

  it('throws api_key_invalid for wrong secret', async () => {
    const { service } = svc();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    const tampered = key.slice(0, -1) + (key.at(-1) === 'a' ? 'b' : 'a');

    await expect(service.verify(tampered)).rejects.toMatchObject({ code: 'api_key_invalid' });
  });

  it.each([
    ['active', null],
    ['revoked', 'revoked'],
    ['expired', 'expired'],
  ] as const)(
    'does not reveal the %s lifecycle state until the secret is authenticated',
    async (_state, lifecycle) => {
      const { service } = svc();
      const created = await service.create({
        tenantId: 't1',
        name: lifecycle ?? 'active',
        scopes: [{ resource: 'r', level: 'read' }],
        ...(lifecycle === 'expired'
          ? { expiresAt: new Date('2025-01-01T00:00:00Z') }
          : {}),
      });
      if (lifecycle === 'revoked') {
        await service.revoke(created.id);
      }

      const wrongSecret = `${created.key.slice(0, -1)}${created.key.endsWith('a') ? 'b' : 'a'}`;
      await expect(service.verify(wrongSecret)).rejects.toMatchObject({
        code: ApiKeyErrorCode.Invalid,
      });

      if (lifecycle === 'revoked') {
        await expect(service.verify(created.key)).rejects.toMatchObject({
          code: ApiKeyErrorCode.Revoked,
        });
      } else if (lifecycle === 'expired') {
        await expect(service.verify(created.key)).rejects.toMatchObject({
          code: ApiKeyErrorCode.Expired,
        });
      } else {
        await expect(service.verify(created.key)).resolves.toMatchObject({ keyId: created.id });
      }
    },
  );

  it('uses one real verify for known prefixes and one dummy verify for unknown prefixes', async () => {
    const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
    const verify = jest.spyOn(hasher, 'verify');
    const dummyVerify = jest.spyOn(hasher, 'dummyVerify');
    const { service } = svc({ hasher });
    const created = await service.create({
      tenantId: 't1',
      name: 'known',
      scopes: [{ resource: 'r', level: 'read' }],
    });
    verify.mockClear();
    dummyVerify.mockClear();

    const wrongSecret = `${created.key.slice(0, -1)}${created.key.endsWith('a') ? 'b' : 'a'}`;
    await expect(service.verify(wrongSecret)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Invalid,
    });
    expect(verify).toHaveBeenCalledTimes(1);
    expect(dummyVerify).not.toHaveBeenCalled();

    verify.mockClear();
    await expect(
      service.verify(`nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`),
    ).rejects.toMatchObject({ code: ApiKeyErrorCode.Invalid });
    expect(dummyVerify).toHaveBeenCalledTimes(1);
    expect(verify).not.toHaveBeenCalled();
  });

  it('throws api_key_invalid for unknown prefix', async () => {
    const { service } = svc();
    const fake = `nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`;

    await expect(service.verify(fake)).rejects.toMatchObject({ code: 'api_key_invalid' });
  });

  it('throws api_key_malformed for garbage input', async () => {
    const { service } = svc();

    await expect(service.verify('garbage')).rejects.toMatchObject({
      code: 'api_key_malformed',
    });
  });

  it('throws api_key_revoked for revoked keys', async () => {
    const { service } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.revoke(created.id);

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: 'api_key_revoked',
    });
  });

  it('throws api_key_expired for expired keys', async () => {
    const { service, storage } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
      expiresAt: new Date('2025-01-01T00:00:00Z'),
    });

    const record = (await storage.listByTenant('t1'))[0];
    expect(record.expiresAt?.getTime()).toBeLessThan(new Date('2026-01-01').getTime());

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: 'api_key_expired',
    });
  });

  it('maps unknown pepper versions to api_key_invalid and reports auth failure', async () => {
    const onAuthFailed = jest.fn();
    const { service, storage } = svc({
      hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
      onAuthFailed,
    });

    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    const [record] = await storage.listByTenant('t1');
    record.pepperVersion = 99;

    const internalRecords = storage as unknown as {
      records: Map<string, typeof record>;
    };
    internalRecords.records.set(record.id, record);

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: ApiKeyErrorCode.Invalid,
    });
    expect(onAuthFailed).toHaveBeenCalledWith(record.prefix, ApiKeyErrorCode.Invalid);
  });

  it('returns context even when lastUsedAt tracking fails in the background', async () => {
    class TouchFailingStorage extends InMemoryApiKeyStorage {
      override async touchLastUsed(): Promise<void> {
        throw new Error('touch failed');
      }
    }

    const storage = new TouchFailingStorage();
    const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
    const service = new ApiKeysService({
      storage,
      hasher,
      namespace: 'nk',
      idFactory: (() => {
        let counter = 0;
        return () => `key_${++counter}`;
      })(),
      clock: () => new Date('2026-01-01T00:00:00Z'),
    });

    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await expect(service.verify(created.key)).resolves.toMatchObject({
      tenantId: 't1',
      environment: 'live',
      scopes: ['r:read'],
    });

    await Promise.resolve();
  });
});

describe('ApiKeysService.list and revoke', () => {
  it('list excludes revoked by default', async () => {
    const { service } = svc();
    const first = await service.create({
      tenantId: 't1',
      name: 'a',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.create({
      tenantId: 't1',
      name: 'b',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.revoke(first.id);

    const listed = await service.list('t1');
    expect(listed.map((record) => record.name)).toEqual(['b']);
  });
});
