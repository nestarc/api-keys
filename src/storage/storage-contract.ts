import { strict as assert } from 'node:assert';

import type { ApiKeyRecord } from '../types';
import type { ApiKeyStorage } from './api-key-storage.interface';

export interface ApiKeyStorageContractOptions {
  /** Human-readable adapter name used in failures and the result. */
  name: string;
  /** Create an isolated adapter backed by disposable test data. */
  createStorage: () => ApiKeyStorage | Promise<ApiKeyStorage>;
  /** Release adapter resources and remove contract fixture data. */
  disposeStorage?: (storage: ApiKeyStorage) => void | Promise<void>;
  /** Number of simultaneous rotation attempts. Defaults to 8 and must be at least 2. */
  rotationConcurrency?: number;
}

export interface ApiKeyStorageContractResult {
  name: string;
  checks: string[];
}

export class ApiKeyStorageContractError extends Error {
  readonly adapterName: string;
  readonly check: string;

  constructor(adapterName: string, check: string, cause: unknown) {
    super(`ApiKeyStorage contract failed for ${adapterName}: ${check}`, { cause });
    this.name = 'ApiKeyStorageContractError';
    this.adapterName = adapterName;
    this.check = check;
  }
}

let contractRunSequence = 0;

/**
 * Run the public, framework-independent contract for a custom `ApiKeyStorage` adapter.
 *
 * The runner uses Node assertions and throws `ApiKeyStorageContractError` on the first failure.
 * It does not depend on Jest, Vitest, Mocha, or their globals.
 */
export async function runApiKeyStorageContract(
  options: ApiKeyStorageContractOptions,
): Promise<ApiKeyStorageContractResult> {
  const concurrency = options.rotationConcurrency ?? 8;
  if (!Number.isSafeInteger(concurrency) || concurrency < 2) {
    throw new RangeError('rotationConcurrency must be a safe integer of at least 2');
  }

  const runId = `${Date.now().toString(36)}_${++contractRunSequence}`;
  const checks: string[] = [];
  let storage: ApiKeyStorage;
  let contractFailure: unknown;
  let contractFailed = false;
  try {
    storage = await options.createStorage();
  } catch (cause) {
    throw new ApiKeyStorageContractError(options.name, 'create storage', cause);
  }

  const check = async (name: string, execute: () => Promise<void>): Promise<void> => {
    try {
      await execute();
      checks.push(name);
    } catch (cause) {
      throw new ApiKeyStorageContractError(options.name, name, cause);
    }
  };

  try {
    await check('insert and lookup preserve records', async () => {
      const record = fixture(runId, 'lookup', {
        lastUsedAt: new Date('2026-01-02T00:00:00Z'),
        expiresAt: new Date('2026-03-01T00:00:00Z'),
      });
      const expected = snapshot(record);
      await storage.insert(record);
      mutateRecord(record);

      assert.deepEqual(snapshot(await required(storage.findById(record.id))), expected);
      assert.deepEqual(snapshot(await required(storage.findByPrefix(record.prefix))), expected);
      assert.equal(await storage.findById(`${runId}_missing`), null);
      assert.equal(await storage.findByPrefix(`${runId}_missing`), null);
    });

    await check('lookup results are defensive copies', async () => {
      const record = fixture(runId, 'copy', {
        lastUsedAt: new Date('2026-01-02T00:00:00Z'),
        expiresAt: new Date('2026-03-01T00:00:00Z'),
      });
      await storage.insert(record);
      const expected = snapshot(record);

      for (const loaded of [
        await storage.findById(record.id),
        await storage.findByPrefix(record.prefix),
        (await storage.listByTenant(record.tenantId))[0] ?? null,
      ]) {
        mutateRecord(await required(Promise.resolve(loaded)));
        assert.deepEqual(snapshot(await required(storage.findById(record.id))), expected);
      }
    });

    await check('tenant listing filters and orders lifecycle history', async () => {
      const tenantId = `${runId}_list_tenant`;
      const records = [
        fixture(runId, 'list_active_b', {
          tenantId,
          createdAt: new Date('2026-01-04T00:00:00Z'),
        }),
        fixture(runId, 'list_grace', {
          tenantId,
          rotatedAt: new Date('2026-02-01T00:00:00Z'),
          replacedByKeyId: `${runId}_replacement`,
          expiresAt: new Date('2026-02-08T00:00:00Z'),
          createdAt: new Date('2026-01-02T00:00:00Z'),
        }),
        fixture(runId, 'list_expired', {
          tenantId,
          expiresAt: new Date('2026-02-01T00:00:00Z'),
          createdAt: new Date('2026-01-03T00:00:00Z'),
        }),
        fixture(runId, 'list_revoked', {
          tenantId,
          revokedAt: new Date('2026-02-01T00:00:00Z'),
          createdAt: new Date('2026-01-05T00:00:00Z'),
        }),
        fixture(runId, 'list_active_a', {
          tenantId,
          createdAt: new Date('2026-01-04T00:00:00Z'),
        }),
        fixture(runId, 'list_other_tenant', { tenantId: `${tenantId}_other` }),
      ];
      for (const record of records) await storage.insert(record);

      assert.deepEqual(
        (await storage.listByTenant(tenantId)).map(({ id }) => id),
        records
          .slice(0, 5)
          .filter(({ revokedAt }) => revokedAt === null)
          .sort(compare)
          .map(({ id }) => id),
      );
      assert.deepEqual(
        (await storage.listByTenant(tenantId, { includeRevoked: true })).map(({ id }) => id),
        records
          .slice(0, 5)
          .sort(compare)
          .map(({ id }) => id),
      );
    });

    await check('revoke and last-used mutations copy Date inputs', async () => {
      const revoked = fixture(runId, 'revoke');
      const touched = fixture(runId, 'touch');
      const revokedAt = new Date('2026-02-01T00:00:00Z');
      const lastUsedAt = new Date('2026-02-02T00:00:00Z');
      await storage.insert(revoked);
      await storage.insert(touched);
      await storage.markRevoked(revoked.id, revokedAt);
      await storage.touchLastUsed(touched.id, lastUsedAt);
      revokedAt.setUTCFullYear(2040);
      lastUsedAt.setUTCFullYear(2040);

      assert.equal(
        (await required(storage.findById(revoked.id))).revokedAt?.toISOString(),
        '2026-02-01T00:00:00.000Z',
      );
      assert.equal(
        (await required(storage.findById(touched.id))).lastUsedAt?.toISOString(),
        '2026-02-02T00:00:00.000Z',
      );
    });

    await check('rotation links records and copies every Date input', async () => {
      const oldRecord = fixture(runId, 'rotate_old');
      const newRecord = fixture(runId, 'rotate_new', {
        lastUsedAt: new Date('2026-01-12T00:00:00Z'),
        expiresAt: new Date('2026-04-01T00:00:00Z'),
        revokedAt: new Date('2026-01-15T00:00:00Z'),
        rotatedAt: new Date('2026-01-14T00:00:00Z'),
        createdAt: new Date('2026-01-10T00:00:00Z'),
      });
      const expectedNew = snapshot(newRecord);
      const rotatedAt = new Date('2026-02-01T00:00:00Z');
      const oldExpiresAt = new Date('2026-02-08T00:00:00Z');
      await storage.insert(oldRecord);
      assert.equal(
        await storage.rotate({ oldKeyId: oldRecord.id, newRecord, oldExpiresAt, rotatedAt }),
        'rotated',
      );
      mutateRecord(newRecord);
      oldExpiresAt.setUTCFullYear(2040);
      rotatedAt.setUTCFullYear(2040);

      assert.deepEqual(await storage.findById(oldRecord.id), {
        ...oldRecord,
        expiresAt: new Date('2026-02-08T00:00:00Z'),
        rotatedAt: new Date('2026-02-01T00:00:00Z'),
        replacedByKeyId: newRecord.id,
      });
      assert.deepEqual(snapshot(await required(storage.findById(newRecord.id))), expectedNew);
    });

    await check('rotation rejects every terminal old-key state', async () => {
      const states: Array<[string, Partial<ApiKeyRecord> | null]> = [
        ['missing', null],
        ['revoked', { revokedAt: new Date('2026-01-31T00:00:00Z') }],
        ['rotated', { rotatedAt: new Date('2026-01-31T00:00:00Z') }],
        ['replaced', { replacedByKeyId: `${runId}_existing` }],
        ['expired', { expiresAt: new Date('2026-02-01T00:00:00Z') }],
      ];
      for (const [state, overrides] of states) {
        const oldRecord = fixture(runId, `terminal_old_${state}`, overrides ?? {});
        const newRecord = fixture(runId, `terminal_new_${state}`);
        if (overrides !== null) await storage.insert(oldRecord);
        assert.equal(
          await storage.rotate({
            oldKeyId: oldRecord.id,
            newRecord,
            oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
            rotatedAt: new Date('2026-02-01T00:00:00Z'),
          }),
          'not_rotatable',
        );
        assert.equal(await storage.findById(newRecord.id), null);
      }
    });

    await check('rotation is exactly once under concurrency', async () => {
      const oldRecord = fixture(runId, 'concurrent_old');
      await storage.insert(oldRecord);
      const results = await Promise.all(
        Array.from({ length: concurrency }, (_, index) =>
          storage.rotate({
            oldKeyId: oldRecord.id,
            newRecord: fixture(runId, `concurrent_new_${index}`),
            oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
            rotatedAt: new Date('2026-02-01T00:00:00Z'),
          }),
        ),
      );
      assert.equal(results.filter((result) => result === 'rotated').length, 1);
      assert.equal(results.filter((result) => result === 'not_rotatable').length, concurrency - 1);
      const oldFound = await required(storage.findById(oldRecord.id));
      assert.notEqual(oldFound.replacedByKeyId, null);
      const replacements = await Promise.all(
        Array.from({ length: concurrency }, (_, index) =>
          storage.findById(fixtureId(runId, `concurrent_new_${index}`)),
        ),
      );
      assert.equal(replacements.filter(Boolean).length, 1);
      assert.equal(replacements.find(Boolean)?.id, oldFound.replacedByKeyId);
    });

    if (storage.revokeForTenant) {
      await check('tenant-bound revoke is atomic', async () => {
        const record = fixture(runId, 'tenant_revoke', { tenantId: `${runId}_tenant_a` });
        await storage.insert(record);
        assert.equal(
          await storage.revokeForTenant!({
            keyId: record.id,
            expectedTenantId: `${runId}_tenant_b`,
            revokedAt: new Date('2026-02-01T00:00:00Z'),
          }),
          'not_found',
        );
        assert.equal((await required(storage.findById(record.id))).revokedAt, null);
        assert.equal(
          await storage.revokeForTenant!({
            keyId: record.id,
            expectedTenantId: record.tenantId,
            revokedAt: new Date('2026-02-01T00:00:00Z'),
          }),
          'revoked',
        );
      });
    }

    if (storage.rotateForTenant) {
      await check('tenant-bound rotation is atomic', async () => {
        const oldRecord = fixture(runId, 'tenant_rotate_old', {
          tenantId: `${runId}_tenant_a`,
        });
        const newRecord = fixture(runId, 'tenant_rotate_new', {
          tenantId: `${runId}_tenant_a`,
        });
        await storage.insert(oldRecord);
        assert.equal(
          await storage.rotateForTenant!({
            oldKeyId: oldRecord.id,
            expectedTenantId: `${runId}_tenant_b`,
            newRecord,
            oldExpiresAt: new Date('2026-02-08T00:00:00Z'),
            rotatedAt: new Date('2026-02-01T00:00:00Z'),
          }),
          'not_rotatable',
        );
        assert.equal(await storage.findById(newRecord.id), null);
      });
    }
  } catch (cause) {
    contractFailure = cause;
    contractFailed = true;
  }

  if (options.disposeStorage) {
    try {
      await options.disposeStorage(storage);
    } catch (cause) {
      throw new ApiKeyStorageContractError(options.name, 'dispose storage', cause);
    }
  }
  if (contractFailed) {
    throw contractFailure;
  }

  return { name: options.name, checks };
}

function fixture(
  runId: string,
  label: string,
  overrides: Partial<ApiKeyRecord> = {},
): ApiKeyRecord {
  return {
    id: fixtureId(runId, label),
    tenantId: `${runId}_tenant`,
    name: label,
    environment: 'live',
    prefix: `${runId}_${label}_prefix`,
    hash: 'f'.repeat(64),
    pepperVersion: 1,
    scopes: ['invoices:read'],
    allowedIpCidrs: ['203.0.113.0/24'],
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    rotatedAt: null,
    replacedByKeyId: null,
    createdBy: null,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

function fixtureId(runId: string, label: string): string {
  return `${runId}_${label}`;
}

function compare(left: ApiKeyRecord, right: ApiKeyRecord): number {
  return right.createdAt.getTime() - left.createdAt.getTime() || left.id.localeCompare(right.id);
}

async function required(record: Promise<ApiKeyRecord | null>): Promise<ApiKeyRecord> {
  const resolved = await record;
  assert.notEqual(resolved, null);
  return resolved!;
}

function mutateRecord(record: ApiKeyRecord): void {
  record.scopes.push('mutated:write');
  record.allowedIpCidrs?.push('198.51.100.1');
  for (const field of ['lastUsedAt', 'expiresAt', 'revokedAt', 'rotatedAt', 'createdAt'] as const) {
    record[field]?.setUTCFullYear(2040);
  }
}

function snapshot(record: ApiKeyRecord): unknown {
  return {
    ...record,
    scopes: [...record.scopes],
    allowedIpCidrs: [...(record.allowedIpCidrs ?? [])],
    lastUsedAt: record.lastUsedAt?.getTime() ?? null,
    expiresAt: record.expiresAt?.getTime() ?? null,
    revokedAt: record.revokedAt?.getTime() ?? null,
    rotatedAt: record.rotatedAt?.getTime() ?? null,
    createdAt: record.createdAt.getTime(),
  };
}
