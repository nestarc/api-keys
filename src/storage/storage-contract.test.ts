import { InMemoryApiKeyStorage } from './in-memory-storage';
import type { ApiKeyStorage } from './api-key-storage.interface';
import { ApiKeyStorageContractError, runApiKeyStorageContract } from './storage-contract';

describe('runApiKeyStorageContract', () => {
  it('runs required and optional capabilities without test-framework globals', async () => {
    const result = await runApiKeyStorageContract({
      name: 'in-memory adapter',
      createStorage: () => new InMemoryApiKeyStorage(),
      rotationConcurrency: 4,
    });

    expect(result.name).toBe('in-memory adapter');
    expect(result.checks).toEqual([
      'insert and lookup preserve records',
      'lookup results are defensive copies',
      'tenant listing filters and orders lifecycle history',
      'revoke and last-used mutations copy Date inputs',
      'rotation links records and copies every Date input',
      'rotation rejects every terminal old-key state',
      'rotation is exactly once under concurrency',
      'tenant-bound revoke is atomic',
      'tenant-bound rotation is atomic',
    ]);
  });

  it('supports adapters that implement only required interface methods', async () => {
    const result = await runApiKeyStorageContract({
      name: 'required-only adapter',
      createStorage: () => {
        const storage = new InMemoryApiKeyStorage();
        return new Proxy(storage, {
          get(target, property, receiver) {
            if (property === 'revokeForTenant' || property === 'rotateForTenant') return undefined;
            const value: unknown = Reflect.get(target, property, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        }) as ApiKeyStorage;
      },
    });

    expect(result.checks).toHaveLength(7);
  });

  it('wraps setup, check, and cleanup failures with stable context', async () => {
    const setupFailure = await runApiKeyStorageContract({
      name: 'setup failure',
      createStorage: () => Promise.reject(new Error('offline')),
    }).catch((error: unknown) => error);
    expect(setupFailure).toMatchObject({
      name: 'ApiKeyStorageContractError',
      adapterName: 'setup failure',
      check: 'create storage',
    });

    class BrokenLookupStorage extends InMemoryApiKeyStorage {
      override async findById(): Promise<null> {
        return null;
      }
    }
    const checkFailure = await runApiKeyStorageContract({
      name: 'broken lookup',
      createStorage: () => new BrokenLookupStorage(),
    }).catch((error: unknown) => error);
    expect(checkFailure).toBeInstanceOf(ApiKeyStorageContractError);
    expect(checkFailure).toMatchObject({
      adapterName: 'broken lookup',
      check: 'insert and lookup preserve records',
    });

    const cleanupFailure = await runApiKeyStorageContract({
      name: 'cleanup failure',
      createStorage: () => new InMemoryApiKeyStorage(),
      disposeStorage: () => Promise.reject(new Error('cleanup failed')),
    }).catch((error: unknown) => error);
    expect(cleanupFailure).toMatchObject({
      adapterName: 'cleanup failure',
      check: 'dispose storage',
    });
  });

  it.each([1, 2.5, Number.MAX_SAFE_INTEGER + 1])(
    'rejects invalid rotation concurrency %s',
    async (rotationConcurrency) => {
      await expect(
        runApiKeyStorageContract({
          name: 'invalid concurrency',
          createStorage: () => new InMemoryApiKeyStorage(),
          rotationConcurrency,
        }),
      ).rejects.toThrow('rotationConcurrency must be a safe integer of at least 2');
    },
  );
});
