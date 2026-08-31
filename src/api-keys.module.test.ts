import { Test } from '@nestjs/testing';
import { ApiKeysModule } from './api-keys.module';
import { ApiKeysService } from './api-keys.service';
import { API_KEY_CLIENT_IP_RESOLVER } from './ip-allowlist';
import { InMemoryApiKeyStorage } from './storage/in-memory-storage';

describe('ApiKeysModule.forRoot', () => {
  it.each(['', 'under_score', 'punctuation!', 'a'.repeat(33)])(
    'rejects invalid namespace %p during module configuration',
    (namespace) => {
      expect(() =>
        ApiKeysModule.forRoot({
          namespace,
          peppers: { 1: 'p'.repeat(32) },
          storage: new InMemoryApiKeyStorage(),
        }),
      ).toThrow(expect.objectContaining({ code: 'api_key_invalid_input' }));
    },
  );

  it('throws a clear error when peppers is empty', () => {
    expect(() =>
      ApiKeysModule.forRoot({
        peppers: {},
        storage: new InMemoryApiKeyStorage(),
      }),
    ).toThrow(/at least one pepper/);
  });

  it('wires the client IP resolver and separate verification/authorization metric sinks', async () => {
    const clientIpResolver = jest.fn().mockReturnValue('203.0.113.42');
    const onMetric = jest.fn();
    const onAuthorizationMetric = jest.fn();
    const moduleRef = await Test.createTestingModule({
      imports: [
        ApiKeysModule.forRoot({
          namespace: 'nk',
          peppers: { 1: 'p'.repeat(32) },
          storage: new InMemoryApiKeyStorage(),
          clientIpResolver,
          onMetric,
          onAuthorizationMetric,
        }),
      ],
    }).compile();

    expect(moduleRef.get(API_KEY_CLIENT_IP_RESOLVER)).toBe(clientIpResolver);
    const service = moduleRef.get(ApiKeysService);
    const created = await service.create({
      tenantId: 't1',
      name: 'metric key',
      scopes: [{ resource: 'r', level: 'read' }],
    });
    await service.verify(created.key);

    expect(onMetric).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'api_key.verification',
        outcome: 'success',
      }),
    );

    await service.authorizeRequest({ rawKey: created.key });
    expect(onAuthorizationMetric).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'api_key.authorization',
        outcome: 'success',
      }),
    );
  });

  it('wires the operation metric sink', async () => {
    class DuplicateStorage extends InMemoryApiKeyStorage {
      override async insert(): Promise<void> {
        throw new Error('duplicate prefix');
      }
    }

    const onOperationMetric = jest.fn();
    const moduleRef = await Test.createTestingModule({
      imports: [
        ApiKeysModule.forRoot({
          namespace: 'nk',
          peppers: { 1: 'p'.repeat(32) },
          storage: new DuplicateStorage(),
          onOperationMetric,
        }),
      ],
    }).compile();

    await expect(
      moduleRef.get(ApiKeysService).create({
        tenantId: 't1',
        name: 'collision',
        scopes: [{ resource: 'r', level: 'read' }],
      }),
    ).rejects.toMatchObject({ code: 'api_key_prefix_collision' });
    expect(onOperationMetric).toHaveBeenCalledWith({
      type: 'api_key.operation',
      operation: 'create',
      outcome: 'prefix_collision_exhausted',
      attempts: 3,
    });
  });
});
