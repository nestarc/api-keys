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

  it('wires the client IP resolver and verification metric sink', async () => {
    const clientIpResolver = jest.fn().mockReturnValue('203.0.113.42');
    const onMetric = jest.fn();
    const moduleRef = await Test.createTestingModule({
      imports: [
        ApiKeysModule.forRoot({
          namespace: 'nk',
          peppers: { 1: 'p'.repeat(32) },
          storage: new InMemoryApiKeyStorage(),
          clientIpResolver,
          onMetric,
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
  });
});
