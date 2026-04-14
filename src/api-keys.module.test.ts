import { ApiKeysModule } from './api-keys.module';
import { InMemoryApiKeyStorage } from './storage/in-memory-storage';

describe('ApiKeysModule.forRoot', () => {
  it('throws a clear error when peppers is empty', () => {
    expect(() =>
      ApiKeysModule.forRoot({
        peppers: {},
        storage: new InMemoryApiKeyStorage(),
      }),
    ).toThrow(/at least one pepper/);
  });
});
