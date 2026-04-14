import { DynamicModule, Module, Provider } from '@nestjs/common';
import { ApiKeysService, ApiKeysServiceDeps } from './api-keys.service';
import { Sha256Hasher } from './hasher';
import type { ApiKeyStorage } from './storage/api-key-storage.interface';

export const API_KEYS_OPTIONS = Symbol('API_KEYS_OPTIONS');
export const API_KEYS_STORAGE = Symbol('API_KEYS_STORAGE');

export interface ApiKeysModuleOptions {
  namespace?: string;
  peppers: Record<number, string>;
  currentPepperVersion?: number;
  debounceMs?: number;
  storage: ApiKeyStorage;
  onAuthFailed?: ApiKeysServiceDeps['onAuthFailed'];
}

@Module({})
export class ApiKeysModule {
  static forRoot(options: ApiKeysModuleOptions): DynamicModule {
    const providers: Provider[] = [
      { provide: API_KEYS_OPTIONS, useValue: options },
      { provide: API_KEYS_STORAGE, useValue: options.storage },
      {
        provide: ApiKeysService,
        useFactory: () =>
          new ApiKeysService({
            storage: options.storage,
            hasher: new Sha256Hasher({
              peppers: options.peppers,
              currentVersion:
                options.currentPepperVersion ??
                Math.max(...Object.keys(options.peppers).map(Number)),
            }),
            namespace: options.namespace ?? 'nk',
            debounceMs: options.debounceMs,
            onAuthFailed: options.onAuthFailed,
          }),
      },
    ];

    return {
      module: ApiKeysModule,
      providers,
      exports: [ApiKeysService],
      global: true,
    };
  }
}
