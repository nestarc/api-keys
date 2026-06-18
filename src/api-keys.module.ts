import { DynamicModule, Module, Provider } from '@nestjs/common';
import { ApiKeysGuard } from './api-keys.guard';
import { ApiKeysService, ApiKeysServiceDeps } from './api-keys.service';
import {
  API_KEY_CONTEXT_WRITER,
  ApiKeyContextWriter,
} from './context';
import { Sha256Hasher } from './hasher';
import type { ApiKeyStorage } from './storage/api-key-storage.interface';
import type { ApiKeyEventSink, ApiKeyTtlPolicy } from './types';

export const API_KEYS_OPTIONS = Symbol('API_KEYS_OPTIONS');
export const API_KEYS_STORAGE = Symbol('API_KEYS_STORAGE');

export interface ApiKeysModuleOptions {
  namespace?: string;
  peppers: Record<number, string>;
  currentPepperVersion?: number;
  debounceMs?: number;
  storage: ApiKeyStorage;
  onAuthFailed?: ApiKeysServiceDeps['onAuthFailed'];
  onEvent?: ApiKeyEventSink;
  onEventError?: ApiKeysServiceDeps['onEventError'];
  emitUsageEvents?: boolean;
  ttlPolicy?: ApiKeyTtlPolicy;
  contextWriter?: ApiKeyContextWriter;
}

@Module({})
export class ApiKeysModule {
  static forRoot(options: ApiKeysModuleOptions): DynamicModule {
    const currentPepperVersion = resolveCurrentPepperVersion(options);
    const providers: Provider[] = [
      { provide: API_KEYS_OPTIONS, useValue: options },
      { provide: API_KEYS_STORAGE, useValue: options.storage },
      { provide: API_KEY_CONTEXT_WRITER, useValue: options.contextWriter },
      {
        provide: ApiKeysService,
        useFactory: () =>
          new ApiKeysService({
            storage: options.storage,
            hasher: new Sha256Hasher({
              peppers: options.peppers,
              currentVersion: currentPepperVersion,
            }),
            namespace: options.namespace ?? 'nk',
            debounceMs: options.debounceMs,
            onAuthFailed: options.onAuthFailed,
            onEvent: options.onEvent,
            onEventError: options.onEventError,
            emitUsageEvents: options.emitUsageEvents,
            ttlPolicy: options.ttlPolicy,
          }),
      },
      ApiKeysGuard,
    ];

    return {
      module: ApiKeysModule,
      providers,
      exports: [ApiKeysService, ApiKeysGuard],
      global: true,
    };
  }
}

function resolveCurrentPepperVersion(options: ApiKeysModuleOptions): number {
  const configuredVersions = Object.keys(options.peppers).map(Number).filter(Number.isFinite);
  if (configuredVersions.length === 0) {
    throw new Error('ApiKeysModule requires at least one pepper');
  }

  const currentPepperVersion = options.currentPepperVersion ?? Math.max(...configuredVersions);
  if (!options.peppers[currentPepperVersion]) {
    throw new Error(`ApiKeysModule current pepper version ${currentPepperVersion} is not configured`);
  }

  return currentPepperVersion;
}
