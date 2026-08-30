import { DynamicModule, Module, Provider } from '@nestjs/common';
import { ApiKeysGuard } from './api-keys.guard';
import { ApiKeysService, ApiKeysServiceDeps } from './api-keys.service';
import {
  API_KEY_CONTEXT_WRITER,
  ApiKeyContextWriter,
} from './context';
import { Sha256Hasher } from './hasher';
import {
  API_KEY_CLIENT_IP_RESOLVER,
  ApiKeyClientIpResolver,
  defaultApiKeyClientIpResolver,
} from './ip-allowlist';
import { validateNamespace } from './input-validation';
import type { ApiKeyStorage } from './storage/api-key-storage.interface';
import type {
  ApiKeyAuthorizationMetricSink,
  ApiKeyEventSink,
  ApiKeyMetricSink,
  ApiKeyTtlPolicy,
} from './types';

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
  onMetric?: ApiKeyMetricSink;
  onMetricError?: ApiKeysServiceDeps['onMetricError'];
  onAuthorizationMetric?: ApiKeyAuthorizationMetricSink;
  onAuthorizationMetricError?: ApiKeysServiceDeps['onAuthorizationMetricError'];
  emitUsageEvents?: boolean;
  ttlPolicy?: ApiKeyTtlPolicy;
  contextWriter?: ApiKeyContextWriter;
  clientIpResolver?: ApiKeyClientIpResolver;
}

@Module({})
export class ApiKeysModule {
  static forRoot(options: ApiKeysModuleOptions): DynamicModule {
    const namespace = validateNamespace(options.namespace ?? 'nk');
    const currentPepperVersion = resolveCurrentPepperVersion(options);
    const providers: Provider[] = [
      { provide: API_KEYS_OPTIONS, useValue: options },
      { provide: API_KEYS_STORAGE, useValue: options.storage },
      { provide: API_KEY_CONTEXT_WRITER, useValue: options.contextWriter },
      {
        provide: API_KEY_CLIENT_IP_RESOLVER,
        useValue: options.clientIpResolver ?? defaultApiKeyClientIpResolver,
      },
      {
        provide: ApiKeysService,
        useFactory: () =>
          new ApiKeysService({
            storage: options.storage,
            hasher: new Sha256Hasher({
              peppers: options.peppers,
              currentVersion: currentPepperVersion,
            }),
            namespace,
            debounceMs: options.debounceMs,
            onAuthFailed: options.onAuthFailed,
            onEvent: options.onEvent,
            onEventError: options.onEventError,
            onMetric: options.onMetric,
            onMetricError: options.onMetricError,
            onAuthorizationMetric: options.onAuthorizationMetric,
            onAuthorizationMetricError: options.onAuthorizationMetricError,
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
