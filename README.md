# @nestarc/api-keys

[![CI](https://github.com/nestarc/api-keys/actions/workflows/ci.yml/badge.svg)](https://github.com/nestarc/api-keys/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@nestarc/api-keys.svg)](https://www.npmjs.com/package/@nestarc/api-keys)
[![license](https://img.shields.io/npm/l/@nestarc/api-keys.svg)](./LICENSE)

Secure, tenant-scoped API keys for NestJS + Prisma. SHA-256 hashed, Stripe-style scopes, test/live environments.

## Features

- **Stripe-style key format** — `<namespace>_<env>_<12-char-prefix>_<32-char-secret>`, indexable by prefix.
- **Timing-safe verification** with SHA-256 + versioned peppers, ready for rotation.
- **Tenant-scoped by design** — every key belongs to a `tenantId` and surfaces it via `ApiKeyContext`.
- **Zero-downtime user key rotation** — issue a replacement key with a configurable grace window.
- **Scope system** — resource/level pairs (`reports:read`, `reports:write`) with `write`-implies-`read` semantics.
- **Environment isolation** — `live` vs `test` keys that cannot cross over.
- **Lifecycle hooks** — creation, revocation, rotation, auth-failure, and opt-in usage events with audit-safe payloads.
- **Stable request context** — `@CurrentApiKey()`, `getApiKeyContext()`, and an optional `contextWriter` bridge.
- **TTL policy** — optional default expiration, maximum expiration, and no-never-expires enforcement.
- **Pluggable storage** — ships with Prisma and in-memory adapters plus a reusable contract suite.
- **NestJS-native** — `ApiKeysModule.forRoot`, `ApiKeysGuard`, `@RequireScope`, `@RequireEnvironment`.
- **Typed errors** — `ApiKeyError` with stable `code` values mapped to HTTP statuses.

## Install

```bash
npm install @nestarc/api-keys
```

## Quickstart

```typescript
import { Module } from '@nestjs/common';
import { ApiKeysModule, PrismaApiKeyStorage } from '@nestarc/api-keys';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

@Module({
  imports: [
    ApiKeysModule.forRoot({
      namespace: 'acme',
      peppers: { 1: process.env.API_KEY_PEPPER! },
      storage: new PrismaApiKeyStorage(prisma),
    }),
  ],
})
export class AppModule {}
```

Add the schema model from `prisma/schema.example.prisma` into your own `schema.prisma` and run a migration.

Use a product-specific `namespace` such as `acme` or `billing` instead of relying on the default `nk`. That keeps your keys distinct if multiple packages or services generate API keys in the same ecosystem.

### Protect a route

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiKeyContext,
  ApiKeysGuard,
  CurrentApiKey,
  RequireScope,
} from '@nestarc/api-keys';

@Controller('reports')
@UseGuards(ApiKeysGuard)
export class ReportsController {
  @Get()
  @RequireScope('reports', 'read')
  list(@CurrentApiKey() apiKey: ApiKeyContext) {
    return { tenantId: apiKey.tenantId, keyId: apiKey.keyId };
  }
}
```

### Issue a key

```typescript
const { id, key } = await apiKeys.create({
  tenantId: 'tenant_123',
  name: 'Primary',
  scopes: [{ resource: 'reports', level: 'read' }],
});
// key is returned ONCE; show it to the user and discard.
```

## Key format

```text
nk_live_<12-char-prefix>_<32-char-secret>
```

The 12-char prefix is safe to log and display; the 32-char secret is shown only once at creation time. Storage persists the prefix and a SHA-256 hash of the secret — never the secret itself.

## Environments

Keys are issued with either `environment: 'live'` (default) or `environment: 'test'`. The guard rejects requests whose key environment doesn't match the route's requirement with `api_key_environment_mismatch` (HTTP 403):

```typescript
import { RequireEnvironment } from '@nestarc/api-keys';

@Post()
@RequireEnvironment('live')
publish() {
  /* ... */
}
```

Use `test` keys in staging and customer sandbox traffic so a leaked test key can never charge a live account.

## Pepper rotation

Peppers are a server-side secret mixed into the hash. Pepper rotation is different from user API key rotation: it changes the server-side hashing secret for newly issued keys, not the raw key shown to customers. Rotate peppers by adding a new version and pointing `currentPepperVersion` at it. Old keys keep working because each record stores the version it was hashed with:

```typescript
ApiKeysModule.forRoot({
  namespace: 'acme',
  peppers: {
    1: process.env.API_KEY_PEPPER_V1!,
    2: process.env.API_KEY_PEPPER_V2!,
  },
  currentPepperVersion: 2,
  storage: new PrismaApiKeyStorage(prisma),
});
```

The module fails fast at startup if `currentPepperVersion` is missing from `peppers`, so a misconfigured deployment never boots with keys it can't verify.

## User key rotation

Use `rotate()` when a customer needs to replace an API key without downtime:

```typescript
const replacement = await apiKeys.rotate(keyId, {
  gracePeriodMs: 10 * 60 * 1000,
  name: 'Primary replacement',
  createdBy: 'user_123',
});

// replacement.key is returned ONCE; show it to the user and discard.
```

The replacement keeps the old key's tenant, environment, scopes, and expiration unless you override them. The old key is not revoked; it receives `rotatedAt`, `replacedByKeyId`, and an `expiresAt` equal to the grace deadline. If the old key already expires earlier, the earlier expiration wins.

## Revoking and listing keys

```typescript
await apiKeys.revoke(keyId);                                 // soft-delete: sets revokedAt, verification returns api_key_revoked
const active = await apiKeys.list('tenant_123');             // active keys only
const all = await apiKeys.list('tenant_123', { includeRevoked: true });
```

Revoked keys remain in storage so you can audit historical usage. Use revocation, not grace rotation, when a key is known to be compromised.

## Lifecycle events

`onEvent` receives audit-safe lifecycle payloads. Raw keys, hashes, and peppers are never included. `api_key.used` is off by default because it can be high volume.

```typescript
ApiKeysModule.forRoot({
  namespace: 'acme',
  peppers: { 1: process.env.API_KEY_PEPPER! },
  storage: new PrismaApiKeyStorage(prisma),
  ttlPolicy: {
    defaultExpiresInMs: 90 * 24 * 60 * 60 * 1000,
    maxExpiresInMs: 365 * 24 * 60 * 60 * 1000,
    allowNeverExpires: false,
  },
  emitUsageEvents: false,
  onEvent: async (event) => {
    await auditLog.record(event);
  },
  onEventError: (error, event) => {
    logger.warn({ error, eventType: event.type }, 'api key event hook failed');
  },
});
```

For tenancy or RLS integration, pass `contextWriter` and write the verified `ApiKeyContext` into your own request-local context after scope and environment checks pass.

## Errors

Verification and authorization failures throw `ApiKeyError` with a stable `code`:

| Code | HTTP | Meaning |
| --- | --- | --- |
| `api_key_missing` | 401 | No key on the request |
| `api_key_malformed` | 401 | Key doesn't match the expected format |
| `api_key_invalid` | 401 | Key not found or secret mismatch |
| `api_key_revoked` | 401 | Key was revoked |
| `api_key_expired` | 401 | Key is past `expiresAt` |
| `api_key_environment_mismatch` | 403 | Key environment doesn't match route |
| `api_key_scope_insufficient` | 403 | Key is missing a required scope |

Use these codes (not messages) to branch in client code or structured logs.

Rotation precondition failures throw `ApiKeyOperationError` with `api_key_record_not_found` or `api_key_not_rotatable`.

## Logging

Never log raw API keys. The package exports `API_KEY_REDACT_REGEX` so you can redact them before request or error logs are written.

```typescript
import { API_KEY_REDACT_REGEX } from '@nestarc/api-keys';

export function redactApiKeys(value: string): string {
  return value.replace(API_KEY_REDACT_REGEX, '[REDACTED_API_KEY]');
}
```

## Docs

- [`docs/prd.md`](docs/prd.md) Product requirements
- [`docs/spec.md`](docs/spec.md) Technical spec
- [`docs/spec-0.2.md`](docs/spec-0.2.md) v0.2 technical spec
- [`CHANGELOG.md`](CHANGELOG.md) Release history

## Contributing

CI runs `lint`, `test`, and `build` on Node 20 and 22 for every PR. Releases are tag-driven: `npm version <bump> && git push --tags` triggers the workflow in [`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes to npm with provenance. Pre-release versions (anything with a `-` in the version) are published under the `next` dist-tag.

## License

MIT
