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
- **Per-key IP allowlists** — exact IPv4/IPv6 addresses and CIDR ranges with fail-closed enforcement.
- **Verification metrics** — low-cardinality success/failure and latency measurements through a pluggable sink.
- **Pluggable storage** — ships with Prisma and in-memory adapters plus a reusable contract suite.
- **NestJS-native** — `ApiKeysModule.forRoot`, `ApiKeysGuard`, `@RequireScope`, `@RequireEnvironment`.
- **Typed errors** — `ApiKeyError` with stable `code` values mapped to HTTP statuses.

## Install

```bash
npm install @nestarc/api-keys
```

NestJS 10 and 11 are supported. `@prisma/client` is an optional peer dependency: the Prisma
storage adapter is verified with Prisma 5.22.0, 6.19.3, and 7.10.0 against PostgreSQL and
declares support for `^5.0.0 || ^6.0.0 || ^7.0.0`. Consumers that use the in-memory adapter or
a custom storage adapter do not need to install Prisma. Prisma 7 consumers must also satisfy
Prisma's Node.js requirement and configure the driver adapter for their database.

## Quickstart

```typescript
import { Module } from '@nestjs/common';
import { ApiKeysModule, PrismaApiKeyStorage } from '@nestarc/api-keys';
import { PrismaClient } from '@prisma/client';

// Prisma 5/6 initialization
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

With Prisma 7, initialize the generated client with its required driver adapter instead:

```typescript
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/prisma/client';

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL! }),
});
```

For Prisma 5/6, add the model from [`prisma/schema.example.prisma`](prisma/schema.example.prisma)
to your schema. For Prisma 7, use
[`prisma/schema.example.v7.prisma`](prisma/schema.example.v7.prisma) with a project-root
`prisma.config.ts` based on
[`prisma/prisma.config.example.ts`](prisma/prisma.config.example.ts), then run a migration.

Use a product-specific `namespace` such as `acme` or `billing` instead of relying on the default `nk`. That keeps your keys distinct if multiple packages or services generate API keys in the same ecosystem.

### Protect a route

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiKeyContext, ApiKeysGuard, CurrentApiKey, RequireScope } from '@nestarc/api-keys';

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
  allowedIpCidrs: ['203.0.113.0/24'], // optional
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

## IP allowlists

Restrict a key to exact IPv4/IPv6 addresses or CIDR ranges with `allowedIpCidrs`:

```typescript
const { key } = await apiKeys.create({
  tenantId: 'tenant_123',
  name: 'Office integration',
  scopes: [{ resource: 'reports', level: 'read' }],
  allowedIpCidrs: ['203.0.113.42', '10.20.0.0/16', '2001:db8::/48'],
});
```

Exact addresses are stored as `/32` or `/128`; CIDRs are normalized and deduplicated.
Missing or empty allowlists are unrestricted. A restricted key used from another address,
or without a resolvable client IP, fails with `api_key_ip_not_allowed`.

The default resolver reads `request.ip` and never trusts `X-Forwarded-For` directly. Configure
your NestJS HTTP adapter's proxy trust correctly, or provide a resolver for your infrastructure:

```typescript
ApiKeysModule.forRoot({
  namespace: 'acme',
  peppers: { 1: process.env.API_KEY_PEPPER! },
  storage,
  clientIpResolver: (request) => {
    const req = request as { verifiedClientIp?: string };
    return req.verifiedClientIp;
  },
});
```

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

The replacement also preserves `allowedIpCidrs` by default. Pass a new array to replace the
allowlist or `allowedIpCidrs: []` to make the replacement unrestricted.

Concurrent calls for the same old key are exactly-once: one call returns a replacement and every
loser throws `ApiKeyOperationError` with `api_key_not_rotatable`. The Prisma adapter enforces this
with a PostgreSQL transaction and conditional update, so an unlinked replacement is never stored.

### Custom storage rotation contract

Starting with the next pre-1.0 minor release (`0.4.0`), custom `ApiKeyStorage` adapters must make
the old-key claim and replacement insert one atomic operation. `rotate()` must check that the old
record is unrevoked, unrotated, unreplaced, and unexpired as of `input.rotatedAt`, then return
`'rotated'` or `'not_rotatable'`:

```typescript
type RotateApiKeyStorageResult = 'rotated' | 'not_rotatable';

rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult>;
```

Do not implement this as `findById()` followed by separate update and insert calls. SQL adapters
should use a transaction plus a conditional update/CAS and roll the claim back if insertion fails.
Legacy adapters returning `Promise<void>` now fail fast instead of being treated as a successful
rotation. This public interface change is intentionally shipped as pre-1.0 minor `0.4.0`, not a
`0.3.x` patch; custom adapter authors must update before upgrading.

## Expiration and time values

`expiresAt` must be a valid JavaScript `Date`. A past value is accepted and creates a key that is
immediately expired. A stored `null` means the key does not expire; `rotate({ expiresAt: null })`
also explicitly makes the replacement non-expiring unless `allowNeverExpires: false` rejects it.

`gracePeriodMs`, `debounceMs`, `defaultExpiresInMs`, and `maxExpiresInMs` must be finite,
non-negative millisecond durations. A zero grace period is valid and expires the old key at the
rotation timestamp, while still issuing the replacement. Date arithmetic that exceeds
JavaScript's supported `Date` range is rejected before storage mutation.

Invalid time input and TTL-policy violations throw `ApiKeyOperationError` with the stable
`api_key_invalid_time` code. If a custom storage adapter returns a corrupt non-null `expiresAt`,
verification fails as `api_key_invalid` and rotation fails as `api_key_not_rotatable`; the record
is never treated as indefinitely valid. Custom adapters should still persist only valid `Date`
values or `null`.

## Revoking and listing keys

```typescript
await apiKeys.revoke(keyId); // soft-delete: sets revokedAt, verification returns api_key_revoked
const active = await apiKeys.list('tenant_123'); // active keys only
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

## Verification metrics

`onMetric` emits one bounded-cardinality measurement for each `verify()` call. Payloads contain
only `outcome`, `durationMs`, and an optional `environment`; key IDs, tenant IDs, prefixes,
scopes, client IPs, and raw key material are excluded.

```typescript
ApiKeysModule.forRoot({
  namespace: 'acme',
  peppers: { 1: process.env.API_KEY_PEPPER! },
  storage,
  onMetric: (metric) => {
    apiKeyVerificationCounter.add(1, {
      outcome: metric.outcome,
      environment: metric.environment ?? 'unknown',
    });
    apiKeyVerificationDuration.record(metric.durationMs, {
      outcome: metric.outcome,
    });
  },
  onMetricError: (error, metric) => {
    logger.warn({ error, outcome: metric.outcome }, 'API key metric sink failed');
  },
});
```

Metric sink failures are isolated from authentication. Use lifecycle events rather than metric
labels when you need per-key audit details.

## RBAC integration

`@nestarc/rbac` maps the context written by `ApiKeysGuard` to an `api_key` subject:

```typescript
import { RbacModule } from '@nestarc/rbac';
import { createApiKeySubjectResolver } from '@nestarc/rbac/integrations/api-keys';

RbacModule.forRoot({
  storage: rbacStorage,
  subjectResolver: createApiKeySubjectResolver(),
  tenant: { requiredByDefault: true },
});
```

Run the authentication guard before RBAC:

```typescript
@UseGuards(ApiKeysGuard, RbacGuard)
@RequireScope('reports', 'read')
@Can('reports.read', { tenant: 'required' })
@Get()
listReports() {}
```

`@RequireScope()` checks capabilities embedded in the key. RBAC `@Can()` checks role bindings
for that API key ID. When both decorators are present, both checks must pass.

## Errors

Verification and authorization failures throw `ApiKeyError` with a stable `code`:

| Code                           | HTTP | Meaning                                         |
| ------------------------------ | ---- | ----------------------------------------------- |
| `api_key_missing`              | 401  | No key on the request                           |
| `api_key_malformed`            | 401  | Key doesn't match the expected format           |
| `api_key_invalid`              | 401  | Key not found or secret mismatch                |
| `api_key_revoked`              | 401  | Key was revoked                                 |
| `api_key_expired`              | 401  | Key is past `expiresAt`                         |
| `api_key_environment_mismatch` | 403  | Key environment doesn't match route             |
| `api_key_scope_insufficient`   | 403  | Key is missing a required scope                 |
| `api_key_ip_not_allowed`       | 403  | Resolved client IP is outside the key allowlist |

Use these codes (not messages) to branch in client code or structured logs.

`ApiKeyError` extends Nest's `HttpException`, so the default Nest HTTP pipeline returns the
table's 401/403 status without a custom exception filter. Its public response body is limited to
`statusCode` and `code`; parser details, raw credentials, hashes, peppers, and stacks are not
included. Direct service consumers can continue to use `error instanceof ApiKeyError`,
`error.code`, and the backward-compatible `error.httpStatus` property. New Nest integrations may
prefer `error.getStatus()`; `httpStatus` is retained and is not deprecated in this release.

Lifecycle details are secret-first: a wrong secret always returns `api_key_invalid`, even when its
prefix belongs to a revoked or expired record. Only a caller presenting the valid secret can
receive `api_key_revoked` or `api_key_expired`.

Operation failures throw `ApiKeyOperationError` with `api_key_record_not_found`,
`api_key_not_rotatable`, or `api_key_invalid_time`.

## Logging

Never log raw API keys. The package exports `API_KEY_REDACT_REGEX` so you can redact them before request or error logs are written.

```typescript
import { API_KEY_REDACT_REGEX } from '@nestarc/api-keys';

export function redactApiKeys(value: string): string {
  return value.replace(API_KEY_REDACT_REGEX, '[REDACTED_API_KEY]');
}
```

## Testing

`createTestKey()` issues and verifies a key through the public service API. Defaults use a test
environment, `tenant_test`, and `test:write` scope:

```typescript
import { createTestKey } from '@nestarc/api-keys';

const fixture = await createTestKey(apiKeys, {
  tenantId: 'tenant_fixture',
  scopes: [{ resource: 'reports', level: 'read' }],
});

expect(fixture.context.tenantId).toBe('tenant_fixture');
request(app).get('/reports').set('Authorization', `Bearer ${fixture.key}`);
```

## Docs

- [`docs/prd.md`](docs/prd.md) Product requirements
- [`docs/spec.md`](docs/spec.md) Technical spec
- [`docs/spec-0.2.md`](docs/spec-0.2.md) v0.2 technical spec
- [`docs/spec-0.3.md`](docs/spec-0.3.md) v0.3 technical spec
- [`CHANGELOG.md`](CHANGELOG.md) Release history

## Contributing

CI runs `lint`, `test`, `build`, and a bounded benchmark smoke check on Node 20 and 22 for every
PR. It also runs the PostgreSQL storage contract against matching Prisma CLI/client versions
5.22.0, 6.19.3, and 7.10.0; the Prisma 7 lane uses matching `@prisma/adapter-pg`. Run that
contract locally with `npm run test:e2e:prisma`; the runner uses `PRISMA_E2E_DATABASE_URL` when
supplied, otherwise it starts a disposable PostgreSQL 16 Docker container.

`npm run test:consumer:strict:legacy` packs the library and verifies exact Nest 10.4.20 with
Prisma 6.19.3. `npm run test:consumer:strict:modern` verifies exact Nest 11.2.1 with Prisma
7.10.0. Both use an independent strict install, assert installed versions and packed peer
metadata, compile the packed public declarations with `skipLibCheck: false`, and boot a Nest
application context. They reject inherited npm bypass settings and explicitly keep
`--legacy-peer-deps` and `--force` disabled.
`npm run test:consumer:strict` defaults to the modern lane.

`npm run test:consumer:http:nest10` and `npm run test:consumer:http:nest11` pack the library and
exercise the default Nest HTTP exception pipeline with the exact supported Nest versions. They
verify the 401/403 status matrix and the safe public error body without installing a custom filter.

Releases are tag-driven: `npm version <bump> && git push --tags` triggers the workflow in
[`.github/workflows/release.yml`](.github/workflows/release.yml), which repeats the Prisma matrix
before publishing to npm with provenance. Pre-release versions (anything with a `-` in the
version) are published under the `next` dist-tag.

## License

MIT
