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

`@prisma/client` is an optional peer dependency. The Prisma storage adapter is verified with
Prisma 5.22.0 and 6.19.3 and declares support for `^5.0.0 || ^6.0.0`. Prisma 7 is not yet in
the supported range. Consumers that use the in-memory adapter or a custom storage adapter do
not need to install Prisma.

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

Rotation precondition failures throw `ApiKeyOperationError` with `api_key_record_not_found` or `api_key_not_rotatable`.

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
5.22.0 and 6.19.3. Run that contract locally with `npm run test:e2e:prisma`; the runner uses
`PRISMA_E2E_DATABASE_URL` when supplied, otherwise it starts a disposable PostgreSQL 16 Docker
container. `npm run test:consumer:strict` packs the library and verifies an independent Prisma
6.19.3 consumer installation without `--legacy-peer-deps` or `--force`.

Releases are tag-driven: `npm version <bump> && git push --tags` triggers the workflow in
[`.github/workflows/release.yml`](.github/workflows/release.yml), which repeats the Prisma matrix
before publishing to npm with provenance. Pre-release versions (anything with a `-` in the
version) are published under the `next` dist-tag.

## License

MIT
