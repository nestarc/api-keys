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
- **Lifecycle hooks** — creation, revocation, rotation, auth-failure, authorization-denial, and opt-in usage events.
- **Stable request context** — `@CurrentApiKey()`, `getApiKeyContext()`, and an optional `contextWriter` bridge.
- **TTL policy** — optional default expiration, maximum expiration, and no-never-expires enforcement.
- **Per-key IP allowlists** — exact IPv4/IPv6 addresses and CIDR ranges with fail-closed enforcement.
- **Verification and authorization metrics** — separate low-cardinality credential and request-policy measurements.
- **Pluggable storage** — ships with Prisma and in-memory adapters plus a reusable contract suite.
- **NestJS-native** — `ApiKeysModule.forRoot`, `ApiKeysGuard`, `@RequireScope`, `@RequireEnvironment`.
- **Typed errors** — `ApiKeyError` with stable `code` values mapped to HTTP statuses.

## Install

```bash
npm install @nestarc/api-keys
```

Node.js 22.13.0 or newer within the Node 22 line, or Node 24, is required. Node 22.13.0 is the
tested minimum and Node 24 is the current source and release runtime. Node 20 is not supported
starting with the planned `0.4.0` release; upgrade the application runtime before upgrading this
package. Newer unlisted Node majors are not supported until they are added to the tested matrix.

NestJS 10 and 11 are supported. `@prisma/client` is an optional peer dependency: the Prisma
storage adapter is verified with Prisma 5.22.0, 6.19.3, and 7.10.0 against PostgreSQL and
declares support for `^5.0.0 || ^6.0.0 || ^7.0.0`. Consumers that use the in-memory adapter or
a custom storage adapter do not need to install Prisma. Prisma 7 consumers must also satisfy
Prisma's Node.js requirement and configure the driver adapter for their database.

| Supported boundary | Persistent evidence |
| --- | --- |
| NestJS 10 | Exact 10.4.20 packed strict install/typecheck/runtime and default HTTP Guard pipeline |
| NestJS 11 | Full source suite plus exact 11.2.3 packed strict and HTTP consumers |
| Prisma 5/6/7 | Exact 5.22.0, 6.19.3, and 7.10.0 generated-client storage contracts on PostgreSQL 16 |
| PostgreSQL 14+ | Prisma 5.22.0 storage contract on PostgreSQL 14; all Prisma majors on PostgreSQL 16 |
| Prisma omitted | Independent NestJS 11.2.3 packed root consumer with no Prisma install or lock entry |

The project tests integration boundaries rather than every NestJS/Prisma/PostgreSQL Cartesian
combination. The legacy NestJS 10 + Prisma 6 and modern NestJS 11 + Prisma 7 packed lanes are the
representative diagonals; Prisma storage is independently tested against a real database. See the
[compatibility evidence policy](docs/2026-08-30-compatibility-evidence-policy.md) for lane ownership,
off-diagonal criteria, and the exact reproducible commands.

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

Use a product-specific `namespace` such as `acme` or `billing` instead of relying on the default
`nk`. A namespace must contain 1–32 ASCII letters or digits. That keeps keys distinct if multiple
packages or services generate API keys in the same ecosystem while ensuring every issued key can
be parsed and redacted by the package.

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

### Tenant identity

`tenantId` is an opaque exact string owned by the application. API Keys accepts 1–255 JavaScript
UTF-16 code units, rejects empty values and leading/trailing whitespace, and never trims, coerces,
case-folds, or Unicode-normalizes the value. Internal whitespace and non-ASCII values are
preserved. Use the same exact identifier in tenancy and RBAC; apply a narrower UUID or slug
validator in your application before calling this package if your system requires one.

Invalid runtime input fails with `ApiKeyOperationError` code `api_key_invalid_input` before key
generation or storage access. A custom storage adapter that returns a non-canonical tenant is not
silently repaired: verification and management reads fail closed. See the
[tenant identity ADR](https://github.com/nestarc/api-keys/blob/main/docs/2026-08-30-tenant-identity-contract-adr.md) for existing-data migration
and cross-package ownership.

## Key format

```text
nk_live_<12-char-prefix>_<32-char-secret>
```

The namespace contains 1–32 ASCII letters or digits. The prefix is exactly 12 base62 characters
and is safe to log and display; the secret is exactly 32 base62 characters and is shown only once
at creation time. `parseKey()` rejects any other namespace, environment, prefix, secret, or segment
shape as `api_key_malformed`. Storage persists the prefix and a SHA-256 hash of the secret — never
the secret itself.

`ApiKeysModule.forRoot()`, direct `ApiKeysService` construction, and `generateKey()` reject an
invalid namespace with `ApiKeyOperationError` code `api_key_invalid_input`. Validation happens
before random key material is generated.

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

Runtime callers, including untyped JavaScript callers, must pass exactly `live` or `test`; other
values fail with `api_key_invalid_input` before key generation or storage mutation.

## Scope input

At least one scope is required. A scope resource is 1–128 ASCII characters, starts with a letter
or digit, and may then contain letters, digits, `.`, `_`, `/`, or `-`. The `:` delimiter is reserved
for the stored `resource:level` representation and cannot appear in a resource. The level must be
exactly `read` or `write`.

These rules are enforced at runtime before key generation or storage mutation. Invalid scope
input throws `ApiKeyOperationError` with `api_key_invalid_input`; duplicate valid scopes are still
deduplicated before persistence.

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
Missing or empty allowlists are unrestricted. A restricted key used through `ApiKeysGuard` or
`authorizeRequest()` from another address, or without a resolvable client IP, fails with
`api_key_ip_not_allowed`.

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

`verify(rawKey)` is intentionally credential-only for backward compatibility. It authenticates
format, secret, tenant identity, lifecycle, and expiry, then returns the stored environment,
scopes, and IP policy without enforcing those request policies. Use the request-aware primitive
for a custom transport:

```typescript
const apiKey = await apiKeys.authorizeRequest({
  rawKey: message.apiKey,
  clientIp: connection.verifiedRemoteAddress,
  requiredEnvironment: 'live',
  requiredScope: { resource: 'reports', level: 'read' },
});
```

`ApiKeysGuard` uses the same primitive. A custom transport may also pass its request and a
`clientIpResolver`; the resolver is called only for a restricted key. Never derive a trusted
client IP from forwarded headers without configuring the surrounding proxy boundary.

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

For a tenant-scoped management endpoint, bind the expected caller tenant in the same atomic
storage mutation:

```typescript
const replacement = await apiKeys.rotateForTenant(callerTenantId, keyId, {
  gracePeriodMs: 10 * 60 * 1000,
});

await apiKeys.revokeForTenant(callerTenantId, anotherKeyId);
```

A missing ID and a tenant mismatch both fail with `api_key_record_not_found`. The ID-only
`rotate()` and `revoke()` methods remain available for trusted system-wide administration; they
do not authorize tenant-scoped callers.

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

Tenant-bound management uses the optional `revokeForTenant()` and `rotateForTenant()` storage
capabilities. Built-in adapters include `expectedTenantId` in the revoke update or rotation CAS.
A custom adapter that does not implement the matching capability fails fast when the additive
service method is called; the service never falls back to a separate tenant check followed by an
ID-only mutation.

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
await apiKeys.revokeForTenant(callerTenantId, keyId); // tenant-bound management path
const current = await apiKeys.list('tenant_123'); // non-revoked keys
const history = await apiKeys.list('tenant_123', { includeRevoked: true });
```

`list()` returns `ApiKeySummary[]`, a serialization-safe management projection. It contains key
metadata such as the ID, name, prefix, scopes, lifecycle timestamps, and creator, but never the
stored hash, pepper version, or raw secret. The internal `ApiKeyRecord` storage contract still
contains verifier material so verification and rotation continue to work; do not return
`storage.listByTenant()` directly from a controller.

Listing is a management-history API, not an authentication predicate. Lifecycle fields have these
meanings at the time you inspect them:

| State              | Lifecycle fields                                                               | Verifiable at that time | Included by default              |
| ------------------ | ------------------------------------------------------------------------------ | ----------------------- | -------------------------------- |
| Active             | `revokedAt` and `rotatedAt` are `null`; `expiresAt` is `null` or in the future | Yes                     | Yes                              |
| Rotated with grace | `rotatedAt` and `replacedByKeyId` are set; `expiresAt` is in the future        | Yes, until `expiresAt`  | Yes                              |
| Expired            | `revokedAt` is `null`; `expiresAt` is at or before the current time            | No                      | Yes                              |
| Revoked            | `revokedAt` is set, regardless of expiry or rotation fields                    | No                      | No; opt in with `includeRevoked` |

Both built-in adapters return records in deterministic `createdAt` descending, then `id` ascending
order. The default deliberately preserves the existing non-revoked contract: expired records and
old rotation records remain available for management history, including after a grace period ends.
`includeRevoked: true` adds revoked history; there is no separate `includeExpired` option. Revoked
keys remain in storage so you can audit historical usage. Use revocation, not grace rotation, when
a key is known to be compromised.

Existing consumers do not need to migrate their default query. Applications that labeled every
default result as "active" must instead classify the lifecycle timestamps using their request time,
or filter expired and rotated records in their management layer. Do not infer authentication state
from list membership; call the verification API for credentials presented by a client.

A tenant-bound management controller can safely return the service projection directly:

```typescript
@Controller('api-keys')
export class ApiKeyManagementController {
  constructor(private readonly apiKeys: ApiKeysService) {}

  @Get()
  list(@CurrentApiKey() caller: ApiKeyContext): Promise<ApiKeySummary[]> {
    return this.apiKeys.list(caller.tenantId);
  }
}
```

The `ApiKeyRecord[]` to `ApiKeySummary[]` return-type narrowing is planned for the pre-1.0 `0.4.0`
release. Consumers that read verifier fields from `list()` must remove that usage; custom storage
implementations continue to use `ApiKeyRecord` internally.

## Lifecycle events

`onEvent` receives lifecycle payloads. Raw keys, hashes, and peppers are never included.
`api_key.authorization_denied` contains only the stable error code and timestamp; it excludes
the raw credential, client IP, prefix, key ID, tenant ID, scopes, and route. `api_key.used` is off
by default because it can be high volume.

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

Observer payloads are defensive copies. Their nested scope arrays and `Date` values do not share
mutable references with stored records, operation results, verification context, or error-reporting
callbacks. The public event and metric interfaces remain mutable for source compatibility, so sinks
may annotate their local payload, but object identity is not a supported contract.

The legacy `onAuthFailed(prefix, code)` hook remains source-compatible but is deprecated; use
`onEvent` and select `api_key.auth_failed` instead. A synchronous throw, rejecting thenable, or
async rejection from the legacy hook is isolated: it cannot replace the original `ApiKeyError`,
suppress the structured auth-failure event, or change the verification metric outcome. Event and
metric failure-reporting callbacks are isolated as well, including asynchronous rejection, so an
observer failure cannot create an unhandled rejection through the service.

For tenancy or RLS integration, pass `contextWriter` and write the verified `ApiKeyContext` into
your own request-local context after scope, environment, and IP checks pass. The writer receives an
isolated context copy. After it completes, the Guard restores `request.apiKey` from the verified
identity, so writer mutation or replacement cannot change the tenant, key ID, environment, scopes,
prefix, or IP policy observed by downstream RBAC/RLS code. `ApiKeyContext` stays mutable at the type
level for source compatibility; this guarantee is runtime boundary isolation, not a deep-freeze API.

## Verification and authorization metrics

`onMetric` emits one bounded-cardinality measurement for each credential-verification attempt,
whether it comes from `verify()` or `authorizeRequest()`. Payloads contain only `outcome`,
`durationMs`, and an optional `environment`; key IDs, tenant IDs, prefixes, scopes, client IPs,
and raw key material are excluded.

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

`authorizeRequest()` and `ApiKeysGuard` emit a separate request-policy metric through
`onAuthorizationMetric`. Missing credentials do not create a verification metric or
`api_key.auth_failed`; they create authorization outcome `missing`. A supplied credential failure
keeps its verification outcome and is collapsed to authorization outcome `credential_rejected`.
Environment, IP, and scope denials use `environment_denied`, `ip_denied`, and `scope_denied`.

```typescript
ApiKeysModule.forRoot({
  namespace: 'acme',
  peppers: { 1: process.env.API_KEY_PEPPER! },
  storage,
  onAuthorizationMetric: (metric) => {
    apiKeyAuthorizationCounter.add(1, {
      outcome: metric.outcome,
      environment: metric.environment ?? 'unknown',
    });
  },
});
```

For direct `verify()` calls, successful credential verification remains an accepted use and
updates `lastUsedAt` plus optional `api_key.used`. In the request-aware path, those usage signals
are deferred until environment, IP, and scope checks all pass. A 403 denial therefore records a
successful credential-verification metric plus an authorization denial, but not accepted usage.

Metric sink failures are isolated from authentication and authorization. Use lifecycle events
rather than metric labels when you need per-key audit details.

See the [request authorization telemetry ADR](https://github.com/nestarc/api-keys/blob/main/docs/2026-08-30-request-authorization-telemetry-adr.md)
for the full missing/credential/denial matrix and compatibility decision.

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
`api_key_not_rotatable`, `api_key_invalid_time`, or `api_key_invalid_input`.

## Logging

Never log raw API keys. The package exports `API_KEY_REDACT_REGEX` so every key producible under
the namespace and base62 format contract can be redacted before request or error logs are written.

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
- [Tenant identity and management boundary ADR](https://github.com/nestarc/api-keys/blob/main/docs/2026-08-30-tenant-identity-contract-adr.md)
- [Request authorization telemetry ADR](https://github.com/nestarc/api-keys/blob/main/docs/2026-08-30-request-authorization-telemetry-adr.md)
- [Node.js support policy ADR](https://github.com/nestarc/api-keys/blob/main/docs/2026-08-30-node-support-policy-adr.md)
- [Compatibility evidence policy](docs/2026-08-30-compatibility-evidence-policy.md)
- [`CHANGELOG.md`](CHANGELOG.md) Release history

## Contributing

CI runs `lint`, `test`, `build`, and a bounded benchmark smoke check on the exact Node 22.13.0
minimum and Node 24 for every PR. The DB and packed-consumer jobs run on the minimum so support
cannot drift below the public `engines.node` contract. CI also runs the PostgreSQL storage contract
against exact matching Prisma CLI/client versions 5.22.0, 6.19.3, and 7.10.0; the Prisma 7 lane
uses matching `@prisma/adapter-pg`. Run the full support matrix with
`npm run test:e2e:postgres-matrix`. It verifies Prisma 5 against PostgreSQL 14 and all three Prisma
versions against PostgreSQL 16 in disposable Docker containers. For one exact runtime/database
combination, `npm run test:e2e:prisma` still accepts `PRISMA_E2E_RUNTIME_ROOT` and
`PRISMA_E2E_DATABASE_URL`, but that single command is not complete support-matrix evidence.

`npm run test:consumer:strict:legacy` packs the library and verifies exact Nest 10.4.20 with
Prisma 6.19.3. `npm run test:consumer:strict:modern` verifies exact Nest 11.2.3 with Prisma
7.10.0. Both use an independent strict install, assert installed versions and packed peer
metadata, compile the packed public declarations with `skipLibCheck: false`, and boot a Nest
application context. They reject inherited npm bypass settings and explicitly keep
`--legacy-peer-deps` and `--force` disabled.
`npm run test:consumer:strict` defaults to the modern lane.

`npm run test:consumer:no-prisma` uses another independent packed root consumer. It does not list
or install `@prisma/client`, rejects any Prisma client entry in the consumer lock, compiles the
public declarations with `skipLibCheck: false`, imports the package root, and boots the in-memory
adapter path. This is the persistent evidence for the optional Prisma peer; the legacy and modern
strict consumers both install Prisma and do not count for that claim.

`npm run test:consumer:http:nest10` and `npm run test:consumer:http:nest11` pack the library and
exercise the default Nest HTTP exception pipeline with the exact supported Nest versions. They
verify the 401/403 status matrix and the safe public error body without installing a custom filter.
Consumer commands pack a local candidate by default. The release workflow instead sets
`API_KEYS_PACKAGE_CANDIDATE_DIR`, causing every packed and HTTP consumer to verify and install the
single candidate artifact prepared for that workflow run.

After an RBAC version containing both `RBAC-M01` and `RBAC-M02` is published, run
`npm run test:consumer:rbac -- --rbac <exact-version>`. The consumer installs only the packed API
Keys candidate and the exact registry RBAC artifact, verifies both integrity records, and exercises
canonical/legacy API-key conflicts plus trusted tenant reconciliation. Published RBAC 0.2.1 is a
known RED prerequisite result and must not be used as passing evidence for this gate.

Releases are tag-driven: `npm version <bump> && git push --tags` triggers the workflow in
[`.github/workflows/release.yml`](.github/workflows/release.yml). Before packaging, the workflow
requires the tag commit to be on canonical `origin/main` and requires the tag, `package.json`, and
dated `CHANGELOG.md` release heading to agree. It builds and packs once, records the tarball's
SHA-256, SRI, and content allowlist, sends those exact bytes through the packed-consumer and Nest
HTTP gates, and publishes that verified tarball through npm trusted publishing with provenance.
Pre-release versions (anything with a `-` in the version) are published under the `next` dist-tag.

## License

MIT
