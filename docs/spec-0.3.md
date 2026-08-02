# @nestarc/api-keys — v0.3 Technical Spec

This document fixes the public scope for 0.3.0. The release focuses on
request-origin policy, low-cardinality verification metrics, and integration
quality. Existing 0.2 API key lifecycle behavior remains unchanged.

## 1. Selected Scope

### Must-have

1. Per-key IP allowlists supporting exact IPv4/IPv6 addresses and CIDR ranges.
2. A consumer-supplied client IP resolver, with `request.ip` as the HTTP default.
3. A dependency-free verification metric sink with bounded-cardinality payloads.
4. A working benchmark smoke command kept in CI.
5. A documented and tested `@nestarc/rbac` integration contract.

### Should-have

- A small `createTestKey()` helper for consumer integration tests.

### Not in 0.3

- Argon2 hashing. The generated secret already has high entropy, and supporting
  Node 20 would require an additional hashing runtime plus hash-algorithm migration
  metadata.
- A production Redis verification cache. Revocation and rotation need a distributed
  invalidation contract before cached verification can be shipped safely.
- OAuth/OIDC, quotas, billing, management UI, or a usage dashboard.
- Automatic mapping of embedded API key scopes to RBAC permissions. API key scopes
  and RBAC role bindings remain independent authorization layers.

## 2. Compatibility Rules

- All new module and service options are optional.
- Existing records without `allowedIpCidrs` behave as unrestricted records.
- Existing custom storage adapters do not gain new methods.
- SHA-256 plus versioned peppers remains the default and only built-in hasher.
- Lifecycle event payloads remain unchanged.
- Metrics and event sink failures never fail authentication.

## 3. Per-key IP Allowlist

### Public types

```ts
interface ApiKeyRecord {
  allowedIpCidrs?: string[];
}

interface ApiKeyContext {
  allowedIpCidrs?: string[];
}

interface CreateApiKeyInput {
  allowedIpCidrs?: string[];
}

interface RotateApiKeyInput {
  allowedIpCidrs?: string[];
}

type ApiKeyClientIpResolver = (
  request: unknown,
) => string | undefined | Promise<string | undefined>;
```

### Semantics

- Missing or empty `allowedIpCidrs` means unrestricted access.
- Exact addresses are normalized to `/32` for IPv4 and `/128` for IPv6.
- CIDRs are parsed, normalized, and deduplicated before persistence.
- Invalid allowlist entries fail `create()` or `rotate()` before storage mutation.
- Rotation preserves the old key allowlist when the input is omitted.
- Passing `[]` during rotation removes the restriction from the replacement key.
- The old key keeps its own allowlist during the grace period.
- A restricted key fails closed if the request IP is missing or malformed.
- A restricted key used outside its allowlist throws
  `api_key_ip_not_allowed` with HTTP 403.

### Request IP resolution

The default resolver reads `request.ip`. Applications behind proxies are responsible
for configuring their NestJS HTTP adapter's proxy trust correctly. Applications may
provide `clientIpResolver` for custom transports or infrastructure.

The package never reads `X-Forwarded-For` directly.

### Prisma schema

```prisma
allowedIpCidrs String[] @default([])
```

Consumers must add the column through their own migration workflow because this
package ships an example schema rather than migrations.

## 4. Verification Metrics

### Public types

```ts
type ApiKeyVerificationOutcome =
  | 'success'
  | 'malformed'
  | 'invalid'
  | 'revoked'
  | 'expired'
  | 'error';

interface ApiKeyVerificationMetric {
  type: 'api_key.verification';
  outcome: ApiKeyVerificationOutcome;
  durationMs: number;
  environment?: Environment;
}

type ApiKeyMetricSink = (
  metric: ApiKeyVerificationMetric,
) => void | Promise<void>;
```

`ApiKeysModuleOptions` and `ApiKeysServiceDeps` add `onMetric` and
`onMetricError`. Metrics are emitted once for each `verify()` invocation.

### Cardinality and security

- Metrics never contain raw keys, hashes, peppers, prefixes, key IDs, tenant IDs,
  scope strings, IP addresses, or route paths.
- `environment` and `outcome` are the only dimensions provided by the package.
- Lifecycle events remain the integration point for per-key audit data.
- Metric sinks are best-effort and are not awaited by authentication.

## 5. RBAC Integration

`@nestarc/rbac` owns the API key subject adapter. Its
`createApiKeySubjectResolver()` reads `request.apiKeyContext` and then
`request.apiKey`. `ApiKeysGuard` writes the verified context to `request.apiKey`,
so the packages are directly compatible when guards run in this order:

```ts
@UseGuards(ApiKeysGuard, RbacGuard)
@Can('reports.read', { tenant: 'required' })
```

`@RequireScope()` checks permissions embedded in the API key. `@Can()` checks
RBAC bindings for the `api_key` subject. If both are present, both must pass.

## 6. Testing Helper

```ts
interface CreateTestKeyOptions {
  tenantId?: string;
  name?: string;
  environment?: Environment;
  scopes?: Scope[];
  expiresAt?: Date;
  createdBy?: string;
  allowedIpCidrs?: string[];
}

createTestKey(
  service: ApiKeysService,
  options?: CreateTestKeyOptions,
): Promise<CreateApiKeyResult & { context: ApiKeyContext }>;
```

Defaults use tenant `tenant_test`, name `Test API key`, environment `test`, and
scope `test:write`. The helper delegates to public `create()` and `verify()` APIs.

## 7. Acceptance Criteria

- Existing tests continue to pass without changing existing consumer calls.
- Exact IPv4, IPv6, CIDR match/miss, invalid input, missing client IP, and rotation
  preservation/override behavior are covered.
- Verification metrics cover every stable outcome and isolate sync/async sink errors.
- Metric payload tests prove high-cardinality and secret fields are absent.
- The benchmark compiles and its timing-safe check passes.
- CI runs a bounded benchmark smoke command.
- The package tarball contains the new declarations and documentation remains aligned.
