# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased changes are kept under `[Unreleased]`. When cutting a release, rename
that heading to the version and date, then re-add an empty `[Unreleased]` block.

## [Unreleased]

### Added

- Add a reproducible PostgreSQL 14/16 compatibility command that installs exact isolated Prisma
  5.22.0, 6.19.3, and 7.10.0 runtimes, plus an independent packed root consumer proving that the
  in-memory/custom-storage path installs, typechecks, and runs without `@prisma/client`.
- Document the minimum persistent NestJS/Prisma/PostgreSQL evidence policy and keep representative
  legacy/modern diagonals instead of expanding to an unbounded Cartesian matrix.

- Add request-aware `authorizeRequest()` and make `ApiKeysGuard` use it for environment, IP, and
  scope policy. Restricted credentials fail closed when no client IP is available, while the
  existing `verify()` method remains an explicitly credential-only compatibility primitive.
- Separate credential verification from request authorization telemetry. Guard denials no longer
  update `lastUsedAt` or emit `api_key.used`; they emit a low-cardinality
  `api_key.authorization_denied` event and optional `api_key.authorization` metric instead.

### Fixed

- Defensively copy every `Date` entering or leaving `InMemoryApiKeyStorage`, including insert,
  lookup, list, revoke, touch, and rotation boundaries, so caller mutation cannot alter persisted
  lifecycle state. The shared storage contract fixes the same observable semantics across the
  in-memory and Prisma adapters.
- Authenticate a known prefix's secret before revealing revoked or expired lifecycle state;
  wrong secrets now consistently fail with `api_key_invalid` while unknown and known-prefix
  failure paths both perform bounded hash/compare work.
- Bind the raw credential's `live`/`test` segment to the stored key environment after secret
  authentication. Segment-only tampering now fails with `api_key_invalid` and does not attach the
  stored tenant, key ID, or environment to failure telemetry.
- Make `ApiKeyError` a Nest `HttpException` so the default Nest 10/11 HTTP pipeline returns the
  documented 401/403 status and a safe `{ statusCode, code }` response body. The existing
  `instanceof ApiKeyError`, `code`, and `httpStatus` contracts remain supported.
- Make rotation an exactly-once atomic CAS: concurrent attempts for one old key now produce one
  linked replacement while every loser returns the stable `api_key_not_rotatable` operation error.
  `PrismaApiKeyStorage` uses an interactive transaction with a conditional PostgreSQL update.
- Validate expiration dates and all TTL, grace, and debounce durations before storage mutation;
  invalid, non-finite, negative, or overflowing values now fail with the stable
  `api_key_invalid_time` operation code. Corrupt persisted expirations fail closed during
  verification and rotation instead of being treated as indefinitely valid.
- Validate namespaces, runtime environments, and scope resource/level input before generating
  key material or mutating storage. Invalid issue input now fails with the stable
  `api_key_invalid_input` operation code, and the parser enforces base62 prefix/secret syntax so
  every issued key satisfies parse, verify, and logger-redaction round trips.
- Defensively copy verification context, lifecycle event, and metric payloads so synchronous or
  asynchronous observer mutation cannot alter authenticated scopes, operation result dates, stored
  identity data, or failure-reporting payloads. `ApiKeysGuard` now gives `contextWriter` an isolated
  copy and restores the verified `request.apiKey` identity after the writer completes, preventing
  cross-tenant, privileged-scope, and IP-policy replacement from reaching downstream RBAC/RLS code.
- Validate tenant IDs as exact 1–255 character strings without leading or trailing whitespace,
  reject invalid create/list input before storage access, and fail closed instead of trimming or
  coercing non-canonical persisted identities into events or `request.apiKey`.
- Add tenant-bound `revokeForTenant()` and `rotateForTenant()` service methods. The built-in
  adapters bind the expected tenant to the revoke update and atomic rotation CAS; missing and
  cross-tenant IDs share `api_key_record_not_found` and create no replacement credential.
- Isolate the deprecated `onAuthFailed` hook's synchronous throws, rejecting thenables, and async
  rejections so they cannot replace the original authentication error or alter auth-failure event
  and verification metric semantics. Observer error-reporting callbacks are also protected from
  producing unhandled rejections.

### Changed

- Make tagged releases fail unless the tag commit is on canonical `origin/main` and the tag,
  package version, and dated changelog heading agree. The workflow now packs one allowlisted
  tarball, verifies its SHA-256/SRI in downstream consumers, and publishes those exact bytes via
  trusted publishing instead of rebuilding after consumer verification.
- Define `list()` as a backward-compatible non-revoked management-history query: expired and
  rotated records remain in the default result, `includeRevoked: true` adds revoked records, and
  both built-in adapters now order by `createdAt` descending then `id` ascending. Consumers that
  labeled every default result as active must classify the returned lifecycle timestamps instead.
- **Breaking in the planned pre-1.0 `0.4.0` release:** `ApiKeysService.list()` now returns
  serialization-safe `ApiKeySummary[]` values instead of internal `ApiKeyRecord[]` values. Hashes
  and pepper versions remain available to storage adapters for verification and rotation but are
  no longer enumerable or declared on the public management projection. Consumers must stop
  reading verifier material from `list()`; custom `ApiKeyStorage` implementations are unchanged.
- **Breaking in the planned pre-1.0 `0.4.0` release:** support Node.js `^22.13.0 || ^24.0.0` and
  move the source matrix to the exact Node 22.13.0 minimum plus Node 24. Node 20 users must upgrade
  their application runtime before upgrading this package. Unlisted future Node majors, including
  Node 26, remain outside the engine range until they are added to the tested matrix.
- **Breaking in the planned pre-1.0 `0.4.0` release:** custom `ApiKeyStorage.rotate()`
  implementations must atomically return `'rotated'` or `'not_rotatable'`. Legacy `Promise<void>`
  adapters fail fast and must migrate; this change will not be published as a `0.3.x` patch.
- **Breaking in the planned pre-1.0 `0.4.0` release:** namespaces are limited to 1–32 ASCII
  letters or digits. Deployments using punctuation or longer namespaces must reissue credentials
  under an alphanumeric namespace before upgrading; use the prior package version during the
  overlap because the new module and direct service constructor fail fast on the old namespace.
  Namespace values containing `_` already produced credentials that the four-segment parser could
  not consume and must also be replaced. Namespace values are rejected rather than normalized so
  credential identity never changes silently.
- **Breaking in the planned pre-1.0 `0.4.0` release:** newly issued scope resources must follow
  the documented 1–128 character grammar and use the reserved `:` only as the resource/level
  separator. Existing stored keys keep their scope strings, but callers issuing new keys with
  whitespace or other punctuation must migrate those resource names before upgrading.
- **Breaking in the planned pre-1.0 `0.4.0` release:** tenant IDs are opaque exact strings limited
  to 1–255 UTF-16 code units with no leading or trailing whitespace. Existing non-canonical records must
  be migrated with their tenancy/RBAC references or have their credentials reissued; values are
  never normalized at runtime. Custom adapters must implement the optional tenant-bound revoke and
  rotate capabilities before exposing the additive safe management methods.
- `onAuthFailed(prefix, code)` is deprecated in favor of the structured `api_key.auth_failed`
  lifecycle event delivered through `onEvent`; it remains supported for source compatibility.
- Move the default development and modern-consumer baseline to the compatible NestJS 11.2.3
  `common`/`core`/`testing` trio while retaining exact NestJS 10.4.20 legacy-consumer coverage.
- Replace the legacy ESLint configuration with flat config and align ESLint 10.9.1 with
  typescript-eslint 8.68.0. ESLint's locked engine floor is recorded as input to the separate
  Node support-policy decision; this change does not alter the package's public Node range.

## [0.3.2] - 2026-08-30

### Added

- PostgreSQL-backed `PrismaApiKeyStorage` contract coverage with Prisma 7.10.0 and its matching
  `@prisma/adapter-pg` driver adapter.
- Tarball-based strict consumer coverage for exact NestJS 11.2.1 and Prisma 7.10.0, including
  package metadata assertions, `skipLibCheck: false` public declaration compilation, npm bypass
  configuration rejection, and a Nest application-context runtime smoke test.
- Packaged Prisma 7 schema and Prisma Config examples alongside the Prisma 5/6 schema example.

### Changed

- Expanded NestJS peers to `^10.0.0 || ^11.0.0` and the optional `@prisma/client` peer to
  `^5.0.0 || ^6.0.0 || ^7.0.0`, backed by strict consumer and real PostgreSQL evidence.
- Extended CI and release verification to retain the Prisma 5/6 lanes while adding Prisma 7.

## [0.3.1] - 2026-08-23

### Added

- PostgreSQL-backed `PrismaApiKeyStorage` contract coverage for CRUD, tenant isolation,
  field mapping, rotation, and transaction rollback.
- Prisma 5.22.0/6.19.3 CI and pre-release verification with matching CLI/client versions.
- A tarball-based strict consumer install test using Prisma 6.19.3 without peer-dependency
  bypass flags.

### Changed

- Expanded the optional `@prisma/client` peer range from Prisma 5 to
  `^5.0.0 || ^6.0.0` based on the real-client PostgreSQL matrix.

## [0.3.0] - 2026-08-02

### Added

- Per-key IPv4, IPv6, and CIDR allowlists through `allowedIpCidrs`.
- Injectable `clientIpResolver` with a safe `request.ip` default.
- Low-cardinality `api_key.verification` metrics through `onMetric` and
  isolated failure reporting through `onMetricError`.
- `createTestKey()` for consumer integration tests.
- `@nestarc/rbac` compatibility coverage and a v0.3 technical specification.

### Changed

- The Prisma example schema now includes `allowedIpCidrs String[] @default([])`.
- CI now runs a bounded benchmark smoke check.

### Fixed

- Updated the benchmark storage adapter for the v0.2 `findById()` and `rotate()`
  contract so the benchmark compiles and runs again.

### Security

- IP restrictions fail closed when a restricted key has no valid resolved client IP.
- Verification metrics exclude raw keys, hashes, peppers, prefixes, key IDs, tenant IDs,
  scopes, client IPs, and route paths.

## [0.2.0] - 2026-06-18

### Added

- `ApiKeysService.rotate()` for zero-downtime API key replacement with configurable grace periods.
- Rotation metadata on records: `rotatedAt` and `replacedByKeyId`.
- Lifecycle event hook API via `onEvent`, with `api_key.created`, `api_key.revoked`,
  `api_key.rotated`, `api_key.auth_failed`, and opt-in `api_key.used` events.
- TTL policy options: `defaultExpiresInMs`, `maxExpiresInMs`, and `allowNeverExpires`.
- Stable request context helpers: `@CurrentApiKey()`, `getApiKeyContext()`,
  `API_KEY_CONTEXT_PROPERTY`, and `contextWriter`.
- `prefix` on `ApiKeyContext` for safe structured logging and tenancy/audit bridges.
- Storage contract methods for rotation-capable adapters: `findById()` and `rotate()`.

### Changed

- Prisma schema example now includes rotation metadata and a `replacedByKeyId` index.
- Documentation now separates pepper rotation from user API key rotation and aligns v0.1
  claims with shipped behavior.

### Security

- Lifecycle event payloads intentionally exclude raw API keys, hashes, and pepper values.
- User key rotation preserves the "raw key returned once" invariant for replacement keys.

## [0.1.0] - 2026-04-15

Initial public release. Supersedes the deprecated `0.1.0-alpha.0` prerelease,
which was published from an out-of-date `package.json` version field; no code
or behavior differences exist between the two.

## [0.1.0-alpha.0] - 2026-04-15

### Added

- Initial `ApiKeysModule.forRoot()` for NestJS with tenant-scoped API keys.
- `ApiKeysService` with `create`, `verify`, `list`, and `revoke` operations.
- Stripe-style key format: `<namespace>_<environment>_<12-char-prefix>_<32-char-secret>`.
- SHA-256 hashing with versioned peppers and timing-safe verification.
- Pluggable storage: `InMemoryApiKeyStorage` (tests) and `PrismaApiKeyStorage` (production).
- Reusable storage contract suite for implementors of `ApiKeyStorage`.
- Scope system with `write`-implies-`read` semantics and exact-match checks.
- `ApiKeysGuard` plus `@RequireScope` and `@RequireEnvironment` decorators.
- Typed error codes (`ApiKeyErrorCode`) with HTTP status mapping via `ApiKeyError`.
- `API_KEY_REDACT_REGEX` export for safe logging.
- Prisma schema example at `prisma/schema.example.prisma`.
- Retry on duplicate prefix collisions during `create` (up to 3 attempts).
- Module-init validation: fails fast when `currentPepperVersion` is missing from `peppers`.
- Best-effort `lastUsedAt` tracking with configurable debounce, isolated from auth success.
- GitHub Actions CI across Node 20 and 22, release workflow publishing with npm provenance,
  and Dependabot for Actions and dev dependencies.

### Security

- Verification failures emit a single `api_key_invalid` error regardless of root cause
  (unknown pepper version, hash mismatch) to avoid leaking internal state.
- Scopes are deduplicated before persistence to keep stored records minimal and consistent.
