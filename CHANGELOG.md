# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased changes are kept under `[Unreleased]`. When cutting a release, rename
that heading to the version and date, then re-add an empty `[Unreleased]` block.

## [Unreleased]

### Fixed

- Authenticate a known prefix's secret before revealing revoked or expired lifecycle state;
  wrong secrets now consistently fail with `api_key_invalid` while unknown and known-prefix
  failure paths both perform bounded hash/compare work.
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

### Changed

- **Breaking in the planned pre-1.0 `0.4.0` release:** custom `ApiKeyStorage.rotate()`
  implementations must atomically return `'rotated'` or `'not_rotatable'`. Legacy `Promise<void>`
  adapters fail fast and must migrate; this change will not be published as a `0.3.x` patch.

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
