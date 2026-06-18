# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased changes are kept under `[Unreleased]`. When cutting a release, rename
that heading to the version and date, then re-add an empty `[Unreleased]` block.

## [Unreleased]

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
