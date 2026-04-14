# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased changes are kept under `[Unreleased]`. When cutting a release, rename
that heading to the version and date, then re-add an empty `[Unreleased]` block.

## [Unreleased]

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
