# ADR: API key tenant identity contract

- Date: 2026-08-30
- Status: Accepted
- Work items: `AK-M06A`, `AK-M06B`, `AK-M06C`

## Context

`ApiKeysService.create()` previously accepted the TypeScript `tenantId: string`
annotation as its only validation and persisted the runtime value unchanged. The
same stored value later appeared in list results, lifecycle events, verification
contexts, and `request.apiKey`.

The published `@nestarc/rbac@0.2.1` API-key resolver does not preserve that
identity contract. It reads `request.apiKeyContext` before the canonical
`request.apiKey` property, trims strings, and coerces finite numbers to strings.
The planned RBAC `RBAC-M01` and `RBAC-M02` changes instead make trusted tenant
conflicts fail closed and treat API-key identity fields as opaque exact strings.

The current API Keys persistence contract stores `tenantId` as a required
`String`/text value. In-memory and Prisma list operations compare it exactly.
There is no package-owned tenant membership lookup or tenant data migration
runner.

## Decision

API Keys owns the tenant ID producer contract and the canonical
`request.apiKey` value. RBAC owns conversion of that verified context to an RBAC
subject, reconciliation with an authoritative tenancy source, and authorization.
API Keys does not depend on the tenancy package or determine membership.

A valid API-key tenant ID is:

- a runtime string, not a number or string-coercible object;
- 1 through 255 JavaScript UTF-16 code units;
- unchanged by `String.prototype.trim()`, which rejects empty, whitespace-only,
  and leading/trailing-whitespace values.

Internal whitespace and non-ASCII characters are preserved. API Keys does not
trim, case-fold, or Unicode-normalize tenant IDs. Canonically equivalent Unicode
spellings remain different opaque identifiers. Applications that require a
narrower UUID, slug, or provider-specific format must validate it before calling
API Keys and use the same exact value in tenancy and RBAC.

Invalid create or list input is rejected before storage access with
`ApiKeyOperationError` / `api_key_invalid_input`. A non-canonical value returned
by storage is never repaired: credential verification fails as
`api_key_invalid`, rotation fails as `api_key_not_rotatable`, and management
reads fail closed. Events and `request.apiKey` are therefore emitted only from a
validated exact tenant value.

Tenant-aware management is additive:

```ts
await apiKeys.revokeForTenant('tenant_a', keyId);
await apiKeys.rotateForTenant('tenant_a', keyId, { gracePeriodMs: 60_000 });
```

These methods return the same successful results as the legacy ID-only methods.
A missing key and an expected-tenant mismatch both use
`api_key_record_not_found`, so the safe API does not expose cross-tenant record
existence. The built-in adapters enforce the expected tenant in the same atomic
mutation as revoke or rotation. A custom adapter without the tenant-bound
capability fails fast; the service never falls back to check-then-mutate.

The existing `revoke(id)` and `rotate(id, input)` methods remain available for a
trusted system-wide management layer. They are not tenant authorization APIs.
Callers handling tenant-scoped input should migrate to the tenant-bound methods.

## Existing data and migration

No value is changed automatically. Before upgrading, operators should inventory
distinct `tenant_id` values and flag values that are empty, exceed 255 code
units, or differ from their trimmed form. For each flagged tenant, choose one
application-approved canonical value, check for collisions, update API-key rows
and every related tenancy/RBAC record in one controlled migration, then verify
the exact value through the packed consumer. Reissuing credentials is the safer
choice when coordinated identity migration cannot be proven.

Because this tightens runtime input, persisted-record, and custom-storage
contracts in a pre-1.0 package, it is targeted at `0.4.0`. Custom storage
implementors can retain the ID-only methods, but must implement the optional
tenant-bound revoke and rotate capabilities before exposing the safe service
methods.

## RBAC release prerequisite checklist (`AK-M06B`)

- [ ] Confirm an exact published RBAC version contains both `RBAC-M01` and
  `RBAC-M02`; a branch, sibling checkout, or unpublished tarball is not evidence.
- [ ] Verify the registry tarball version, `gitHead`, URL, and integrity.
- [ ] Install the packed API Keys candidate and that exact RBAC artifact in a
  fresh directory with strict peer dependencies.
- [ ] Verify `ApiKeysGuard` writes the validated exact value to `request.apiKey`.
- [ ] Verify matching canonical and trusted tenant sources authorize normally.
- [ ] Verify a conflicting trusted tenant source fails closed.
- [ ] Verify conflicting canonical `request.apiKey` and legacy
  `request.apiKeyContext` values fail closed, while an identical legacy value is
  accepted.
- [ ] Verify RBAC never trims, coerces, case-folds, or Unicode-normalizes API-key
  `keyId` or `tenantId`.
- [ ] Add the consumer to source CI and release pre-publish gates.

## Alternatives considered

### Trim at the producer

Rejected because silent repair can merge two application identities and would
hide upstream bugs. Consumers must be able to compare the exact authenticated
identity.

### Preserve every non-empty runtime value

Rejected because whitespace edges and unbounded strings make cross-package
identity drift and resource abuse easier, while runtime number coercion changes
the declared public type.

### Leave tenant-bound mutations to applications only

Rejected as the sole contract because the package already owns tenant-scoped
creation/listing and atomic rotation. Additive storage capabilities let the
library enforce the same boundary without weakening the legacy trusted-admin
path.
