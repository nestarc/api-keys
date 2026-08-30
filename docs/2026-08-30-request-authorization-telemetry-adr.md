# ADR: credential verification, request authorization, and usage telemetry

- Date: 2026-08-30
- Status: Accepted
- Work items: `AK-M07A`, `AK-M07B`

## Context

`ApiKeysService.verify(rawKey)` authenticates the credential and returns its
environment, scopes, and IP policy. Before this decision it also updated
`lastUsedAt`, optionally emitted `api_key.used`, and recorded a successful
verification metric before `ApiKeysGuard` applied environment, IP, and scope
requirements. A request later rejected with HTTP 403 therefore had no distinct
authorization telemetry and still appeared as a successful use.

The same public method can be used outside Nest. Its name and the returned
allowlist made it easy for a custom transport to assume that IP restrictions
were enforced even though `verify()` had no request or client-IP input.

## Decision

Credential verification and request authorization are separate boundaries.

- `verify(rawKey)` remains the backward-compatible credential-only primitive.
  It validates format, namespace, secret, tenant identity, revocation, and
  expiry. It does not enforce route environment, IP, or scope policy.
- `authorizeRequest(input)` is the additive request-aware primitive. It performs
  credential verification and then applies the optional required environment,
  the credential's IP allowlist, and the optional required scope.
- `ApiKeysGuard` delegates all of those checks to `authorizeRequest()` instead
  of duplicating the policy.
- A restricted credential passed to `authorizeRequest()` without an explicit
  client IP or a resolver that returns one fails closed as
  `api_key_ip_not_allowed`. The default resolver reads `request.ip` and does not
  trust forwarded headers directly.

An accepted use is recorded only after the public boundary succeeds. For direct
`verify()` callers, successful credential verification is that boundary, so the
existing `lastUsedAt` and opt-in `api_key.used` behavior is preserved. For
`authorizeRequest()` and the Guard, the boundary includes environment, IP, and
scope authorization, so a denied request does not update `lastUsedAt` or emit
`api_key.used`.

## Telemetry contract

| Request result | Verification metric | `api_key.auth_failed` | Authorization event/metric | Usage |
| --- | --- | --- | --- | --- |
| missing credential | none | none | denied / `missing` | none |
| malformed, invalid, revoked, expired credential | matching verification failure | emitted | denied / `credential_rejected` | none |
| environment denial | `success` | none | denied / `environment_denied` | none |
| IP denial or unresolved IP | `success` | none | denied / `ip_denied` | none |
| scope denial | `success` | none | denied / `scope_denied` | none |
| request accepted | `success` | none | metric `success`; no denial event | `lastUsedAt` and optional `api_key.used` |
| direct `verify()` accepted | `success` | none | none | `lastUsedAt` and optional `api_key.used` |

`api_key.auth_failed` means that a supplied credential failed credential
verification. It is not emitted when no credential was supplied. The new
`api_key.authorization_denied` event represents a rejected request boundary and
contains only `type`, `at`, and the stable public error `code`. It excludes the
raw credential, client IP, prefix, key ID, tenant ID, scopes, and route.

`onMetric` remains the existing verification metric sink. The additive
`onAuthorizationMetric` sink receives `api_key.authorization` metrics with only
`outcome`, `durationMs`, and optional low-cardinality `environment`. Its outcome
collapses all credential failures to `credential_rejected`; detailed public
error codes remain in denial events. Sink and error-reporter failures are
isolated from the original request result.

## Custom transport recipe

Custom transports should resolve client identity according to their trusted
network boundary and call the request-aware primitive:

```ts
const context = await apiKeys.authorizeRequest({
  rawKey: message.apiKey,
  clientIp: connection.verifiedRemoteAddress,
  requiredEnvironment: 'live',
  requiredScope: { resource: 'reports', level: 'read' },
});
```

Callers that intentionally need only credential authentication may continue to
use `verify()`, but must treat `allowedIpCidrs`, `environment`, and `scopes` in
the returned context as unenforced policy data.

## Compatibility and release

The new service method, input/metric types, module options, event, and metric
sink are additive. Existing direct-service `verify()` callers retain their
runtime usage tracking and verification metric behavior. Guard users gain
deferred usage tracking and authorization telemetry. Consumers with exhaustive
TypeScript switches over `ApiKeyEvent` must handle the additive
`api_key.authorization_denied` variant.

This ships with the other planned pre-1.0 `0.4.0` contract changes. No trusted
proxy behavior is inferred or enabled automatically.

## Alternatives considered

### Make `verify()` require request context

Rejected because it would break direct-service and non-request credential
consumers and would make a previously required single string insufficient.

### Keep Guard-only IP and scope checks

Rejected because it leaves custom transports without one reusable policy
primitive and allows the Guard and service contracts to drift.

### Count every verified credential as Guard usage

Rejected for the request-aware path because a known credential repeatedly
denied by environment, IP, or scope policy should not advance the last accepted
use timestamp. Credential verification success remains independently visible in
the verification metric.
