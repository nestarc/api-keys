# @nestarc/api-keys — v0.2 Technical Spec

> [!NOTE]
> 상태: `HISTORICAL / COMPLETED (v0.2)`. 이 문서의 Must/Should 항목은 출시 기록이며 새
> backlog가 아니다. 현재 계약은 [README](../README.md), 미완료 작업은
> [canonical 유지보수 큐](./2026-08-30-p0-p3-maintenance-work-plan.md)를 기준으로 한다.

본 문서는 0.2.0에서 실제 개발할 범위를 고정한다. 목표는 0.1.0의
MVP를 유지하면서 API key lifecycle, 감사 가능성, nestarc 통합 표면을
운영 가능한 수준으로 올리는 것이다.

## 1. 최종 선정 범위

### Must-have

1. **무중단 키 회전**
   - 새 key를 발급하고 기존 key에는 grace period 만료 시각을 설정한다.
   - 원문 key는 새 key 발급 응답에서만 한 번 반환한다.
   - 기존 key의 원문 secret은 저장하지 않으므로 rehash 방식의 회전은 제공하지 않는다.

2. **Lifecycle event/audit hook**
   - 생성, 폐기, 회전, 인증 실패 이벤트를 표준 payload로 발행한다.
   - raw key, hash, pepper 값은 어떤 이벤트에도 포함하지 않는다.
   - 기존 `onAuthFailed`는 유지하되 새 `onEvent`가 우선 표준 API가 된다.

3. **Stable API key context contract**
   - Guard 성공 후 request에 붙는 context를 공식 contract로 문서화한다.
   - `@CurrentApiKey()` decorator와 `getApiKeyContext()` helper를 제공한다.
   - `ApiKeyContext`에 안전하게 로그 가능한 `prefix`를 추가한다.

4. **문서와 테스트 정렬**
   - v0.1 문서가 이미 구현된 것처럼 적은 rotation, audit-log, tenancy 자동 주입 설명을
     v0.2 기준으로 정정한다.
   - storage contract와 integration test를 v0.2 기능에 맞게 확장한다.

### Should-have

- `defaultExpiresIn`, `maxExpiresIn`, `allowNeverExpires` 형태의 opt-in TTL policy.
- `onVerified` 또는 `contextWriter` hook을 통한 `@nestarc/tenancy` bridge recipe.
- `ApiKeysTestingModule` 또는 `createTestKey()` helper는 0.2.0에서 제외하고 후속 버전으로 이월한다.

### Not now

- 내장 rate limiter, quota, billing, usage dashboard.
- Redis verification cache.
- management UI 또는 developer portal.
- OAuth/OIDC/full IAM.
- IP allowlist.
- argon2 hashing option.
- GitHub secret scanning partner integration.

## 2. Design Principles

- **Additive public API first**: 기존 `create`, `verify`, `revoke`, `list` 동작을 깨지 않는다.
- **Plaintext never persists**: rotation 후에도 raw key는 반환값 밖에 존재하지 않는다.
- **Lifecycle is explicit**: rotation, revocation, expiration은 서로 다른 운영 의미를 갖는다.
- **Audit-safe payloads**: event payload는 prefix와 id만 포함하고 secret/hash/pepper는 금지한다.
- **Headless integration**: `audit-log`, `outbox`, `tenancy`, `rbac`를 직접 의존하지 않고 hook과 helper로 연결한다.
- **Cache later**: revoke/rotation 일관성이 더 중요하므로 verification cache는 0.2.0에 넣지 않는다.

## 3. Key Rotation

### Public API

```ts
export interface RotateApiKeyInput {
  /**
   * Planned rotation window. Defaults to 0 for security.
   * Set this explicitly for zero-downtime customer migration.
   */
  gracePeriodMs?: number;
  name?: string;
  createdBy?: string;
  expiresAt?: Date | null;
}

export interface RotateApiKeyResult {
  id: string;
  key: string;
  replacedKeyId: string;
  graceExpiresAt: Date;
}

apiKeys.rotate(id: string, input?: RotateApiKeyInput): Promise<RotateApiKeyResult>;
```

### Semantics

- `rotate()` creates a new key using the current namespace, environment, scopes, and tenant of the old key.
- `name`, `createdBy`, and `expiresAt` may be overridden by input.
- If `gracePeriodMs` is omitted, it defaults to `0`; the old key expires immediately.
- If `gracePeriodMs > 0`, both old and new keys verify until `graceExpiresAt`.
- The old key is not marked revoked. It receives rotation metadata and an `expiresAt` value.
- If the old key already has an earlier `expiresAt`, the earlier expiration wins.
- Revoked keys cannot be rotated.
- Expired keys cannot be rotated unless a future version explicitly adds recovery semantics.
- Rotation is not pepper rehash. Existing key secrets cannot be rehashed because raw secrets are not stored.
- Consumers should use `revoke()` instead of grace rotation for known compromise.

### Record Changes

```ts
export interface ApiKeyRecord {
  // existing fields...
  rotatedAt: Date | null;
  replacedByKeyId: string | null;
}
```

Prisma example schema adds:

```prisma
rotatedAt       DateTime?
replacedByKeyId String?

@@index([replacedByKeyId])
```

### Storage Contract

The storage interface becomes:

```ts
export interface ListApiKeysOptions {
  includeRevoked?: boolean;
}

export interface ApiKeyStorage {
  insert(record: ApiKeyRecord): Promise<void>;
  findById(id: string): Promise<ApiKeyRecord | null>;
  findByPrefix(prefix: string): Promise<ApiKeyRecord | null>;
  listByTenant(tenantId: string, opts?: ListApiKeysOptions): Promise<ApiKeyRecord[]>;
  markRevoked(id: string, at: Date): Promise<void>;
  touchLastUsed(id: string, at: Date): Promise<void>;
  rotate(input: RotateApiKeyStorageInput): Promise<void>;
}

export interface RotateApiKeyStorageInput {
  oldKeyId: string;
  newRecord: ApiKeyRecord;
  oldExpiresAt: Date;
  rotatedAt: Date;
}
```

`rotate()` must be atomic for production storage adapters. The Prisma adapter should use a transaction so the old key is not expired unless the new key insert succeeds.

### Duplicate Prefix Handling

Rotation reuses the same collision retry policy as `create()`:

- Retry up to 3 times if storage reports duplicate prefix.
- If all attempts fail, throw `Error('failed to generate a unique API key prefix')`.

### Rotation Events

Successful rotation emits:

```ts
{
  type: 'api_key.rotated',
  at: Date,
  tenantId: string,
  oldKeyId: string,
  oldPrefix: string,
  newKeyId: string,
  newPrefix: string,
  environment: Environment,
  scopes: string[],
  graceExpiresAt: Date,
  createdBy: string | null
}
```

## 4. Lifecycle Events

### Public API

```ts
export interface ApiKeyEventBase {
  at: Date;
}

export interface ApiKeyCreatedEvent extends ApiKeyEventBase {
  type: 'api_key.created';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
  scopes: string[];
  createdBy: string | null;
}

export interface ApiKeyRevokedEvent extends ApiKeyEventBase {
  type: 'api_key.revoked';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
}

export interface ApiKeyRotatedEvent extends ApiKeyEventBase {
  type: 'api_key.rotated';
  tenantId: string;
  oldKeyId: string;
  oldPrefix: string;
  newKeyId: string;
  newPrefix: string;
  environment: Environment;
  scopes: string[];
  graceExpiresAt: Date;
  createdBy: string | null;
}

export interface ApiKeyAuthFailedEvent extends ApiKeyEventBase {
  type: 'api_key.auth_failed';
  prefix: string | null;
  code: ApiKeyErrorCode;
  tenantId?: string;
  keyId?: string;
  environment?: Environment;
}

export interface ApiKeyUsedEvent extends ApiKeyEventBase {
  type: 'api_key.used';
  keyId: string;
  tenantId: string;
  prefix: string;
  environment: Environment;
  scopes: string[];
}

export type ApiKeyEvent =
  | ApiKeyCreatedEvent
  | ApiKeyRevokedEvent
  | ApiKeyRotatedEvent
  | ApiKeyAuthFailedEvent
  | ApiKeyUsedEvent;

export type ApiKeyEventSink = (event: ApiKeyEvent) => void | Promise<void>;

export interface ApiKeysModuleOptions {
  // existing options...
  onEvent?: ApiKeyEventSink;
  onEventError?: (error: unknown, event: ApiKeyEvent) => void;
  emitUsageEvents?: boolean;

  /**
   * Kept for backwards compatibility.
   * In 0.2.0 auth failures call both onAuthFailed and onEvent when provided.
   */
  onAuthFailed?: (prefix: string | null, code: string) => void;
}
```

### Event Types

Required events:

- `api_key.created`
- `api_key.revoked`
- `api_key.rotated`
- `api_key.auth_failed`

Optional high-volume event:

- `api_key.used`

`api_key.used` is disabled by default and controlled by `emitUsageEvents`. `lastUsedAt` remains the low-cost default usage signal.

### Payload Rules

Every event may include:

- `type`
- `at`
- `tenantId` when known
- `keyId` or old/new key ids
- `prefix` when known
- `environment` when known
- `scopes` when known
- `createdBy` when relevant
- failure `code` for auth failures

No event may include:

- raw API key
- secret segment
- hash
- pepper or pepper version
- Authorization header value

### Delivery Semantics

- Event hooks are best-effort by default.
- `onEvent` failures must not break authentication.
- For `create`, `revoke`, and `rotate`, events are emitted after successful storage mutation.
- If `onEvent` throws, the service calls `onEventError` when provided and otherwise swallows the error.
- Durable audit is the consumer's responsibility; recommended sinks are `@nestarc/audit-log` or `@nestarc/outbox`.

### Backwards Compatibility

- `onAuthFailed(prefix, code)` remains supported for 0.2.0.
- New integrations should use `onEvent`.
- Auth failure must invoke `onAuthFailed` and `onEvent({ type: 'api_key.auth_failed', ... })` if both are configured.

## 5. Stable Context Contract

### Context Shape

```ts
export interface ApiKeyContext {
  keyId: string;
  tenantId: string;
  environment: Environment;
  scopes: string[];
  prefix: string;
}
```

`prefix` is safe for logs and support tooling. It must never be sufficient to authenticate.

### Request Contract

Guard success attaches context to:

```ts
request[API_KEY_CONTEXT_PROPERTY]; // default property name: "apiKey"
```

This property name is a stable public contract for 0.2.x.

### Decorator and Helper

```ts
export const CurrentApiKey = createParamDecorator((_data: unknown, ctx: ExecutionContext) =>
  getApiKeyContext(ctx.switchToHttp().getRequest()),
);

export function getApiKeyContext(request: unknown): ApiKeyContext | undefined;
```

`@CurrentApiKey()` is HTTP-first. GraphQL/RPC adapters are out of scope for 0.2.0.

### Integration Hook

```ts
export type ApiKeyContextWriter = (apiKey: ApiKeyContext, request: unknown) => void | Promise<void>;

export interface ApiKeysModuleOptions {
  contextWriter?: ApiKeyContextWriter;
}
```

`contextWriter` runs after scope and environment checks pass. It enables recipes such as writing `tenantId` into `@nestarc/tenancy` ALS without importing tenancy directly.

## 6. TTL Policy

TTL policy is a should-have. It is opt-in only in 0.2.0 to avoid changing existing behavior.

```ts
export interface ApiKeyTtlPolicy {
  defaultExpiresInMs?: number;
  maxExpiresInMs?: number;
  allowNeverExpires?: boolean; // default true for backwards compatibility
}

export interface ApiKeysModuleOptions {
  ttlPolicy?: ApiKeyTtlPolicy;
}
```

Rules:

- If `defaultExpiresInMs` is set and `create()` input has no `expiresAt`, set `expiresAt = now + defaultExpiresInMs`.
- If `allowNeverExpires === false`, `create()` must reject keys without effective expiration.
- If `maxExpiresInMs` is set, `create()` and `rotate()` must reject an expiration later than `now + maxExpiresInMs`.
- Existing `expiresAt` verification semantics do not change.

## 7. Testing Helpers

Testing helpers are deferred from 0.2.0 because rotation, lifecycle events, context helpers,
and TTL policy are the selected release scope. The likely follow-up shape is:

```ts
export interface CreateTestKeyOptions {
  tenantId?: string;
  name?: string;
  environment?: Environment;
  scopes?: Scope[];
  expiresAt?: Date;
  createdBy?: string;
}

export async function createTestKey(
  service: ApiKeysService,
  options?: CreateTestKeyOptions,
): Promise<CreateApiKeyResult & { context: ApiKeyContext }>;
```

If a Nest testing module helper is added, it should be a thin wrapper around `ApiKeysModule.forRoot()` with `InMemoryApiKeyStorage`, deterministic pepper, and optional clock/id factory.

## 8. Error Handling

0.2.0 does not add new authentication failure codes. Existing verification errors remain:

- `api_key_missing`
- `api_key_malformed`
- `api_key_invalid`
- `api_key_revoked`
- `api_key_expired`
- `api_key_environment_mismatch`
- `api_key_scope_insufficient`

Management operations may introduce a separate error type:

```ts
export const ApiKeyOperationErrorCode = {
  NotFound: 'api_key_record_not_found',
  NotRotatable: 'api_key_not_rotatable',
} as const;
```

This error type is not thrown by `verify()` and does not map to authentication HTTP status by default.

## 9. Documentation Changes

Update docs to distinguish implemented 0.1 behavior from 0.2 behavior:

- `docs/prd.md`
  - Move "rotation", "audit-log automatic recording", and "tenancy ALS automatic injection" out of v0.1 implemented scope.
  - Mark them as 0.2 selected work or integration recipes.
- `docs/spec.md`
  - Keep as v0.1 historical spec, or add a note pointing to this file for 0.2.
- `README.md`
  - Add `rotate()` quickstart.
  - Add event hook example.
  - Add `@CurrentApiKey()` example.
  - Clarify that `currentPepperVersion` rotates peppers for newly issued keys; it is not user key rotation.

## 10. Required Tests

### Unit Tests

- `rotate()` computes `graceExpiresAt` from `clock() + gracePeriodMs`.
- Rotation preserves tenant, environment, and scopes by default.
- Rotation accepts `name`, `createdBy`, and `expiresAt` overrides.
- `ApiKeyContext` includes `prefix`.
- `getApiKeyContext()` returns undefined when context is absent.
- `@CurrentApiKey()` reads the same property as `ApiKeysGuard`.
- Event payloads never include raw key, hash, secret, or pepper.
- `onEvent` failures are isolated and forwarded to `onEventError`.

### Integration Tests

- Old and new keys both verify during grace period.
- Old key fails with `api_key_expired` after grace period.
- Revoked key cannot be rotated.
- Expired key cannot be rotated.
- Duplicate prefix during rotation retries.
- `api_key.created`, `api_key.revoked`, `api_key.rotated`, and `api_key.auth_failed` events fire.
- `emitUsageEvents` controls `api_key.used`.
- Guard still enforces `@RequireScope` and `@RequireEnvironment` after context changes.

### Storage Contract Tests

- `findById()` returns inserted records.
- `rotate()` inserts the new record and updates the old record atomically.
- `rotate()` preserves previous earlier `expiresAt` when it is earlier than grace expiration.
- `listByTenant()` can show rotation metadata.
- `markRevoked()` behavior remains unchanged.

## 11. Release Acceptance Criteria

0.2.0 is complete when:

- Existing 0.1 tests still pass.
- New rotation, event, context, and storage contract tests pass.
- `npm run build` passes.
- README documents the selected 0.2 APIs with no raw key logging examples.
- `docs/prd.md` no longer claims unimplemented v0.1 features as shipped.
- Prisma schema example includes v0.2 rotation fields.
- Changelog lists breaking adapter contract changes clearly.

## 12. Deferred Decisions

- Redis or other distributed verification cache.
- First-class quota/rate-limit package integration.
- Direct `@nestarc/audit-log` adapter package.
- Direct `@nestarc/tenancy` dependency.
- GraphQL/RPC guard support.
- API product/resource grouping beyond current `resource:level` scopes.
- IP allowlist and request signature/HMAC support.
