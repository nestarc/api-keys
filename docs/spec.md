# @nestarc/api-keys — v0.1 Technical Spec

> [!NOTE]
> 상태: `HISTORICAL / COMPLETED (v0.1)`. 이 문서의 결정을 새 backlog로 실행하지 않는다.
> 현재 계약은 [README](../README.md), 미완료 작업은
> [canonical 유지보수 큐](./2026-08-30-p0-p3-maintenance-work-plan.md)를 기준으로 한다.

본 문서는 v0.1에서 고정된 기술 결정을 기록한다. 0.2.0에서 추가된 회전,
lifecycle event, context helper의 상세 스펙은 [`spec-0.2.md`](./spec-0.2.md)를
기준으로 한다.

## 1. 키 포맷

```
nk_{env}_{prefix}_{secret}
│  │    │         └── 32자 base62 랜덤. 해시 저장 대상
│  │    └──────────── 12자 base62 랜덤. 평문 저장, UNIQUE index
│  └───────────────── "live" | "test"
└──────────────────── 패키지/consumer 네임스페이스. 기본 "nk", 설정 가능
```

예시:

```
nk_live_a8f3K2xPqR4v_7hQmN2pLw9xYtB5vCzF4jK1mR6nV8sU3aE
```

### 설계 근거

- **prefix 분리**: 상수시간 비교 전에 빠른 조회 키로 활용. timing attack 방지. Stripe가 쓰는 패턴.
- **환경 비트**: 사용자가 한눈에 식별 가능. 실수 방지 가드레일.
- **네임스페이스**: 한 회사가 여러 제품에 nestarc를 쓸 때 키 충돌 방지.

### 구성 옵션

```ts
ApiKeysModule.forRoot({
  namespace: 'acme', // 기본 'nk'
  peppers: { 1: process.env.API_KEY_PEPPER! },
  currentPepperVersion: 1,
  storage,
});
```

## 2. 해싱

- **알고리즘**: SHA-256
- **입력**: `secret + pepper` (pepper는 env, 32+ bytes)
- **비교**: `crypto.timingSafeEqual`

### 설계 근거

- API 키는 128비트+ 고엔트로피 랜덤이므로 brute-force 내성이 이미 충족된다. OWASP도 API 키에 대해 bcrypt 불필요로 본다.
- per-request 인증이므로 bcrypt/argon2의 50~200ms 비용은 허용 불가.
- pepper는 DB 유출 시 오프라인 공격 방어. env에 분리 저장.

### Pepper 회전

- 스키마에 `pepperVersion: Int` 컬럼 보관.
- 모듈 설정에서 `peppers: { 1: ..., 2: ... }` 맵 허용.
- 검증 시 해당 버전 pepper로 비교.
- 새로 생성되거나 회전된 user key는 `currentPepperVersion`을 사용한다.

## 3. Scope 모델

### 형태

Stripe Restricted API Keys 호환 구조를 채택한다.

```ts
type Resource = string; // "invoices", "reports" 등 consumer 정의
type Level = 'read' | 'write';
type Scope = { resource: Resource; level: Level };
```

### 내부 표현

DB 저장 및 비교는 flatten된 문자열.

```
"invoices:read", "invoices:write", "reports:read"
```

`write`는 `read`를 포함한다 (Stripe와 동일).

### 적용

```ts
@UseGuards(ApiKeysGuard)
@RequireScope('invoices', 'write')
@Post('/invoices')
createInvoice() {}
```

### 경로

- v0.1: 문자열 매칭 엔진 내장
- v0.3: `@nestarc/rbac`는 API key를 subject로 매핑하며 scope와 RBAC permission은 독립적으로 평가

## 4. 환경 분리

### 키 레벨

- 키 자체가 `live` 또는 `test` 중 하나로 발급된다.
- 발급 시 `environment` 컬럼에 저장되고 prefix에도 반영된다.

### 앱 레벨 강제

```ts
@RequireEnvironment('live')
@Post('/charges')
charge() {}
```

불일치 시 `403 api_key_environment_mismatch` 반환.

### 데이터 격리

라이브러리는 **격리를 강제하지 않는다.** consumer가 자신의 아키텍처에 맞춰 결정:

- 단일 DB + `environment` 컬럼 필터링 (권장)
- 별도 스키마 / DB 분리

`ApiKeyContext.environment`를 노출하여 consumer가 활용.

## 5. DB 스키마 (Prisma)

```prisma
model ApiKey {
  id             String    @id @default(cuid())
  tenantId       String
  name           String
  environment    String    // "live" | "test"
  prefix         String    @unique
  hash           String
  pepperVersion  Int       @default(1)
  scopes         String[]
  allowedIpCidrs String[]   @default([])
  lastUsedAt     DateTime?
  expiresAt      DateTime?
  revokedAt      DateTime?
  rotatedAt      DateTime?
  replacedByKeyId String?
  createdBy      String?
  createdAt      DateTime  @default(now())

  @@index([tenantId, environment])
  @@index([tenantId, revokedAt])
  @@index([replacedByKeyId])
}
```

### RLS

`tenantId` 기준 RLS 정책은 consumer 책임. `@nestarc/tenancy` 사용 시 기존 정책 재사용.

### lastUsedAt 업데이트 전략

- 매 요청마다 UPDATE는 비용 과다.
- **debounce**: 현재 시각과 `lastUsedAt` 차이가 60초 미만이면 skip.
- 더 엄격한 분석이 필요한 consumer는 `outbox`로 비동기 이벤트 기록 권장.

## 6. 검증 흐름

```
1. Header 파싱: "Authorization: Bearer nk_live_XXXX_YYYY"
2. 포맷 파싱: env, prefix, secret 분리
3. 형식 유효성: regex / 길이 검사
4. DB 조회:
   SELECT * FROM ApiKey
   WHERE prefix = ?
     AND revokedAt IS NULL
     AND (expiresAt IS NULL OR expiresAt > NOW())
5. 해시 비교:
   timingSafeEqual(
     sha256(secret + peppers[row.pepperVersion]),
     row.hash
   )
6. 환경 검증: row.environment === expected (데코레이터가 있을 경우)
7. IP allowlist 검증: clientIpResolver 결과가 allowedIpCidrs에 포함되는지 확인
8. Scope 검증: @RequireScope 대비 row.scopes 포함 여부
9. 성공:
   - request.apiKey에 { tenantId, keyId, scopes, environment, prefix } 주입
   - contextWriter가 있으면 consumer의 request-local context에 bridge
   - lastUsedAt debounced update (fire-and-forget)
   - api_key.used lifecycle event는 선택적, 기본 off
10. 실패:
   - lifecycle hook: api_key.auth_failed (prefix만 기록, 평문 금지)
   - 일정 응답 시간 유지 (prefix 미존재 시 dummy hash 수행)
```

## 7. 공개 API 표면

```ts
// 서비스
apiKeys.create(input: {
  tenantId: string;
  name: string;
  environment?: 'live' | 'test';  // 기본 'live'
  scopes: Scope[];
  expiresAt?: Date;
  createdBy?: string;
  allowedIpCidrs?: string[];
}): Promise<{ id: string; key: string }>;   // key는 이 반환값에서만 노출

apiKeys.verify(rawKey: string): Promise<ApiKeyContext>;

apiKeys.revoke(id: string): Promise<void>;
apiKeys.list(tenantId: string, opts?: { includeRevoked?: boolean }): Promise<ApiKey[]>;
apiKeys.rotate(id: string, opts?: {
  gracePeriodMs?: number;
  name?: string;
  createdBy?: string;
  expiresAt?: Date | null;
  allowedIpCidrs?: string[];
}): Promise<{ id: string; key: string; replacedKeyId: string; graceExpiresAt: Date }>;

// Guards & Decorators
@UseGuards(ApiKeysGuard)
@RequireScope(resource: string, level: 'read' | 'write')
@RequireEnvironment(env: 'live' | 'test')
@CurrentApiKey()
getApiKeyContext(request)

// Context
ApiKeyContext {
  tenantId: string;
  keyId: string;
  scopes: string[];
  environment: 'live' | 'test';
  prefix: string;
  allowedIpCidrs?: string[];
}
```

## 8. 보안 체크리스트

- [x] 평문 키는 `create()` 반환값에서만 노출
- [x] Logger redact 규칙 제공 (`nk_(live|test)_[a-zA-Z0-9]+_[a-zA-Z0-9]+`)
- [x] `timingSafeEqual` 비교
- [x] prefix 미존재 시 dummy hash로 응답 시간 일정화
- [x] pepper는 env only, 코드 저장 금지
- [x] 인증 실패 로그에 평문/해시 기록 금지 (prefix와 tenant만)
- [x] TLS 외부는 검증하지 않음 (consumer 책임, README 명시)
- [x] 키 생성 시 scope 0개 허용 금지 (명시적 실패)

## 9. 에러 코드

| 코드                           | HTTP | 의미                                      |
| ------------------------------ | ---- | ----------------------------------------- |
| `api_key_missing`              | 401  | 헤더에 키 없음                            |
| `api_key_malformed`            | 401  | 포맷 오류                                 |
| `api_key_invalid`              | 401  | 존재하지 않거나 해시 불일치               |
| `api_key_revoked`              | 401  | 폐기됨                                    |
| `api_key_expired`              | 401  | 만료됨                                    |
| `api_key_environment_mismatch` | 403  | live/test 엔드포인트와 불일치             |
| `api_key_scope_insufficient`   | 403  | scope 부족                                |
| `api_key_ip_not_allowed`       | 403  | 요청 IP가 키 allowlist에 없거나 확인 불가 |

## 10. 다른 패키지와의 결합

### @nestarc/tenancy

Guard 성공 시 `request.apiKey`에 `ApiKeyContext`를 붙인다. consumer는 `contextWriter`
hook에서 `tenantId`를 자신의 ALS/RLS context에 주입할 수 있다.

### @nestarc/audit-log

다음 lifecycle event를 `onEvent` hook으로 publish할 수 있다:

- `api_key.created`
- `api_key.revoked`
- `api_key.rotated`
- `api_key.auth_failed` (rate-limited, 초당 N개 초과 시 샘플링)

`api_key.used`는 **기본 off**. 너무 잦아 로그 오염 유발.

### @nestarc/rbac (v0.3)

`@nestarc/rbac/integrations/api-keys`의 `createApiKeySubjectResolver()`가
`request.apiKey`를 `api_key` subject로 매핑한다. `@RequireScope`는 키에 내장된
scope를, RBAC `@Can`은 동적으로 저장된 role binding을 확인하며 둘을 함께 쓰면
두 검사를 모두 통과해야 한다.

### @nestarc/outbox

`lastUsedAt` 정밀 추적이 필요한 consumer는 `api_key.used` 이벤트를 outbox로 발행하는 옵션을 enable 가능.
