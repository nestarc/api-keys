# @nestarc/api-keys — PRD

## 1. 문제 정의

B2B SaaS 백엔드에서 고객이 "서버에서 여러분 API를 호출하려면 뭘 써야 하나요?"라고 물었을 때, 답을 직접 만들어야 한다. 이 과정에서 반복적으로 발생하는 문제:

- 키를 평문/bcrypt로 저장하거나, 조회 성능이 O(n)이 되는 구현
- 테넌트와 키를 연결하는 방식이 `tenancy` RLS 컨텍스트와 분리되어 권한 누수 발생
- 회전(rotation), 만료, 폐기를 뒤늦게 추가하며 스키마 마이그레이션 비용 발생
- test/live 환경 구분을 앱 레벨에서 뒤섞어 운영 사고 발생
- 감사 로그와 연결되지 않아 "누가 언제 이 키를 썼나"를 추적 불가

Clerk, Auth0, Better-Auth는 **end-user authentication**에 집중하고 있어 이 영역은 상대적으로 공백이다. Unkey, Zuplo API Keys 같은 상용 서비스가 존재하나 셀프호스트 + Prisma + 멀티테넌트 통합은 드물다.

## 2. 해결 방향

nestarc의 기존 축(`tenancy`, `audit-log`, `access-control` 예정)과 자연스럽게 결합되는 **프로덕션 레디 API key primitive**를 제공한다. "Stripe처럼 동작하는 셀프호스트 API key"를 한 줄 포지셔닝으로 잡는다.

## 3. 타깃 사용자

- NestJS + Prisma + PostgreSQL 기반 멀티테넌트 SaaS 백엔드 개발자
- 고객사에 API 접근을 제공해야 하는 B2B 제품 팀
- 자체 API 키 시스템을 보안 사고 없이 빠르게 갖추고 싶은 초기 단계 스타트업

## 4. 성공 기준

- **도입 마찰**: `npm install` → 모듈 등록 → 마이그레이션 → Guard 적용까지 15분 이내
- **보안 기본값**: 안전하지 않은 구성이 기본이 되지 않는다. SHA-256 해시, pepper 필수, 평문 노출은 최초 1회
- **성능**: 키 검증 p99 < 3ms (in-memory cache 포함 가정)
- **통합**: `@nestarc/tenancy` 사용 시 추가 코드 없이 RLS 컨텍스트가 자동 주입된다

## 5. 범위

### 포함 (v0.1)
- 키 발급, 검증, 회전, 폐기, 만료
- SHA-256 + pepper 해싱
- Stripe 스타일 포맷: `nk_{env}_{prefix}_{secret}`
- Resource × (read|write) scope 매트릭스
- test/live 환경 분리 (prefix + 컬럼)
- NestJS Guard + `@RequireScope` 데코레이터
- `@nestarc/tenancy` ALS 자동 주입
- `@nestarc/audit-log` 이벤트(생성/회전/폐기/실패 인증) 자동 기록
- 사용 추적: `lastUsedAt` debounced 업데이트

### 제외
- OAuth, JWT 세션, end-user 로그인 (Clerk/Auth0/better-auth 영역)
- 관리 UI (headless 유지)
- 엔드포인트별 rate limiting (후속 `@nestarc/quotas` 담당)
- 결제/플랜 연동 (후속 `@nestarc/entitlements` 담당)
- 키 분석 대시보드

## 6. 경쟁/비교

| 항목 | Stripe RAK | Unkey | Clerk | 자체구현 | @nestarc/api-keys |
|---|---|---|---|---|---|
| 셀프호스트 | ✗ | 부분 | ✗ | ✓ | ✓ |
| Prisma 통합 | — | ✗ | ✗ | 수동 | ✓ |
| Multi-tenant 네이티브 | — | ✗ | 제한적 | 수동 | ✓ (tenancy 연동) |
| Scope 모델 | ✓ | ✓ | ✗ | 수동 | ✓ (Stripe 호환) |
| Test/Live 분리 | ✓ | ✓ | ✗ | 수동 | ✓ |
| Audit 통합 | ✓ | ✓ | 부분 | 수동 | ✓ (audit-log 연동) |

## 7. 비기능 요건

- **보안**: 평문 로깅 금지(logger redact 규칙 제공), 상수시간 비교, 실패 응답 시간 일정화
- **가용성**: 폐기는 5초 이내 반영(캐시 TTL)
- **관찰성**: 생성/회전/폐기/인증실패 4개 이벤트 publish
- **테스트 가능성**: `createTestKey()` 헬퍼로 통합 테스트 1줄 작성

## 8. 의존성과 연결

- 필수: `@prisma/client`, `@nestjs/common`
- 선택: `@nestarc/tenancy` (권장), `@nestarc/audit-log` (권장), `@nestarc/access-control` (후속)
- 런타임: Node 20+, PostgreSQL 14+

## 9. 로드맵

**v0.1** (MVP, 2~3주)
- 모듈/서비스/Guard
- Prisma 스키마 + 마이그레이션 가이드
- SHA-256 해싱
- 문자열 flatten scope (`"resource:level"`)
- tenancy/audit-log 기본 통합
- README + quickstart

**v0.2**
- 키 회전 (graceperiod)
- Test/Live 모드 엄격 분리 데코레이터
- 캐시 계층 (Redis 선택)
- `@RequireScope('resource', 'write')` decorator API

**v0.3**
- `@nestarc/access-control` adapter
- argon2 해싱 옵션
- IP allowlist per key
- 사용량 메트릭 내보내기

## 10. 리스크와 대응

| 리스크 | 대응 |
|---|---|
| SHA-256 + pepper 유출 시 오프라인 공격 | pepper rotation 가이드 제공, v0.3에 argon2 옵션 |
| 사용자가 평문 키를 로깅 | logger redact 미들웨어 제공, README 명시 |
| Scope 모델이 Stripe 모델로 굳어 access-control과 충돌 | adapter 패턴으로 분리, scope string은 내부 표현 |
| test/live 혼용 사고 | 키 검증 시 환경 불일치를 별도 에러 코드로 노출 |
