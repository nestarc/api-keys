# `@nestarc/api-keys` v0.3.2 P0–P3 유지보수 작업 계획

- 상태: `ACTIVE`
- 작성일: 2026-08-30 (Asia/Seoul)
- 공개 기준: `v0.3.2`, `origin/main@a24fe1d656e32dae0fe04d14a0df2fec5a15b41e`
- 조사 checkout: `codex/ten-m21-api-keys-modern@972a0e9599092564b2bbc0f324e65108d2ed280e`
- tree hash: 공개 기준과 조사 checkout 모두 `19bb9755b10dbd2b8026e4743a58ee28786daf6c`
- 패키지: `@nestarc/api-keys@0.3.2`
- 목적: P0–P3 조사 결과를 한 세션에 한 작업/한 PR로 실행할 수 있게 나누고, 새 세션이 조사와 완료 작업을 반복하지 않도록 한다.

> [!IMPORTANT]
> 이 문서가 v0.3.2 이후 유지보수 큐의 기준이다. `docs/superpowers/plans/**`와 과거 spec의 미체크 항목은 역사 자료이지 자동 backlog가 아니다. [`prisma-peer-compatibility-plan-2026-08-23.md`](./prisma-peer-compatibility-plan-2026-08-23.md)는 사용자 수정 중이며 덮어쓰지 않는다. 그 문서의 `0.3.2 candidate/publish pending` 표현은 2026-08-30 현재 이미 완료된 배포 상태보다 오래됐다.

> [!CAUTION]
> P0/P1에는 인증·키 회전·tenant 경계가 포함된다. 상세 공격 payload, 실제 raw key, pepper, hash, 비공개 재현 스크립트는 공개 이슈나 일반 릴리스 노트에 남기지 않는다. 공개 기록에는 영향, 수정 계약, 회귀 테스트 결과만 남긴다.

## 0. 문서 운영 규칙

### 0.1 우선순위

| 우선순위 | 의미 | 실행 원칙 |
| --- | --- | --- |
| `P0` | 현재 공개 계약의 인증/격리/credential lifecycle을 직접 깨뜨리는 재현된 문제 | 다른 기능보다 먼저 수정하고 patch release 후보로 관리한다. |
| `P1` | 잘못된 입력, hook, 지원 범위, dependency 상태가 보안 또는 운영 신뢰성을 떨어뜨리는 문제 | P0 뒤에 진행하며 한 PR에 한 계약만 바꾼다. |
| `P2` | 안전한 관리 API, 문서, 테스트, 공급망, adapter parity 개선 | P0/P1 계약이 안정된 뒤 진행한다. |
| `P3` | 구조 개선, 장기 호환성, 연구성 기능 | 별도 ADR/스파이크로 시작하며 현 release를 막지 않는다. |

### 0.2 상태

| 상태 | 의미 |
| --- | --- |
| `READY` | 선행 조건이 충족돼 바로 시작할 수 있다. |
| `IN_PROGRESS` | 한 세션이 작업을 소유해 구현·검증 중이다. 동시에 다른 세션이 같은 ID를 시작하지 않는다. |
| `BLOCKED` | 표에 적힌 선행 작업 또는 외부 release가 필요하다. |
| `DECISION` | 표의 선행이 충족됐으며 이 작업 단위에서 호환성/제품 계약을 먼저 선택해야 한다. ADR만으로 끝나는지 같은 PR에서 additive 구현까지 하는지 완료 조건을 따른다. |
| `EXTERNAL` | 다른 저장소나 관리자 권한에서 수행한다. |
| `DONE` | 코드, 검증, 문서, 필요한 배포 증거가 모두 끝났다. |
| `SUPERSEDED` | 다른 작업에 흡수됐으며 재실행하지 않는다. |

### 0.3 새 세션 시작 절차

1. 이 문서의 기준 커밋과 현재 `git status --short --branch`를 비교한다.
2. 기존 수정 파일과 미추적 파일의 소유권을 보존한다. `git reset`, checkout 복원, `.DS_Store` 삭제를 임의로 하지 않는다.
3. 공개 상태는 `origin/main`, release tag, npm `latest`를 다시 조회한다. 날짜가 달라졌으면 먼저 기준선/큐 상태만 갱신한다.
4. 실행 큐에서 가장 앞선 실행 가능한 `READY` 또는 선행이 충족된 `DECISION` 작업 하나만 고르고 선행 조건, 비범위, 외부 의존성을 확인한다. 뒤쪽 P2/P3 작업의 기술적 선행이 충족됐더라도 앞선 P0/P1을 건너뛰지 않는다.
5. "정확한 첫 행동"의 실패 테스트 또는 계약 표부터 만든다.
6. 수정 전후에 해당 작업의 검증 프로필과 `git diff --check`를 실행한다.

시작용 최소 명령:

```bash
git fetch --prune --tags
git status --short --branch
git log -1 --oneline
git rev-parse origin/main
git rev-parse v0.3.2
gh release view v0.3.2 --json tagName,targetCommitish,publishedAt
npm view @nestarc/api-keys version dist.tarball time --json
node -p "require('./package.json').version"
npm test -- --runInBand
```

### 0.4 세션 종료 인계 형식

작업을 끝내거나 중단할 때 이 문서의 작업 상태와 마지막 작업 기록을 갱신한다.

```text
Task: AK-Mxx
State: DONE | BLOCKED | IN_PROGRESS | DECISION | EXTERNAL
Start ref / end ref:
Changed files:
Contract decision:
Commands and exact results:
Unverified paths and reason:
External PR/release evidence:
Next exact action:
```

코드가 작성됐다는 이유만으로 `DONE` 처리하지 않는다. acceptance, 관련 matrix, 문서, release가 필요한 작업은 실제 증거까지 있어야 한다.

## 1. 2026-08-30 기준선

### 1.1 저장소와 배포 상태

- GitHub Release [`v0.3.2`](https://github.com/nestarc/api-keys/releases/tag/v0.3.2)는 게시 완료됐다.
- npm `latest`는 `@nestarc/api-keys@0.3.2`이며 2026-08-30T04:50:07.525Z에 게시됐다.
- release, npm `gitHead`, `origin/main`은 `a24fe1d`를 가리킨다.
- 조사 checkout의 commit은 topic commit `972a0e9`지만 tree는 공개 `origin/main`과 byte-identical하다.
- PR #22의 Nest 11/Prisma 7 호환성 변경은 merge·release·npm publish까지 완료됐다.
- 2026-08-30 조회 당시 source CI의 Node 20/22와 Prisma 5/6/7 checks가 성공했다. release는 Prisma matrix를 Node 22에서, publish job의 lint/test/build를 Node 24에서 통과했다.

현재 checkout에는 조사 전부터 다음 사용자 변경이 있다.

```text
M  docs/prisma-peer-compatibility-plan-2026-08-23.md
?? .DS_Store
?? src/.DS_Store
?? test/.DS_Store
```

이 파일들은 이번 계획의 정리 대상이 아니며 삭제·복원·stage하지 않는다.

### 1.2 fresh 로컬 검증

조사 환경 Node `24.11.1`에서 실행했다.

| 검증 | 결과 |
| --- | --- |
| `npm test -- --runInBand` | 11 suites, 81 tests PASS |
| `npm run lint` | PASS |
| `tsc --noEmit -p tsconfig.build.json` | PASS |
| fresh Jest coverage | statements 84.02%, branches 77.61%, functions 81.94%, lines 83.53% |
| `npm audit --omit=dev --json` | production 0 |
| `npm audit --json` | 7 total: high 2, moderate 4, low 1; 모두 dev/test tree |

일반 Jest coverage에서는 실DB 전용 `prisma-storage.ts`가 0%다. 이는 Prisma adapter가 미검증이라는 뜻이 아니라 unit coverage와 별개인 Prisma 5/6/7 PostgreSQL lane에서 검증된다는 뜻이다. 향후 coverage gate는 두 증거를 혼동하지 않는다.

### 1.3 지원 선언과 실제 증거

| 축 | 공개 선언 | 현재 자동 증거 | 남은 결정 |
| --- | --- | --- | --- |
| Node | `^22.13.0 || ^24.0.0` | source exact Node 22.13.0/Node 24, DB·consumer Node 22.13.0, publish Node 24 | Node 26 등 새 major는 명시적 matrix 검증 뒤 추가 |
| NestJS | 10/11 | Nest 11.2.3 full source suite+strict/HTTP, Nest 10.4.20 strict/HTTP | Nest 12는 `AK-M23` evidence 뒤 결정 |
| Prisma | 5/6/7 optional | 각 major PostgreSQL 16 contract, 6/7 대표 strict consumers, no-Prisma root consumer | 결합 변경/실패 때만 targeted off-diagonal 추가 |
| PostgreSQL | 14+ | Prisma 5 + PostgreSQL 14 boundary, Prisma 5/6/7 + PostgreSQL 16 current | 새 하한/상한은 real DB evidence 뒤 변경 |
| module format | CommonJS `main/types` | 현재 tarball consumer | ESM/`exports` 도입 여부는 P3 ADR |

Node 20의 EOL 상태는 [Node.js 공식 release 표](https://nodejs.org/en/about/previous-releases)를 기준으로 한다.

### 1.4 완료된 작업 — 다시 구현하지 않음

- v0.1 발급/검증, SHA-256+pepper, scope, Guard, InMemory/Prisma storage
- v0.2 key rotation, lifecycle hook, TTL policy, request context
- v0.3 IP allowlist, verification metric, RBAC compatibility, benchmark, `createTestKey()` testing helper
- v0.3.1 Prisma 5/6 PostgreSQL contract와 strict tarball consumer
- v0.3.2 Nest 11/Prisma 7 PostgreSQL contract, strict consumer, schema/config examples
- Prisma 5/6/7 CI/release matrix와 npm trusted publishing/provenance
- `AK-M08A/B/C`의 Actions/Jest/Prettier/ts-jest 순차 갱신, Nest 11.2.3 dev trio,
  ESLint 10/typescript-eslint 8 flat-config toolchain
- `AK-M10`의 PostgreSQL 14/16 + Prisma 5/6/7 matrix, no-Prisma packed root consumer,
  대표 diagonal compatibility evidence policy
- tenancy `TEN-M21`은 `DONE`이며 다시 열지 않는다. 역사적 published-only full-flow는 tenancy 0.15.0, API Keys 0.3.2, RBAC 0.2.1, Nest 11.2.1, Prisma 7.10.0 tuple과 legacy lane을 검증했다.
- 이후 published `@nestarc/tenancy@0.16.0`의 별도 modern lane은 API Keys 0.3.2, RBAC 0.2.1, Outbox 0.2.1, Jobs 0.3.1, Webhook 0.13.1, Nest 11.2.1, Prisma 7.10.0을 registry lock/integrity와 함께 다시 검증했고 legacy/modern 실경로가 각각 3/3 통과했다.
- 이후 API Keys/RBAC patch의 published-only 재검증은 새 tenancy 외부 작업 `TEN-ECO-NEXT`가 소유한다. `TEN-M21`을 재개하거나 API Keys 작업의 `DONE`을 이 사후 검증에 종속시키지 않는다.

완료된 현대화 작업을 새 task로 만들지 않는다. 이 문서의 matrix 작업은 이미 있는 lane을 보존하면서 증거 깊이와 지원 정책을 맞추는 일이다.

## 2. 실행 큐

| 순서 | ID | 우선순위 | 상태 | 크기 | 선행 | 작업 |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `AK-M01` | P0 | `DONE` | L | 없음 | secret-first lifecycle 판정과 Nest 기본 HTTP 401/403 계약 복구 |
| 2 | `AK-M02` | P0 | `DONE` | L | 없음 | concurrent rotation을 exactly-once CAS로 변경 |
| 3 | `AK-M03` | P1 | `DONE` | M | 없음 | 시간/TTL/grace 입력과 손상 record fail-closed |
| 4 | `AK-M04` | P1 | `DONE` | M | 없음 | namespace·environment·scope·parser·redaction round-trip 계약 |
| 5 | `AK-M05` | P1 | `DONE` | M | 없음 | observer/contextWriter 경계와 인증 context whole-object 불변성 |
| 6A | `AK-M06A` | P1 | `DONE` | S | 없음 | tenant ID producer canonicalization ADR |
| 6B | `AK-M06B` | P1 | `BLOCKED` | M | `AK-M06A`, `RBAC-M01`+`RBAC-M02` 포함 published RBAC | tenant ID producer 계약 구현과 packed RBAC consumer |
| 6C | `AK-M06C` | P1 | `DONE` | M | `AK-M02`, `AK-M06A` | tenant-bound revoke/rotate 안전 API 또는 management ownership 결정 |
| 7A | `AK-M07A` | P1 | `DONE` | M | `AK-M01` | credential verification과 Guard authorization telemetry 분리 |
| 7B | `AK-M07B` | P1 | `DONE` | M | `AK-M01` | Guard 밖 IP allowlist의 request-aware 계약 결정·구현 |
| 7C | `AK-M14` | P1 | `DONE` | S | `AK-M07A` | legacy `onAuthFailed` observer failure 격리 |
| 8A | `AK-M08A` | P1 | `DONE` | S | 없음 | green dependency PR을 순차 재검증·merge |
| 8B | `AK-M08B` | P1 | `DONE` | M | `AK-M08A` | Nest trio를 11.2.x default dev baseline으로 이동 |
| 8C | `AK-M08C` | P1 | `DONE` | M | `AK-M08A` | ESLint 10/typescript-eslint 8 toolchain 정렬 |
| 9 | `AK-M09` | P1 | `DONE` | M | `AK-M08B`, `AK-M08C` | Node 22/24 지원 계약으로 정렬 |
| 10 | `AK-M10` | P1 | `DONE` | L | `AK-M09` | Nest/Prisma/PostgreSQL/no-Prisma compatibility 증거 정책 고정 |
| 11 | `AK-M11` | P1 | `DONE` | S | `AK-M08A`, `AK-M08C` | coverage floor와 CI evidence |
| 12 | `AK-M15` | P2 | `DECISION` | S | 없음 | list의 active/expired/grace semantics 정렬 |
| 13 | `AK-M12` | P2 | `DONE` | M | 없음; filter 의미 비변경 | public list DTO에서 verifier material 제거 |
| 14 | `AK-M13` | P2 | `READY` | S | `AK-M04` | raw key environment와 stored environment bind |
| 15 | `AK-M16` | P2 | `BLOCKED` | S | `AK-M05` | InMemory storage record Date defensive copy |
| 16A | `AK-M17A` | P2 | `DECISION` | S | 없음 | `SECURITY.md`와 지원 release policy |
| 16B | `AK-M17B` | P2 | `EXTERNAL` | S | `AK-M17A` | GitHub reporting/security/ruleset 설정 |
| 17 | `AK-M18` | P2 | `READY` | M | `AK-M08A`, `AK-M09` | release ancestry와 pack-once provenance |
| 18 | `AK-M19` | P2 | `BLOCKED` | M | `AK-M08A`, `AK-M08B`, `AK-M08C`, `AK-M18` | CI/release/Dependabot 구조 정리 |
| 19A | `AK-M20A` | P2 | `READY` | S | `AK-M09`, `AK-M10` | 문서 권위와 현재 지원표 정렬 |
| 19B | `AK-M20B` | P2 | `READY` | M | `AK-M02` | reusable storage contract의 public package 계약 |
| 20 | `AK-M21` | P3 | `DECISION` | M | `AK-M10` | `exports`/ESM packaging ADR |
| 21 | `AK-M22` | P3 | `READY` | S | `AK-M02` | collision retry terminal error 계약 |
| 22 | `AK-M23` | P3 | `READY` | S | `AK-M10` | Nest 12 stable strict-consumer 호환성 스파이크 |

P0는 `AK-M01`과 `AK-M02`를 서로 다른 PR로 진행한다. 어느 하나의 완료가 다른 하나를 대체하지 않는다.

### 2.1 파일과 정확한 첫 행동

| ID | 주 파일 | 새 세션의 정확한 첫 행동 |
| --- | --- | --- |
| `AK-M01` | service verify, hasher, `src/errors.ts`, guard, 새 HTTP E2E | known revoked/expired prefix에 잘못된 secret을 붙였을 때 상태가 노출되는 test와 기본 Nest pipeline 500 test를 먼저 추가한다. |
| `AK-M02` | service, storage interface, InMemory/Prisma adapters | 같은 old key를 barrier로 동시에 rotate해 성공 replacement가 둘 이상 생기는 deterministic contract test를 추가한다. |
| `AK-M03` | service 시간 계산과 storage contract | `Invalid Date`, `NaN`, `Infinity`, 음수 duration 표를 만들고 mutation 전 거부/verify fail-closed 기대를 테스트한다. |
| `AK-M04` | module, service input, key-format, scope, README | namespace/environment/scope runtime 입력 표와 발급→parse→verify→redact round-trip failing test를 먼저 만든다. |
| `AK-M05` | service lifecycle/metric emit, context, guard/contextWriter | event sink와 contextWriter가 payload/object를 변경해 downstream `request.apiKey` tenant/scopes가 바뀌는 failing test를 추가한다. |
| `AK-M06A` | types/docs ADR | 현재 저장된 tenant ID 형태와 RBAC 소비 계약을 목록화하고 reject/trim/preserve 정책을 ADR로 결정한다. |
| `AK-M06B` | types, service create/list, packed RBAC consumer | `RBAC-M01`과 `RBAC-M02`를 포함한 published version을 확인한 뒤 ADR의 첫 invalid tenant case를 RED test로 만든다. |
| `AK-M06C` | service revoke/rotate, storage lookup, docs | tenant B caller가 tenant A의 ID를 알고 있는 위협 모델을 쓰고 safe expected-tenant API와 management-layer ownership 중 하나를 ADR로 선택한다. |
| `AK-M07A` | service verify, guard, event/metric types | missing header와 IP/scope/environment 거절의 현재 lastUsed/event/metric 결과를 contract table로 고정한다. |
| `AK-M07B` | service request-aware verification, guard, docs | IP 제한 key를 Guard 밖 `verify()`로 IP 없이 성공시키는 test를 만들고 credential-only vs request-aware API 정책을 결정한다. |
| `AK-M14` | `reportAuthFailed()`와 hook tests | observer의 sync throw/async reject에도 원래 `ApiKeyError`가 유지되는 test를 추가한다. |
| `AK-M08A` | PR #16/#17/#20, lockfile | 각 PR의 base/check/diff를 다시 조회하고 #16 → #17 → #20 순서로 재베이스 필요성을 판단한다. |
| `AK-M08B` | Nest trio, tests, lockfile | 실패한 단독 `@nestjs/common` PR #18을 그대로 쓰지 말고 common/core/testing exact-compatible 묶음의 clean install을 만든다. |
| `AK-M08C` | ESLint config/deps | 실패한 #19/#21을 통합 대체할 flat config + ESLint10 + typescript-eslint8 branch를 만든다. |
| `AK-M09` | engines, CI/release, README, types | Node 22 최소 lane에서 A/B/C 프로필을 먼저 실행하고 지원 하한 변경 ADR을 남긴다. |
| `AK-M10` | CI matrix, DB/consumer scripts, README | Nest 10/11, Prisma 5/6/7, PostgreSQL 14/16, Prisma 미설치 선언/증거 표를 만들고 최소 지속 lane을 선택한다. |
| `AK-M11` | Jest config/workflow | fresh full coverage와 실DB adapter gate의 책임을 분리한 threshold 제안을 먼저 기록한다. |
| `AK-M15` | storage list options, service, README | expired/rotated/revoked key의 현재 default list 결과를 표로 만들고 제품 계약을 선택한다. |
| `AK-M12` | types, `list()`, docs | 현재 `JSON.stringify(await list())`에 verifier field가 포함되는 regression test를 추가하고 기존 filter 의미는 바꾸지 않는다. |
| `AK-M13` | `key-format.ts`, verify | raw key의 environment segment만 바뀐 credential을 거부하는 failing test를 추가한다. |
| `AK-M16` | InMemory clone/storage contract | 반환 record의 Date를 mutate해 저장 상태가 변하는 failing test를 추가한다. |
| `AK-M17A` | `SECURITY.md` | 비공개 신고 채널과 지원 release line을 관리자와 확정하고 문서 초안을 만든다. |
| `AK-M17B` | GitHub settings | `AK-M17A`의 정책을 기준으로 현재 reporting/security/ruleset 값을 관리자 권한에서 기록한다. |
| `AK-M18` | release workflow, package script | tag commit이 main 밖인 fixture와 verified tarball을 재빌드하는 현재 graph를 테스트로 표현한다. |
| `AK-M19` | workflows, Dependabot config | CI/release job과 dependency group의 현재/목표 graph를 표로 만든다. |
| `AK-M20A` | README, PRD/spec, compatibility plan | package metadata·release와 모순되는 문장을 목록화하되 기존 dirty 문서는 수정하지 않는다. |
| `AK-M20B` | testing/storage contract, package exports/files, README | README의 reusable contract claim과 실제 tarball export 부재를 failing packed-consumer test로 고정한다. |
| `AK-M21` | package exports/build/consumer | 공개 deep import 사용처와 CJS/ESM 소비자를 조사한 ADR만 먼저 작성한다. |
| `AK-M22` | create/rotate retry errors | `AK-M02`의 새 rotation protocol 위에서 항상 duplicate를 반환하는 adapter의 마지막 retry error를 stable-contract test로 고정한다. |
| `AK-M23` | peer metadata, packed consumer | `AK-M10`의 증거 정책 위에서 Nest 12.0.1 exact strict consumer를 실행해 첫 install/type/runtime 실패를 기록한다. |

## 3. P0 작업 명세

### `AK-M01` — secret-first 인증 판정과 Nest HTTP 오류 계약 복구

- 상태: `P0 / DONE`
- 문제 1: `verify()`는 known prefix record의 secret을 인증하기 전에 revoked/expired를 반환한다. 공개 prefix에 임의 secret을 붙여도 record 존재와 lifecycle 상태를 구분할 수 있고 이 분기는 hash 비교를 생략한다.
- 문제 2: `ApiKeyError`는 plain `Error`에 `httpStatus`만 보유한다. Nest 10/11의 기본 exception filter는 이를 HTTP exception으로 인식하지 않아 Guard 오류를 500으로 응답한다.
- 영향: 인증되지 않은 상태 oracle과 failure-work 차이가 생기며, 문서상 401/403 계약도 깨져 정상 인증 실패가 5xx 경보, error stack log, 재시도를 유발한다.

완료 조건:

- [x] known prefix라도 secret 검증 전에는 revoked/expired/pepper 상태를 공개하지 않는다.
- [x] 잘못된 secret을 가진 active/revoked/expired key는 모두 stable `api_key_invalid`이며, 유효 secret을 제시한 holder만 revoked/expired를 구분한다.
- [x] unknown-prefix dummy path와 known-prefix invalid-secret path가 의도한 hash/compare work를 수행한다. deterministic call-path test와 bounded timing benchmark를 함께 두되 wall-clock 완전 동일성은 주장하지 않는다.
- [x] 기본 Nest HTTP pipeline에서 missing/malformed/invalid/revoked/expired는 401이다.
- [x] environment/scope/IP 거절은 403이다.
- [x] response body에 안정된 public `code`가 있고 reason, raw key, hash, pepper, stack은 노출하지 않는다.
- [x] direct service 사용자는 계속 `instanceof ApiKeyError`와 `error.code`를 사용할 수 있다.
- [x] Nest 10과 11 실제 application E2E가 custom filter 없이 통과한다.
- [x] 기존 `httpStatus` 호환을 유지할지 deprecate할지 명시한다.

검증: 프로필 A/B, 새 Nest 10/11 HTTP consumer, wrong-secret/known-prefix lifecycle table, hasher work-path test, bounded timing benchmark.

비범위: 관리 API의 `ApiKeyOperationError` HTTP 매핑, 애플리케이션 전역 error body 표준화.

완료 결정(2026-08-30): known record도 hash/compare가 성공한 뒤 lifecycle을 판정한다. unknown
prefix의 dummy path도 SHA-256 뒤 fixed-length `timingSafeEqual` compare를 실행한다. `ApiKeyError`는
Nest `HttpException`을 상속하며 public body를 `{ statusCode, code }`로 제한한다. 기존
`httpStatus`는 이번 release에서 deprecate하지 않고 호환 유지하며 새 Nest 코드는
`getStatus()`도 사용할 수 있다. exact Nest 10.4.20/11.2.1 packed HTTP consumer를 CI와 release
publish 선행 gate에 추가했다.

### `AK-M02` — concurrent rotation exactly-once CAS

- 상태: `P0 / DONE`
- 문제: service의 active/replaced precheck와 storage mutation이 분리돼 있다. 같은 old key의 동시 회전이 둘 이상 성공하면 여러 replacement credential이 유효하지만 lineage는 마지막 하나만 가리킬 수 있다.

완료 조건:

- [x] storage rotation contract가 old record의 active/unreplaced 조건을 mutation과 같은 원자 경계에서 확인한다.
- [x] 동시 N회 중 정확히 한 번만 성공하고 나머지는 stable `NotRotatable` 결과다.
- [x] 성공 replacement 하나만 저장·유효·linked된다.
- [x] Prisma adapter는 실제 PostgreSQL transaction/CAS를 사용한다.
- [x] atomic rotation을 구현할 수 없는 custom adapter 경로는 조용히 two-step fallback하지 않고 fail-fast 또는 명시 capability로 처리한다.
- [x] InMemory와 Prisma가 같은 contract suite를 통과한다.
- [x] custom storage implementor migration note와 semver 결정을 남긴다.

검증: 프로필 A/B, storage contract, real PostgreSQL barrier concurrency test, Prisma 5/6/7 lanes.

비범위: distributed lock service, rotation UI, 다른 프로세스의 secret 전달 workflow.

완료 결정(2026-08-30): `ApiKeyStorage.rotate()`는 old record가 `input.rotatedAt` 시점에
unrevoked/unrotated/unreplaced/unexpired인지 replacement insert와 같은 원자 경계에서 확인하고
`'rotated' | 'not_rotatable'`을 반환한다. service의 선조회는 `NotFound`와 빠른 거절을 위한
것일 뿐 성공 권한은 storage CAS 결과만 가진다. InMemory adapter는 await 없는 단일 mutation
구간에서 검사·연결·insert를 수행하고, Prisma adapter는 interactive transaction 안에서 조건부
`updateMany`로 old record를 claim한 뒤 replacement를 create한다. create 실패 시 claim도 rollback된다.
구형 `Promise<void>` custom adapter는 성공으로 간주하지 않고 fail-fast한다. 공개 storage interface의
breaking change이므로 pre-1.0 minor `0.4.0`으로 배포하며 `0.3.x` patch에는 게시하지 않는다.

## 4. P1 작업 명세

### `AK-M03` — 시간 값 fail-closed validation

- 상태: `P1 / DONE`
- 범위: `expiresAt`, `gracePeriodMs`, default/max TTL, debounce 및 storage에서 읽은 expiry.

완료 조건:

- [x] `Invalid Date`, `NaN`, `±Infinity`, 허용하지 않는 음수 duration을 storage mutation 전에 stable error로 거부한다.
- [x] 손상된 persisted expiry는 verify/rotate에서 무기한 유효로 해석하지 않고 fail closed한다.
- [x] 과거 expiry, `null`, zero grace의 현재 의미를 테스트와 문서로 고정한다.
- [x] TTL policy 계산에 overflow가 생기면 거부한다.
- [x] valid input의 기존 create/rotate 결과는 유지된다.

검증: 프로필 A/B, service 입력은 InMemory/Prisma-before-mutation spy table, 손상 persisted record는 fake/custom storage fail-closed table, 유효 값만 real PostgreSQL lane. Prisma DateTime으로 표현할 수 없는 `Invalid Date` row를 억지로 seed하지 않는다.

비범위: timezone UI, cron cleanup, 유효한 legacy Date migration.

완료 결정(2026-08-30): public `ApiKeyOperationErrorCode.InvalidTime`을
`api_key_invalid_time`으로 추가했다. `expiresAt`은 유효한 `Date`, duration 입력은 유한한
0 이상의 millisecond여야 하며 default/max/grace Date 산술이 JavaScript Date 범위를 넘으면
storage mutation 전에 같은 code로 거부한다. 과거 expiry는 즉시 만료, persisted/explicit
replacement `null`은 non-expiring, zero grace는 rotation 시각 즉시 old-key 만료 의미를 유지한다.
secret이 일치한 뒤 custom storage의 손상된 non-null expiry를 발견하면 verify는
`api_key_invalid`, rotate는 `api_key_not_rotatable`로 fail closed한다.

### `AK-M04` — namespace·runtime input·key format·redaction 계약

- 상태: `P1 / DONE`
- 문제: namespace를 검증하지 않아 일부 키는 발급 직후 parse할 수 없거나 공식 redaction regex가 secret을 가리지 못한다. untyped/JavaScript caller의 invalid environment나 scope도 storage mutation 전 runtime에서 거부되지 않는다.

완료 조건:

- [x] 허용 charset과 길이를 public contract로 정의한다.
- [x] module, direct service, `generateKey()`가 같은 중앙 validator를 사용한다.
- [x] runtime environment는 정확히 `live|test`, scope level은 `read|write`이며 resource의 empty/delimiter/길이 정책을 중앙 validator로 적용한다.
- [x] invalid environment/scope는 key 생성과 storage mutation 전에 stable input error로 거부한다.
- [x] 발급 가능한 모든 key는 parse → verify → redact round-trip을 만족한다.
- [x] empty, underscore 포함, redaction에 안전하지 않은 namespace는 key 발급 전에 거부된다.
- [x] parser가 prefix/secret base62 문법도 검증한다.
- [x] 기존 punctuation namespace 사용자의 호환/마이그레이션 전략을 CHANGELOG에 기록한다.

검증: 프로필 A/B/D, JavaScript/untyped runtime input table, generated-key property/table tests, logger serialization test.

비범위: 새로운 versioned key format, namespace 자동 변환.

완료 결정(2026-08-30): namespace는 ASCII 영숫자 1–32자이며 module 설정, direct service
constructor, `generateKey()`가 같은 중앙 validator로 fail fast한다. environment는 정확히
`live|test`, scope resource는 ASCII 영숫자로 시작하는 1–128자의 영숫자/`.`/`_`/`/`/`-`,
level은 정확히 `read|write`로 고정했다. 잘못된 발급 입력은 random key 생성과 InMemory/Prisma
storage mutation 전에 public `ApiKeyOperationError`의 `api_key_invalid_input`으로 거부한다.
parser는 namespace/environment와 12/32자 base62 prefix/secret까지 검사하되 외부 credential
실패 code는 `api_key_malformed`를 유지한다. 허용된 경계 namespace와 live/test 발급 key는
parse → verify → JSON logger redaction round-trip table을 통과한다. 기존 punctuation/장문
namespace는 자동 변환하지 않으며 0.4.0 전에 기존 버전으로 credential을 재발급하는 migration을
CHANGELOG에 기록했다.

### `AK-M05` — observer payload와 인증 context whole-object 불변성

- 상태: `P1 / DONE`
- 문제: usage event와 반환 `ApiKeyContext`가 mutable scopes 배열을 공유할 수 있다. Guard는 같은 context object를 `request.apiKey`에 저장한 뒤 `contextWriter`에 넘기므로 writer가 tenant/key/scopes를 바꾸면 downstream RBAC/RLS가 변조된 identity를 읽을 수 있다.

완료 조건:

- [x] event, metric, 반환 context 사이에 mutable nested collection/Date alias가 없다.
- [x] sync/async sink가 payload를 변경해도 반환 context와 Guard 판단이 바뀌지 않는다.
- [x] `contextWriter`에 전달한 object를 변경하거나 교체해도 이미 인증된 `request.apiKey`의 tenantId/keyId/environment/scopes/IP policy가 바뀌지 않는다.
- [x] downstream RBAC/RLS fixture가 contextWriter 이후에도 verified identity를 읽는다.
- [x] public type을 `readonly`로 강화할지 runtime defensive copy만 할지 호환성을 기록한다.
- [x] 모든 event type의 nested collection을 같은 기준으로 검토한다.

검증: 프로필 A/B, malicious/buggy observer와 contextWriter mutation tests, Guard privileged-scope 및 cross-tenant downstream negative tests.

비범위: callback sandboxing, 범용 deep-freeze library, storage adapter record Date cloning(`AK-M16` 소유).

완료 결정(2026-08-30): public `ApiKeyContext`/event/metric type은 기존 TypeScript 소비자의
source compatibility를 위해 mutable로 유지하고 runtime defensive copy를 적용한다. verification
context의 scopes/IP 배열, 모든 lifecycle event의 `at`, created/used/rotated scopes, rotated grace
deadline과 metric object는 sink·error reporter 경계마다 분리한다. Guard는 검증 context와 별도인
copy를 `contextWriter`에 넘기고 writer 완료 뒤 untouched verified identity에서 `request.apiKey`를
복원한다. writer가 전달 object 또는 request property를 sync/async로 변경해도 tenant/key/environment,
privileged scope, prefix, IP policy가 downstream 실제 RBAC resolver에 전파되지 않는다. runtime
deep-freeze와 storage adapter record Date ownership은 각각 비범위와 `AK-M16`에 남긴다.

### `AK-M06A` — tenant ID producer ADR

- 상태: `P1 / DONE`
- 문제: `create()`는 tenant ID를 검증/정규화하지 않고 저장한다. RBAC의 legacy path에는 trim/coerce 동작이 있어 producer와 consumer identity가 달라질 수 있다.

완료 조건:

- [x] tenant ID의 empty/whitespace/runtime type/길이 정책을 reject/trim/preserve 중 명시적으로 선택한다.
- [x] API Keys가 canonical `request.apiKey` producer를 소유하고 RBAC가 trusted tenant reconciliation/authorization을 소유하는 경계를 고정한다.
- [x] 기존 non-canonical record의 reject/preserve/migration 정책과 semver를 기록한다.
- [x] 구현 파일은 바꾸지 않고 ADR·입력/legacy 표·`AK-M06B` migration checklist만 만든다.

검증: 현재 record/consumer inventory, `RBAC-M01`/`RBAC-M02` 계약 대조, 문서 link check.

완료 결정(2026-08-30): [`2026-08-30-tenant-identity-contract-adr.md`](./2026-08-30-tenant-identity-contract-adr.md)에서
tenant ID를 trim/coerce/Unicode normalize하지 않는 1–255 UTF-16 code unit opaque exact string으로
고정했다. empty, non-string, leading/trailing whitespace, 초과 길이는 reject한다. API Keys는
검증된 `request.apiKey` producer를, RBAC는 trusted tenant reconciliation과 authorization을 소유한다.
기존 non-canonical row는 runtime repair하지 않고 coordinated migration 또는 credential 재발급한다.
ADR 작성·inventory·migration checklist를 먼저 끝낸 뒤 별도 구현 단계인 `AK-M06B/C`를 진행했다.

### `AK-M06B` — tenant ID producer 계약 구현

- 상태: `P1 / BLOCKED (RBAC-M01과 RBAC-M02를 모두 포함한 published RBAC version)`;
  API Keys producer 구현과 RED packed consumer는 완료했지만 외부 registry artifact가 없다.

완료 조건:

- [x] create, list, event, context, storage가 `AK-M06A`의 canonical value를 사용한다.
- [x] invalid/non-canonical input은 storage mutation 전에 stable error로 처리한다.
- [ ] published RBAC를 설치한 packed API Keys candidate consumer에서 canonical source와 trusted tenant mismatch가 fail closed한다.
- [x] candidate tarball의 version/source/integrity와 RBAC registry artifact를 검사하며 sibling checkout을 암묵적으로 사용하지 않는다.
- [ ] 이 packed consumer를 CI/release의 지속 gate로 추가한다.
- [ ] API Keys task의 `DONE`은 packed pre-publish evidence로 판단한다. published-only full ecosystem 사후 검증은 `TEN-ECO-NEXT`가 소유한다.

검증: 프로필 A/B/D, packed API Keys→published RBAC consumer. `TEN-ECO-NEXT` 결과는 링크하되 완료 선행으로 삼지 않는다.

비범위: tenant membership 확인, tenancy package 직접 의존, 데이터 migration 실행기.

부분 진행 결정(2026-08-30): `create()`와 `list()`는 storage 접근 전에 exact tenant를 검증하고,
verify/list/rotate/revoke는 custom storage의 non-canonical record를 repair하지 않고 fail closed한다.
`scripts/test-rbac-consumer.js`는 candidate tarball SHA-512와 registry RBAC version/gitHead/tarball/
integrity를 검사한 뒤 Guard writer, canonical/legacy conflict, no-trim/coerce, trusted tenant mismatch를
실행한다. npm latest `@nestarc/rbac@0.2.1` (`gitHead 69bf0e1`, integrity
`sha512-9dqvRNC7sI3IKO/gUf6pRKbK4MSVvKXs0YgahYDsJkHZvhTMflYzaS5H9CnzViLMWuHV6eVmsXkWY8J52PVJ1w==`)
는 conflicting `request.apiKeyContext`를 resolve해 예상대로 RED다. 이 버전의 gate를 CI/release에
넣으면 main과 release가 항상 실패하므로, `RBAC-M01/M02` 포함 exact published version이 생길 때까지
workflow 연결과 `DONE`을 보류한다.

### `AK-M06C` — tenant-bound management mutation 계약

- 상태: `P1 / DONE`
- 문제: `list(tenantId)`는 이미 tenant-bound지만 public `revoke(id)`와 `rotate(id)`는 expected tenant를 받지 않아 library가 caller tenant와 record tenant의 일치를 강제할 수 없다.

완료 조건:

- [x] service가 tenant boundary를 강제할지 trusted management layer가 소유할지 threat model과 public contract로 결정한다.
- [x] library가 소유하면 additive expected-tenant revoke/rotate API를 만들고 tenant B가 tenant A key를 mutation하지 못하는 InMemory/Prisma test를 둔다.
- [x] application이 소유하면 ID-only API의 신뢰 경계, 안전한 lookup/mutation recipe와 misuse warning을 문서화하고 deprecation 필요성을 결정한다.
- [x] `AK-M02`의 atomic rotation protocol을 우회하는 tenant check-then-rotate two-step을 만들지 않는다.

검증: ADR, tenant A/B mutation table, 선택 시 packed management consumer.

완료 결정(2026-08-30): library-owned additive `revokeForTenant(tenantId, id)`와
`rotateForTenant(tenantId, id, input)`를 제공한다. missing과 mismatch는 모두
`api_key_record_not_found`다. built-in InMemory/Prisma adapter는 expected tenant를 revoke
`updateMany`와 rotation transaction/CAS 조건에 포함한다. custom adapter capability가 없으면
ID-only mutation으로 fallback하지 않고 fail fast한다. 기존 `revoke(id)`/`rotate(id)`는 trusted
system-wide management 호환 경로로 유지하고 deprecate하지 않지만 tenant authorization을 보장하지
않음을 README에 명시했다. Nest 10/11 packed consumers가 cross-tenant revoke 거절과 tenant-bound
rotate/revoke 성공을 runtime으로 검증한다.

### `AK-M07A` — verification과 authorization telemetry 의미 분리

- 상태: `P1 / DONE`
- 문제: service verify 성공 뒤 Guard의 environment/IP/scope 거절이 발생해도 `lastUsedAt`, optional `api_key.used`, success metric이 이미 기록된다.

완료 조건:

- [x] credential verification 성공과 요청 authorization 성공을 서로 다른 용어와 event/metric으로 정의한다.
- [x] Guard 403을 성공 사용으로 기록할지, 별도 denial로 기록할지 ADR로 결정한다.
- [x] missing Authorization header처럼 service 호출 전 실패하는 요청의 `auth_failed` event/metric 의미도 결정한다.
- [x] 선택한 의미가 last-used, usage event, auth-failed event, metrics에 일관된다.
- [x] service-only/custom transport 사용자를 깨뜨리지 않는 API를 제공한다.
- [x] denial payload에는 raw key, IP, tenant/key high-cardinality 값이 기본 포함되지 않는다.

검증: missing/environment/IP/scope Guard table, service-only verify tests, event/metric cardinality test.

비범위: durable audit sink, application rate limiting.

완료 결정(2026-08-30): [`request authorization telemetry ADR`](./2026-08-30-request-authorization-telemetry-adr.md)에
따라 `verify()`는 credential-only 호환 primitive로 유지하고 direct 호출 성공은 기존처럼 accepted
use로 기록한다. 새 `authorizeRequest()`와 Guard는 credential verification 뒤 environment/IP/scope
authorization까지 성공해야 `lastUsedAt`과 opt-in `api_key.used`를 기록한다. missing은 credential
attempt가 아니므로 `api_key.auth_failed`/verification metric을 만들지 않고, credential failure는 기존
auth-failed/verification 의미를 유지한다. request denial은 key/tenant/raw key/IP를 제외한
`api_key.authorization_denied`와 별도 저카디널리티 `api_key.authorization` metric으로 기록한다.

### `AK-M07B` — Guard 밖 IP allowlist 계약

- 상태: `P1 / DONE`
- 문제: public `verify(rawKey)`는 record의 IP 제한을 반환할 뿐 enforcement하지 않고 Guard만 IP를 검사한다. custom transport/direct-service consumer가 advertised restriction을 자동 적용한다고 오해할 수 있다.

완료 조건:

- [x] `verify()`를 credential-only primitive로 명명/문서화할지, request-aware 검증 API를 additive로 제공할지 ADR로 결정한다.
- [x] 제한 key를 request-aware path에서 IP 없이 검증하면 fail closed한다.
- [x] Guard와 custom transport recipe가 같은 request-aware primitive/policy를 사용한다.
- [x] 기존 direct-service 사용자의 compatibility와 semver를 기록하고 IP enforcement 보증 범위를 README/spec에 명시한다.

검증: HTTP/custom-transport/IP resolver table, packed direct-service consumer.

비범위: trusted proxy 자동 설정, application rate limiting.

완료 결정(2026-08-30): additive `authorizeRequest({ rawKey, clientIp | request,
clientIpResolver, requiredEnvironment, requiredScope })`를 공개하고 Guard가 같은 primitive를 사용한다.
제한 key는 explicit/resolved client IP가 없거나 allowlist 밖이면 `api_key_ip_not_allowed`로 fail
closed한다. `verify()`는 stored IP/environment/scope policy를 반환하지만 집행하지 않는 credential-only
API로 유지한다. Nest 10/11 strict packed direct consumers가 제한 key의 direct `verify()` 성공,
request-aware missing-IP 거절, 허용 IP 성공과 public declaration을 검증했다.

### `AK-M14` — legacy observer failure isolation

- 상태: `P1 / DONE`

완료 조건:

- [x] `onAuthFailed`의 sync throw/thenable/async reject가 원래 인증 오류를 바꾸지 않는다.
- [x] observer 실패 뒤에도 `AK-M07A`가 정한 `auth_failed` event와 verification metric 의미가 유지된다.
- [x] reporting callback 자체의 실패도 격리된다.
- [x] unhandled rejection이 없고 legacy hook deprecation 여부를 문서화한다.

검증: sync/async observer table, unhandled rejection check, `AK-M01` HTTP error regression.

완료 결정(2026-08-30): `onAuthFailed(prefix, code)`는 source compatibility를 위해 유지하되
structured `api_key.auth_failed` lifecycle event로 대체하도록 deprecate한다. 공통 observer 실행
경계가 sync throw와 표준 Promise뿐 아니라 `PromiseLike` thenable rejection도 즉시 관찰하며,
legacy hook 실패는 원래 `ApiKeyError`, auth-failed event, verification metric을 바꾸지 않는다.
event/verification/authorization metric observer의 error-reporting callback이 동기 예외 또는 async
rejection으로 다시 실패해도 격리해 API key operation이나 process unhandled rejection으로 전파하지
않는다.

### `AK-M08A/B/C` — dependency/toolchain 정리

2026-08-30 snapshot에서 production audit은 0이고 full audit은 dev tree 7건이다. PR 상태는 새 세션에서 반드시 다시 조회한다.

#### `AK-M08A` — green PR 순차 처리

- 상태: `P1 / DONE`

- PR #16 Actions, #17 Prettier/ts-jest lock, #20 Jest/@types major를 각각 최신 base에서 재검증한다.
- lockfile 충돌을 피하려고 #16 → #17 → #20 순으로 처리한다.
- 각 PR은 lint/test/typecheck/build/bench와 현재 Prisma/consumer matrix를 통과해야 한다.

완료 결정(2026-08-30): PR #16은 기존 base의 5개 Node/Prisma check 성공을 재확인하고
`306be401`로 squash merge했다. 이어 PR #17을 새 main으로 update-branch해 run
`33311083763`의 Node 20/22와 Prisma 5/6/7을 모두 통과시킨 뒤 `b3dbf139`로 merge했고,
PR #20도 다시 update-branch해 run `33311145802`의 같은 5개 check를 모두 통과시킨 뒤
`f00ce8f2`로 merge했다. 세 merge commit의 main push run도 각각 성공했다. 원격 세 커밋은
기존 로컬 유지보수 커밋을 보존하는 merge
`055daa5`로 통합했다. 로컬에서 이후 추가된 HTTP consumer job의 checkout/setup-node도
Actions v7로 맞춰 #16의 의도를 보존한다.

#### `AK-M08B` — Nest trio default baseline

- 상태: `P1 / DONE`

- 단독 `@nestjs/common` major PR #18은 사용하지 않는다.
- common/core/testing과 필요한 platform package를 호환되는 Nest 11.2.x 묶음으로 갱신한다.
- Nest 10 지원은 strict legacy consumer에서 계속 검증한다.
- 완료 뒤 Nest/file-type 관련 dev advisory를 재평가한다.

완료 결정(2026-08-30): dev baseline을 `@nestjs/common`, `@nestjs/core`,
`@nestjs/testing`의 호환되는 `~11.2.3` trio로 이동했다. source unit suite에는 HTTP platform이
필요하지 않아 platform package를 root에 추가하지 않았고, exact HTTP consumer가 각 Nest 10/11
platform package를 독립 설치한다. exact Nest 10.4.20 legacy와 Nest 11.2.3 modern strict/HTTP
consumer가 모두 통과했다. Nest 11.2.3이 가져오는 `file-type@21.3.4` 경로를 재확인했으며
production/full audit 모두 0이다.

#### `AK-M08C` — ESLint 10 toolchain

- 상태: `P1 / DONE`

- 실패 중인 #19/#21의 단독 업데이트를 대체한다.
- ESLint 10, parser/plugin, flat config의 실제 engine floor를 한 PR에서 정렬하고 그 결과를 `AK-M09`의 public Node 하한 입력으로 넘긴다. public Node 지원 정책 자체는 이 작업에서 결정하지 않는다.
- lint 의미 변경과 대량 formatting을 분리한다.

완료 결정(2026-08-30): legacy eslintrc/ignore를 `eslint.config.cjs` flat config로 대체하고
`eslint@10.9.1`, `@eslint/js@10.0.1`, typescript-eslint parser/plugin `8.68.0`,
`globals@17.11.0`을 하나의 lockfile로 정렬했다. 기존 recommended와 unused-argument ignore
의미를 유지했으며 source/test 대량 formatting은 하지 않았다. locked ESLint/@eslint/js engine
floor는 `^20.19.0 || ^22.13.0 || >=24`다. 이는 `AK-M09` 입력이며 공개 `engines.node >=20`은
이번 작업에서 바꾸지 않았다. bypass/force/override 없이 `npm ci`가 재현되고 전체 audit은 0이다.

공통 금지: `npm audit fix --force`, `--legacy-peer-deps`, `--force`, 근거 없는 permanent override.

### `AK-M09` — Node 22/24 지원 정책

- 상태: `P1 / DONE`
- 권장 방향: Node 20 EOL을 제거하고 `engines`, types, CI, release, consumer를 Node 22/24로 맞춘다.

완료 조건:

- [x] 정확한 최소 Node 22 patch를 실제 test/build/consumer로 결정한다.
- [x] `engines`, README, CI/release, `@types/node`, examples가 같은 하한을 가리킨다.
- [x] Node 20 제거의 semver와 migration note를 기록한다.
- [x] Node 24를 source test lane에도 포함한다.
- [x] Node 26 Current는 자동 지원 선언하지 않는다.

검증: 프로필 A/B/C/D를 Node 최소/24에서 실행.

완료 결정(2026-08-30): 정확한 최소 런타임은 ESLint 10의 Node 22 floor와 실제 clean
profile A/B/C/D가 모두 통과한 Node 22.13.0이다. 공개 engine은 미래 major를 자동 포함하지 않는
`^22.13.0 || ^24.0.0`이며 `@types/node` 하한도 `^22.13.0`으로 맞췄다. source CI는 exact
22.13.0과 24, Prisma/strict/HTTP consumer와 release 사전 검증은 exact 22.13.0, publish는 24를
사용한다. Node 20 제거는 planned pre-1.0 `0.4.0` breaking migration이며 지원 정책과 증거는
[`2026-08-30-node-support-policy-adr.md`](./2026-08-30-node-support-policy-adr.md)에 기록했다.

### `AK-M10` — Nest/Prisma/PostgreSQL/no-Prisma 지원 증거 정책

- 상태: `P1 / DONE`

완료 조건:

- [x] Nest 10/11 전체 suite 깊이와 Prisma 5/6/7 DB contract의 역할을 문서화한다.
- [x] Nest10+Prisma7, Nest11+Prisma6 off-diagonal을 직접 smoke할지 대표 diagonal 정책으로 둘지 명시한다.
- [x] 지원한다고 선언한 major 경계는 적어도 strict install/typecheck/runtime 또는 real DB lane의 증거가 있다.
- [x] 전체 Cartesian matrix를 근거 없이 늘리지 않는다.
- [x] optional Prisma 미설치 root consumer를 실제 packed strict install/typecheck/runtime lane으로 추가한다. 현재 Prisma를 설치하는 strict consumers를 이 증거로 세지 않는다.
- [x] PRD의 PostgreSQL 14+ 선언을 실제 PostgreSQL 14 boundary lane으로 검증하거나 지원 하한을 증거에 맞게 정정한다. PostgreSQL 16 lane은 보존한다.
- [x] Prisma 5/6/7 각각의 exact runtime root를 반복 설치·실행하는 script/CI command를 제공한다.

검증: 프로필 C/D, peer metadata assertion, PostgreSQL 14/16 DB evidence, no-Prisma packed consumer.

완료 결정(2026-08-30): compatibility 증거는 전체 Cartesian product가 아니라 통합 경계별
최소 지속 lane으로 관리한다. Nest 11.2.3은 full source suite와 strict/HTTP packed consumer,
Nest 10.4.20은 strict/HTTP packed boundary를 담당한다. Prisma 5.22.0/6.19.3/7.10.0은 각각
PostgreSQL 16 real DB contract를 수행하고, Prisma 5.22.0 + PostgreSQL 14가 DB 하한을 증명한다.
Nest 10 + Prisma 6과 Nest 11 + Prisma 7을 대표 diagonal로 유지하며 두 integration surface를
결합하는 변경이나 재현된 호환성 실패가 있을 때만 off-diagonal을 추가한다. 별도 Nest 11.2.3
packed root consumer는 `@prisma/client`가 dependency/lock/runtime resolution에 전혀 없는 상태에서
strict install, `skipLibCheck: false` typecheck, root import, in-memory create/verify를 검증한다.
정책과 변경 기준은
[`2026-08-30-compatibility-evidence-policy.md`](./2026-08-30-compatibility-evidence-policy.md)에
기록했고 CI/release publish 선행 gate에 같은 명령을 연결했다.

### `AK-M11` — coverage floor

- 상태: `P1 / DONE`

완료 조건:

- [x] fresh full run을 기준으로 현실적인 global threshold를 정한다.
- [x] Guard, service, errors, key format 같은 critical file은 per-file threshold를 검토한다.
- [x] Prisma adapter 0%를 단순 제외해 수치를 부풀리지 않고 real DB gate와 연결한다.
- [x] CI artifact에 summary를 남긴다.
- [x] 수치 맞추기용 무의미한 테스트는 추가하지 않는다.

검증: 프로필 B/C와 의도적 regression이 gate를 실패시키는지 확인.

완료 결정(2026-08-31): fresh 전체 run의 `88.23/84.10/86.95/87.86`을 기준으로 global
statements/branches/functions/lines floor를 각각 `88/84/86/87`로 고정했다. critical file은 Guard
`100/83/100/100`, service `93/89/100/93`, errors `100/100/100/100`, key format
`97/92/100/97`을 같은 JSON summary에서 별도 검증한다. Jest의 path threshold가 해당 파일을
global 집계에서 빼는 의미를 피하기 위해 Jest 자체는 진짜 전체 global floor를, 후속 checker는
critical file floor를 담당한다. `prisma-storage.ts`는 collect 대상에 그대로 남겨 fresh run에서
`6.06/0/7.69/6.06`으로 집계되며, 기능 증거는 별도 필수 PostgreSQL 14/16 + Prisma 5/6/7 real DB
job이 담당한다. source CI와 tag release는 `coverage-summary.json`과 사람이 읽는
`coverage-floor.txt`를 14일 artifact로 보존하며 release publish는 coverage job 성공을 요구한다.
coverage 수치를 올리기 위한 제품 무관 테스트는 추가하지 않았다.

## 5. P2 작업 명세

### `AK-M12` — safe public list projection

- 상태: `P2 / DONE`
- 문제: `list()`가 storage record를 그대로 반환해 `hash`와 `pepperVersion`이 public enumerable field가 된다.

완료 조건:

- [x] `ApiKeySummary` 같은 public projection을 도입해 verifier material을 제외한다.
- [x] serialized list에 hash, pepper version, raw secret이 없다.
- [x] internal storage record와 rotation/verification 기능은 유지된다.
- [x] 기존 반환 type 변경의 semver/compatibility path를 기록한다.
- [x] 관리 controller가 그대로 반환해도 최소 안전 필드만 노출되는 예제를 제공한다.

검증: serialization, type declaration, packed consumer tests.

비범위: storage interface 비공개화, 관리 UI.

완료 결정(2026-08-31): `ApiKeysService.list()`는 storage의 `ApiKeyRecord[]`를 명시적인
`ApiKeySummary[]`로 projection해 반환한다. summary에는 관리 metadata와 lifecycle timestamp만
포함하고 `hash`/`pepperVersion`은 runtime enumerable field와 public declaration 모두에서 제외한다.
scopes/IP 배열과 Date는 새 객체로 복사하며 storage interface와 verifier/rotation record는 변경하지
않았다. 기존 `includeRevoked` query를 그대로 전달하므로 default가 revoked만 제외하고 expired 및
rotation-grace record를 유지하는 현재 동작은 보존한다. 이 보안 projection은 filter 정책 선택과
독립적이므로 `AK-M15` 선행을 해제했고, active/expired/grace 의미 결정은 여전히 별도 `DECISION`으로
남긴다. 공개 반환 type narrowing은 계획된 pre-1.0 `0.4.0` breaking change이며 storage adapter의
`ApiKeyRecord` 계약은 유지한다. README에는 tenant-bound controller가 service 결과를 직접 반환하는
예제와 storage 결과를 직접 노출하지 말라는 경계를 추가했다.

### `AK-M13` — environment segment binding

- 상태: `P2 / READY`

완료 조건:

- [ ] parsed environment와 stored record environment가 다르면 stable invalid 결과로 거부한다.
- [ ] 정상 live/test 및 route-level environment mismatch 의미를 보존한다.
- [ ] event/metric은 변조된 credential의 내부 record 정보를 과다 노출하지 않는다.

검증: service/Guard table, Prisma lane.

### `AK-M15` — list 상태 의미

- 상태: `P2 / DECISION`
- 문제: README의 "active keys"와 구현의 "non-revoked keys"가 다르며 expired/rotation grace record가 default 결과에 남는다.

완료 조건:

- [ ] active, revoked, expired, rotated-with-grace 상태를 정의한다.
- [ ] `includeRevoked`, 새 `includeExpired` 또는 문서 정정 중 호환 가능한 API를 선택한다.
- [ ] InMemory/Prisma ordering과 filter가 일치한다.
- [ ] 현재 소비자의 non-revoked 기대를 migration note로 다룬다.

### `AK-M16` — InMemory storage record Date defensive copy

- 상태: `P2 / BLOCKED (AK-M05)`

완료 조건:

- [ ] insert/find/list/rotate/revoke/touch 경계에서 모든 nullable Date를 복사한다.
- [ ] input 또는 반환 record의 Date mutation이 저장 상태에 영향을 주지 않는다.
- [ ] Prisma와 동일한 observable storage semantics를 contract suite로 고정한다.
- [ ] 이 작업은 adapter record의 Date ownership만 다룬다. event/context whole-object 불변성은 `AK-M05`를 다시 수정하지 않고 그 gate를 재사용한다.

### `AK-M17A` — SECURITY와 reporting policy

- 상태: `P2 / DECISION`

완료 조건:

- [ ] `SECURITY.md`에 지원 버전, 비공개 신고 경로, 응답 범위, credential/PoC 주의사항을 기록한다.
- [ ] 존재하지 않는 이메일이나 SLA를 발명하지 않는다.
- [ ] 실제 채널과 지원 release line이 승인되면 문서 PR만으로 `DONE` 처리한다. repository settings 변경은 섞지 않는다.

검증: relative links, supported-version table, 실제 승인된 private contact 또는 GitHub reporting URL.

### `AK-M17B` — repository security settings

- 상태: `P2 / EXTERNAL (AK-M17A)`

완료 조건:

- [ ] private vulnerability reporting, Dependabot security updates, secret scanning/push protection 적용 가능성을 관리자 권한에서 결정한다.
- [ ] main/tag force-push/delete 방지 ruleset과 required checks를 검토한다.
- [ ] 적용하지 않는 설정은 권한/요금제/제품 결정 사유와 재검토 조건을 기록한다.

검증: GitHub repository settings/API와 실제 Security 탭 노출. 코드 PR과 별도 evidence로 남긴다.

### `AK-M18` — release ancestry와 pack-once provenance

- 상태: `P2 / READY`

완료 조건:

- [ ] tag commit이 canonical `origin/main` ancestry에 포함됨을 publish 전에 확인한다.
- [ ] tag/package/CHANGELOG version이 일치한다.
- [ ] consumer가 검증한 exact tarball을 publish하거나 SHA/integrity로 동일성을 증명한다.
- [ ] trusted publishing, provenance, 최소 권한을 유지한다.
- [ ] ancestry/pack-once fixture와 workflow dry-run이 통과하면 이 구현 작업을 `DONE` 처리할 수 있다. 다음 실제 release 결과를 기다리지 않는다.

검증: ancestry success/failure fixture, package content allowlist, candidate tarball SHA/integrity, workflow command graph. 실제 release의 npm `gitHead`/attestation은 §9 release evidence에 누적한다.

### `AK-M19` — workflow와 dependency bot 수렴

- 상태: `P2 / BLOCKED (AK-M18)`

완료 조건:

- [ ] CI/release Prisma matrix의 drift를 reusable workflow 또는 parity test로 막는다.
- [ ] Actions version/SHA 정책을 통일한다.
- [ ] Nest trio, Jest, ESLint/typescript-eslint을 호환 그룹으로 갱신한다.
- [ ] job timeout과 concurrency가 명시된다.
- [ ] production audit 0 gate와 만료형 dev-audit exception 방식을 도입한다.

### `AK-M20A` — 문서 권위와 지원표

- 상태: `P2 / READY (AK-M09, AK-M10 DONE)`

완료 조건:

- [ ] README에 Node/Nest/Prisma/PostgreSQL 지원표와 검증 깊이를 둔다.
- [ ] Prisma는 adapter 사용 시에만 필요한 optional peer임을 PRD와 맞춘다.
- [ ] v0.1–v0.3 spec/implementation plans에 historical/completed 표식을 둔다.
- [ ] 기존 dirty compatibility 문서는 소유권 확인 뒤 실제 0.3.2 배포 상태로 갱신한다.
- [ ] 이 유지보수 계획을 canonical execution queue로 링크한다.

### `AK-M20B` — reusable storage contract public package 계약

- 상태: `P2 / READY (AK-M02 DONE)`
- 문제: README/CHANGELOG는 custom `ApiKeyStorage` implementor용 reusable contract suite를 약속하지만 현재 suite는 `test/contract/storage-contract.ts`에만 있고 tarball files/root exports에 없다.

완료 조건:

- [ ] runtime package가 지원 가능한 test helper/fixture를 export할지, 문구를 내부 contract로 정정할지 ADR로 결정한다.
- [ ] export하면 `AK-M02`의 atomic rotation capability와 모든 required method를 검증하고 consumer test framework/Jest global을 암묵적으로 요구하지 않는다.
- [ ] packed clean consumer가 public 경로로 contract를 import·compile·대표 adapter에 실행한다.
- [ ] export하지 않으면 README/CHANGELOG/spec에서 external implementor promise를 정확히 좁히고 custom adapter verification recipe를 제공한다.
- [ ] package files/type declarations와 documentation이 같은 결정을 반영한다.

검증: actual tarball allowlist, no-Prisma custom adapter consumer, public declaration compile.

## 6. P3와 결정 대기 backlog

### `AK-M21` — packaging/ESM ADR

- 상태: `P3 / DECISION (AK-M10 DONE)`

- 현 CommonJS `main/types`를 유지할지 `exports` map과 dual ESM/CJS를 도입할지 결정한다.
- deep import 사용자를 먼저 조사한다.
- 도입 시 root/type/CJS/ESM, optional Prisma 미설치, schema/config files를 packed consumer에서 검증한다.
- 조사 없이 `exports`를 추가해 기존 deep import를 차단하지 않는다.

### `AK-M22` — collision retry terminal error

- 상태: `P3 / READY (AK-M02 DONE)`

- create와 rotate가 최대 재시도 뒤 동일한 typed error/cause 계약을 제공한다.
- 정확한 attempt count와 metric을 테스트한다.
- random generator 자체 교체는 포함하지 않는다.

### `AK-M23` — Nest 12 stable compatibility spike

- 상태: `P3 / READY (AK-M10 DONE)`
- 2026-08-30 기준 [`@nestjs/core` latest는 12.0.1](https://www.npmjs.com/package/%40nestjs/core?activeTab=versions)이므로 더 이상 “stable 대기” 후보로 두지 않는다.
- Nest 12.0.1 exact versions를 strict packed consumer에 설치해 install, typecheck, runtime smoke와 실제 HTTP Guard 경로를 조사한다.
- 이 세션은 evidence와 ADR만 소유한다. peer 범위 확대, breaking migration, 구현 변경은 결과에 따라 별도 task/PR로 만든다.

### 결정 대기 후보

| ID | 후보 | 결정 질문 |
| --- | --- | --- |
| `AK-B03` | class/method scope metadata | 현재 override를 유지할지 누적/교집합 semantics를 제공할지? |
| `AK-B04` | pagination/search | 실제 key cardinality와 consumer 요구가 있는지? |
| `AK-B05` | event delivery durability | outbox/audit-log adapter가 library core에 필요한지? |
| `AK-B06` | Argon2/hash-version migration | 실제 threat model, migration/rollback, runtime 비용 근거가 있는지? |
| `AK-B07` | Redis verification cache | revoke/rotation invalidation과 stale-read SLO를 증명할 요구가 있는지? |
| `AK-B08` | unbiased base62 sampling | 현재 entropy 위험 평가와 format compatibility 변경 가치가 있는지? |
| `AK-B09` | package manager/npm version pin | 재현성 incident 또는 Corepack/tooling 정책이 있는지? |
| `AK-B11` | Prisma 8 compatibility | stable release, PostgreSQL adapter, strict consumer 근거가 있는지? |
| `AK-B12` | async/non-global module configuration | `forRootAsync`, global opt-out, exported DI token 소비자 요구가 있는지? |
| `AK-B13` | generated E2E artifact/tooling hygiene | repo 밖 generation과 scripts/bench lint·typecheck를 지속 gate로 둘 가치가 있는지? |

기존 후보 `AK-B01`과 `AK-B02`는 각각 executable P1 `AK-M07B`와 `AK-M06C`로 승격했다. 나머지 후보는 서로 독립이며 한 ID를 묶어 구현하지 않는다. 합의 전 `READY`가 아니다.

## 7. 검증 프로필

### 프로필 A — 빠른 회귀

```bash
npm run lint
./node_modules/.bin/tsc --noEmit -p tsconfig.build.json
npm test -- --runInBand
git diff --check
```

### 프로필 B — coverage

```bash
api_keys_coverage_dir="$(mktemp -d /tmp/api-keys-coverage.XXXXXX)"
npm run test:coverage -- --coverageDirectory="$api_keys_coverage_dir"
```

출력에 기록된 session-owned 경로만 증거로 사용한다. ignored `coverage/`의 오래된 결과나 다른 세션과 공유한 고정 `/tmp` 경로를 기준으로 삼지 않는다.

### 프로필 C — DB와 compatibility

- Prisma 5.22.0 PostgreSQL 14 boundary contract
- Prisma 5.22.0, 6.19.3, 7.10.0 PostgreSQL 16 contract
- exact Nest 10.4.20/Prisma 6.19.3 strict consumer
- exact Nest 11.2.3/Prisma 7.10.0 strict consumer
- exact Nest 11.2.3 no-Prisma strict root consumer
- exact Nest 10.4.20/11.2.3 HTTP consumer
- 해당 작업이 지원 matrix를 바꿀 때만 선택한 off-diagonal lane

`test:e2e:postgres-matrix`가 세 exact Prisma runtime root를 session-owned 임시 경로에 각각
설치하고 PostgreSQL 14 boundary와 PostgreSQL 16의 세 Prisma major를 반복 실행한다. 이 명령은
matrix 증거가 caller-provided database로 바뀌지 않도록 `PRISMA_E2E_DATABASE_URL`을 사용하지 않고
실제 container server major를 확인한다. 단일 `test:e2e:prisma`는 선택한 runtime/database를
진단할 때만 사용하며 전체 matrix 증거로 세지 않는다.

```bash
npm run test:e2e:postgres-matrix
npm run test:consumer:strict:legacy
npm run test:consumer:strict:modern
npm run test:consumer:no-prisma
npm run test:consumer:http:nest10
npm run test:consumer:http:nest11
```

`test:e2e:postgres-matrix`는 PostgreSQL 14 boundary와 16 current lane을 구분해 보고해야 한다. 기존 strict consumers는 application context만 boot하므로 `AK-M01`의 HTTP/Guard/exception-filter 증거 또는 `AK-M10`의 no-Prisma 증거로 세지 않는다.

현재 Prisma runner는 ignored `test/e2e/generated/`를 지우고 다시 생성한다. 이는 tracked 사용자 변경이 아니지만 session 종료 시 생성 경로를 기록한다. repo 밖 generation과 cleanup 개선은 후보 `AK-B13`이며 compatibility 결과와 같은 PR에 섞지 않는다.

### 프로필 D — package/release

```bash
npm run build
npm pack --dry-run --json
npm run bench:smoke
npm audit --omit=dev --json
```

full `npm audit --json`은 pass profile과 분리해 JSON과 exit code를 기록한다. 현재 dev finding이 남아 exit 1인 것은 기준선과 일치할 수 있지만, 새 finding이나 production 경로는 실패다.

## 8. cross-package 소유권과 release 순서

```text
API Keys: verified ApiKeyContext와 request.apiKey 생성
    ↓
RBAC: request source/tenant conflict를 조정하고 RbacSubject로 변환
    ↓
Tenancy ecosystem: published package tuple의 end-to-end 경로 검증
```

- API Keys가 소유: key format, verification, rotation, storage, event/metric, tenant ID producer, `request.apiKey`.
- RBAC가 소유: `ApiKeyContext → RbacSubject`, legacy property fallback, trusted tenant reconciliation, authorization.
- tenancy가 소유: published-only exact tuple과 API key → tenant → RBAC → RLS/outbox/jobs/webhook 전체 E2E.

| 외부 작업 | 상태 | 이 문서와의 관계 |
| --- | --- | --- |
| `TEN-M21` | `DONE` | published tenancy 0.16.0의 legacy/modern gate 기준선이다. 재개하지 않는다. |
| `TEN-ECO-NEXT` | `EXTERNAL` | 이후 API Keys/RBAC published patch tuple을 검증하는 새 tenancy-owned 작업이다. API Keys task의 pre-publish `DONE` 조건이 아니다. |

`TEN-ECO-NEXT`는 이 문서에서 예약한 인계 ID다. 실제 실행 전에 tenancy 계획 문서에 새 작업으로 생성해야 하며 기존 `TEN-M21`을 이름만 바꾸거나 reopen하지 않는다.

권장 identity 변경 순서:

1. API Keys `AK-M06A`가 producer canonicalization ADR을 확정한다.
2. RBAC가 `RBAC-M01` trusted tenant reconciliation과 `RBAC-M02` canonical request source를 별도 PR로 합치고, 둘 다 포함한 registry version을 배포한다. 두 번의 배포 자체를 의무화하지 않는다.
3. API Keys `AK-M06B`가 published RBAC와 packed API Keys candidate를 sibling checkout 없이 검증하고 persistent consumer gate를 추가한 뒤 배포한다.
4. tenancy 소유의 새 외부 작업 `TEN-ECO-NEXT`가 양쪽 published exact version을 pin해 full ecosystem E2E를 실행한다.

`TEN-M21`은 현재 v0.16.0 evidence로 `DONE`이며 재개하지 않는다. `TEN-ECO-NEXT`는 API Keys/RBAC package 작업과 별도 상태·인계를 갖고, 사후 실패 시 새 cross-package issue를 만들 뿐 이미 검증된 package PR의 `DONE`을 순환적으로 막지 않는다. `AK-M01`, `AK-M02`, `AK-M03`, `AK-M04`, `AK-M05`는 이 외부 순서와 독립적으로 진행할 수 있다.

## 9. 실제 자동 gate, 수동 release check, 향후 gate

### 9.1 2026-08-30 실제 자동화

- source CI: PR/main에서 exact Node 22.13.0/Node 24 각각 lint, test, build, bench smoke를 실행하고 exact
  Nest 10.4.20/11.2.3 HTTP consumer를 별도 job으로 실행한다.
- source CI와 tag release의 `verify-prisma`: exact Node 22.13.0과 PostgreSQL 16에서 Prisma 5/6/7 real DB contract를 실행하고 Prisma 6/7 lane은 legacy/modern strict consumer도 실행한다.
- source/release workflow의 checkout/setup-node는 Actions v7로 통일했다.
- tag release `publish`: `verify-prisma`와 `verify-http`를 선행으로 요구하며 Node 24에서 lint,
  test, build, tag/package version check 후 trusted publish를 실행한다.
- source CI와 tag release의 exact Node 22.13.0 coverage job은 global/critical-file floor를 강제하고
  JSON/text summary artifact를 14일 보존한다. release `publish`는 이 job도 선행으로 요구한다.
- 현재 workflow에는 production audit gate, `git diff --check`, main ancestry, CHANGELOG version check,
  pack-once identity가 없다. 이를 이미 강제되는 gate로 기록하지 않는다.

### 9.2 현재 수동 release checklist

- [ ] 프로필 A와 D를 fresh checkout에서 실행하고 production audit 0을 확인한다.
- [ ] Prisma 5/6/7 runtime roots와 legacy/modern strict consumers 결과를 기록한다.
- [ ] tag/package/CHANGELOG version과 tag target을 사람이 확인한다.
- [ ] `git diff --check`, tarball content, npm dist-tag, release notes를 확인한다.

수동 check를 했다는 기록은 workflow enforcement를 의미하지 않는다.

### 9.3 작업 완료 뒤 추가할 persistent gate

- [x] `AK-M01`: wrong-secret lifecycle oracle/hash-work regression과 Nest 10/11 actual HTTP 401/403 E2E
- [x] `AK-M02`: real PostgreSQL concurrent rotation exactly-once CAS
- [x] `AK-M03`: invalid time/duration pre-mutation 및 corrupt persisted expiry fail-closed contract
- [x] `AK-M04`: runtime environment/scope와 generated key parse/verify/redact property contract
- [x] `AK-M05`: observer/contextWriter whole-object mutation negative contract
- [ ] `AK-M06B`: packed API Keys candidate → published RBAC canonical/conflict consumer
- [x] `AK-M06C`: tenant-bound revoke update와 rotation CAS의 InMemory/Prisma/packed consumer contract
- [x] `AK-M07A`: missing/denial telemetry semantics; `AK-M07B`: request-aware IP restriction contract
- [x] `AK-M14`: legacy auth observer sync/thenable/async rejection과 reporter 재실패 격리
- [x] `AK-M09`: exact Node 22.13.0 minimum/Node 24 source lanes와 minimum DB/consumer gates
- [x] `AK-M10`: PostgreSQL 14/16와 no-Prisma packed consumer
- [x] `AK-M11`: fresh coverage threshold
- [x] `AK-M12`: serialized public summary와 packed declaration/runtime verifier-material exclusion
- [ ] `AK-M18`: main ancestry와 consumer-verified exact tarball identity
- [ ] `AK-M20B`: public storage contract 또는 corrected documentation packed test

`TEN-ECO-NEXT`의 published-only evidence는 tenancy-owned external gate다. API Keys release에서는 `AK-M06B`의 packed pre-publish consumer를 지속 gate로 유지해 순환을 만들지 않는다. 향후 gate를 완료 전 P0 patch의 선행 조건으로 소급 적용하지 않는다.

## 10. 다음 세션 권장 시작점

1. `AK-M06A/C`와 `AK-M06B`의 API Keys-side diff를 검토해 계획된 0.4.0 P1 PR 경계를
   결정한다. `AK-M06B`를 `DONE`으로 표시하거나 RBAC gate를 workflow에 연결하지 않는다.
2. RBAC 저장소에서 `RBAC-M01`과 `RBAC-M02`를 각각 완료하고 둘 다 포함한 exact registry
   version을 publish한다.
3. 이 저장소에서 `npm run test:consumer:rbac -- --rbac <exact-version>`을 실행한다. PASS일 때만
   `.github/workflows/ci.yml`과 `release.yml`에 같은 exact version의 persistent gate를 추가한다.
4. profile A/B/D와 packed RBAC consumer를 다시 통과시켜 `AK-M06B`를 `DONE` 처리하고,
   tenancy-owned `TEN-ECO-NEXT`에 published package tuple을 인계한다.
5. `AK-M07A/B`, `AK-M14`, `AK-M08A/B/C`, `AK-M09`, `AK-M10`, `AK-M11`은 완료됐다. 외부
   RBAC release를 기다리는 동안 다음 순서의 실행 가능한 작업은 `AK-M15` list 상태 의미 결정이다.

Published RBAC 0.2.1은 `request.apiKeyContext` conflict와 trim/coerce 계약 때문에 의도적으로
RED다. sibling checkout 또는 unpublished RBAC tarball을 `AK-M06B` 완료 증거로 사용하지 않는다.

## 11. 작업 기록

| 날짜 | 작업 ID | 상태 | 시작 ref | 종료 ref/PR/release | 검증 요약 | 다음 행동 |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-08-30 | 계획 기준선 | `DONE` | `v0.3.2 / a24fe1d` | 문서 작성 | 11 suites/81 tests, lint/typecheck, fresh coverage, audits, release/CI/source 검토 | `AK-M01` 시작 |
| 2026-08-30 | `AK-M01` | `DONE` | `408ca80` | `408ca80 + worktree` (PR/release 없음) | profile A 11 suites/85 tests, profile B 84.21/77.61/81.94/83.73, Nest 10.4.20/11.2.1 packed HTTP PASS, benchmark smoke PASS | AK-M01 단독 patch commit/PR 뒤 `AK-M02` 시작 |
| 2026-08-30 | `AK-M02` | `DONE` | `ea2ebb7` | `ea2ebb7 + worktree` (PR/release 없음) | profile A 11 suites/93 tests, profile B 85.55/80.56/80.82/85.14, Prisma 5/6/7 PostgreSQL 각 18 tests, strict legacy/modern PASS | AK-M02 단독 0.4.0 PR 뒤 `AK-M03` 시작 |
| 2026-08-30 | `AK-M03` | `DONE` | `c6c343a` | `c6c343a + worktree` (PR/release 없음) | profile A 11 suites/116 tests, profile B 86.82/81.85/83.11/86.49, Prisma 5/6/7 PostgreSQL 각 18 tests, build/audit PASS | AK-M03 단독 P1 PR 뒤 `AK-M04` 시작 |
| 2026-08-30 | `AK-M04` | `DONE` | `2a867ca` | `2a867ca + worktree` (PR/release 없음) | profile A 11 suites/148 tests, profile B 87.54/83.26/84.70/87.30, build/pack 46 entries/bench/audit PASS | AK-M04 단독 0.4.0 P1 PR 뒤 `AK-M05` 시작 |
| 2026-08-30 | `AK-M05` | `DONE` | `3477505` | `3477505 + worktree` (PR/release 없음) | profile A 11 suites/151 tests, profile B 88.03/84.49/85.22/87.79, malicious observer/writer와 실제 RBAC resolver PASS | AK-M05 단독 P1 PR 뒤 `AK-M06A` 시작 |
| 2026-08-30 | `AK-M06A` | `DONE` | `f3a1bed` | `f3a1bed + worktree` (PR/release 없음) | tenant input/legacy inventory, RBAC-M01/M02 대조, ADR/migration checklist와 link 확인 | API Keys producer 구현 뒤 published RBAC prerequisite 재확인 |
| 2026-08-30 | `AK-M06B` | `BLOCKED` | `f3a1bed` | `f3a1bed + worktree` (PR/release 없음) | API Keys canonical producer와 packed consumer 작성; published RBAC 0.2.1 conflict RED, profile A/B/D와 package matrix 나머지 PASS | RBAC-M01/M02 포함 version publish 뒤 consumer PASS와 CI/release gate 추가 |
| 2026-08-30 | `AK-M06C` | `DONE` | `f3a1bed` | `f3a1bed + worktree` (PR/release 없음) | InMemory + Prisma 5/6/7 각 20 tests, Nest 10/11 packed management runtime PASS | AK-M06C 범위 완료; M06B 외부 prerequisite 또는 AK-M07A 진행 |
| 2026-08-30 | `AK-M07A` | `DONE` | `f3a1bed` | `f3a1bed + worktree` (PR/release 없음) | 12 suites/184 tests, coverage 87.91/83.02/85.04/87.70, Guard missing/denial telemetry table PASS | `AK-M14` observer isolation RED table |
| 2026-08-30 | `AK-M07B` | `DONE` | `f3a1bed` | `f3a1bed + worktree` (PR/release 없음) | Nest 10/11 strict direct + HTTP packed consumers, request-aware IP table PASS | AK-M07A/B 변경을 함께 검토·commit |
| 2026-08-30 | `AK-M14` | `DONE` | `3454cb6` | `3454cb6 + worktree` (PR/release 없음) | 12 suites/188 tests, coverage 88.23/83.17/86.95/87.86, sync/thenable/async observer와 reporter rejection PASS, Nest 10/11 HTTP PASS | AK-M14 파일을 검토·commit한 뒤 `AK-M08A` 최신 PR 상태 재조회 |
| 2026-08-30 | `AK-M08A` | `DONE` | local `7a75426`, remote `a24fe1d` | PR #16 `306be401`, #17 `b3dbf139`, #20 `f00ce8f2`; local merge `055daa5` | #17/#20 최신 main 재베이스 후 각 Node 20/22와 Prisma 5/6/7 5 checks PASS | Nest 11.2.x trio clean install |
| 2026-08-30 | `AK-M08B` | `DONE` | `055daa5` | `055daa5 + worktree` (PR/release 없음) | Nest trio 11.2.3, 12 suites/188 tests, exact Nest 10.4.20/11.2.3 strict+HTTP, Prisma 5/6/7 각 20 PASS | AK-M08C와 함께 toolchain 검증 뒤 `AK-M09` |
| 2026-08-30 | `AK-M08C` | `DONE` | `055daa5` | `055daa5 + worktree` (PR/release 없음) | ESLint 10.9.1 flat config, coverage 88.23/84.10/86.95/87.86, clean npm ci, production/full audit 0 | `AK-M09` Node 22/24 지원 계약 |
| 2026-08-30 | `AK-M09` | `DONE` | `fa4093f` | `fa4093f + worktree` (PR/release 없음) | exact Node 22.13.0/24.11.1 A/B/C/D, 각 12 suites/188 tests와 coverage 88.23/84.10/86.95/87.86, Prisma 5/6/7 각 20, Nest 10/11 strict+HTTP, audits 0 | `AK-M10` compatibility 증거 정책 |
| 2026-08-30 | `AK-M10` | `DONE` | `2488896` | `2488896 + worktree` (PR/release 없음) | PostgreSQL 14/Prisma 5와 PostgreSQL 16/Prisma 5/6/7 각 20 PASS, no-Prisma strict packed consumer, Nest 10/11 strict+HTTP, profile A/D PASS | `AK-M11` coverage floor |
| 2026-08-31 | `AK-M11` | `DONE` | `7e1dd16` | `7e1dd16 + worktree` (PR/release 없음) | global 88/84/86/87와 4 critical-file floor PASS, 두 intentional regression exit 1, PostgreSQL/Prisma matrix와 packed consumers PASS | `AK-M15` list 상태 의미 결정 |
| 2026-08-31 | `AK-M12` | `DONE` | `5747de4` | `5747de4 + worktree` (PR/release 없음) | RED serialization 노출 재현, 12 suites/189 tests, coverage 88.27/84.01/87.17/87.90, Nest 10/11 packed type/runtime PASS, build/pack/bench/audit PASS | `AK-M15` list 상태 의미 결정 |

### AK-M01 종료 인계

```text
Task: AK-M01
State: DONE
Start ref / end ref: 408ca80 / 408ca80 + session worktree (commit·PR·release 없음)
Changed files: src/api-keys.service.ts, src/errors.ts, src/errors.test.ts, src/hasher.ts,
  test/integration/api-keys.service.test.ts, bench/api-keys.bench.ts,
  scripts/test-http-consumer.js, package.json, .github/workflows/ci.yml,
  .github/workflows/release.yml, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: lifecycle은 secret hash/compare 성공 뒤 판정한다. ApiKeyError public HTTP body는
  { statusCode, code }이며 httpStatus는 호환 유지하고 deprecate하지 않는다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts src/errors.test.ts
    => expected FAIL (revoked/expired wrong-secret oracle, HttpException API 부재)
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 11 suites, 85 tests PASS
  fresh Jest coverage => statements 84.21%, branches 77.61%, functions 81.94%, lines 83.73%
  npm run bench:smoke => PASS; local |unknown-known invalid| p50 0.2µs, bound 500µs
  npm run test:consumer:http:nest10 => exact Nest 10.4.20 PASS
  npm run test:consumer:http:nest11 => exact Nest 11.2.1 PASS
  git diff --check + untracked script whitespace check => PASS
Unverified paths and reason: remote GitHub CI/release jobs은 push 전이라 미실행. Prisma profile C는
  storage/Prisma 계약을 변경하지 않아 AK-M01 검증 범위에서 제외했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M01 파일만 검토·commit해 별도 patch PR로 merge한 뒤 AK-M02의 concurrent
  rotation barrier failing contract test를 추가한다.
```

### AK-M02 종료 인계

```text
Task: AK-M02
State: DONE
Start ref / end ref: ea2ebb7 / ea2ebb7 + session worktree (commit·PR·release 없음)
Changed files: src/api-keys.service.ts, src/index.ts,
  src/storage/api-key-storage.interface.ts, src/storage/in-memory-storage.ts,
  src/storage/prisma-storage.ts, test/contract/storage-contract.ts,
  test/e2e/prisma-storage.e2e-spec.ts, test/integration/api-keys.service.test.ts,
  bench/api-keys.bench.ts, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: storage.rotate()가 active/unreplaced 조건과 replacement insert를 원자 처리하고
  'rotated' | 'not_rotatable'을 반환한다. Prisma는 interactive transaction + updateMany CAS를
  사용한다. 구형 Promise<void> adapter는 fail-fast하며 pre-1.0 minor 0.4.0 breaking change다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/in-memory-storage.test.ts
    test/integration/api-keys.service.test.ts => expected FAIL; concurrent 8회 모두 성공
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 11 suites, 93 tests PASS
  fresh Jest coverage => statements 85.55%, branches 80.56%, functions 80.82%, lines 85.14%
  Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 => 각 1 suite, 18 tests PASS
  npm run test:consumer:strict:legacy => exact Nest 10.4.20/Prisma 6.19.3 PASS
  npm run test:consumer:strict:modern => exact Nest 11.2.1/Prisma 7.10.0 PASS
  npm run build => PASS; npm pack --dry-run --json => PASS, 44 entries
  npm run bench:smoke => PASS; local |unknown-known invalid| p50 0.5µs, bound 500µs
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release jobs은 push 전이라 미실행. Prisma runner가 만든
  ignored test/e2e/generated/와 /tmp exact runtime/coverage 경로는 검증 산출물이며 tracked 변경 아님.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M02 파일만 검토·commit해 pre-1.0 0.4.0 대상 단독 PR로 merge한 뒤 AK-M03의
  invalid time/duration storage-before-mutation RED table을 추가한다.
```

### AK-M03 종료 인계

```text
Task: AK-M03
State: DONE
Start ref / end ref: c6c343a / c6c343a + session worktree (commit·PR·release 없음)
Changed files: src/api-keys.service.ts, src/errors.ts, src/errors.test.ts,
  test/integration/api-keys.service.test.ts, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: invalid expiresAt, duration configuration/input, Date arithmetic overflow는
  storage mutation 전 ApiKeyOperationError/api_key_invalid_time으로 거부한다. 과거 expiry는 즉시
  expired, null은 non-expiring, zero grace는 old key 즉시 만료다. authenticated record의 손상
  expiry는 verify api_key_invalid, rotate api_key_not_rotatable로 fail closed한다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    => expected FAIL; ApiKeyOperationErrorCode.InvalidTime contract 부재
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 11 suites, 116 tests PASS
  fresh Jest coverage (/tmp/api-keys-m03-final-coverage.0Ru4jY) => statements 86.82%,
    branches 81.85%, functions 83.11%, lines 86.49%
  Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 => 각 1 suite, 18 tests PASS
  npm run build => PASS
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release jobs과 strict packed consumers는 push 전이며,
  AK-M03이 package/peer contract를 바꾸지 않아 미실행. Invalid Date persisted row는 Prisma DateTime으로
  표현할 수 없어 계획대로 실DB에 seed하지 않고 custom-storage return table로 검증했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M03 파일만 검토·commit해 별도 P1 PR로 merge한 뒤 AK-M04의 runtime
  namespace/environment/scope 및 parse/verify/redact round-trip RED table을 추가한다.
```

### AK-M04 종료 인계

```text
Task: AK-M04
State: DONE
Start ref / end ref: 2a867ca / 2a867ca + session worktree (commit·PR·release 없음)
Changed files: src/input-validation.ts, src/key-format.ts, src/key-format.test.ts,
  src/scope-matcher.ts, src/scope-matcher.test.ts, src/api-keys.service.ts,
  src/api-keys.module.ts, src/api-keys.module.test.ts, src/errors.ts, src/errors.test.ts,
  src/index.ts, test/integration/api-keys.service.test.ts, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: namespace는 ASCII 영숫자 1–32자, environment는 live|test, scope resource는
  ASCII 영숫자로 시작하고 영숫자, dot, underscore, slash, hyphen으로 구성된 1–128자,
  level은 read|write다. invalid issue input은
  key 생성/storage mutation 전 api_key_invalid_input으로 거부한다. parser의 외부 실패는
  api_key_malformed를 유지하며 namespace/environment와 base62 12/32자 segment를 모두 검사한다.
  normalization은 하지 않으며 기존 punctuation/장문 namespace는 0.4.0 전 재발급한다.
Commands and exact results:
  RED: npm test -- --runInBand src/key-format.test.ts src/scope-matcher.test.ts
    src/api-keys.module.test.ts test/integration/api-keys.service.test.ts
    => expected FAIL; 4 suites failed, 18 tests failed (invalid runtime input 발급,
       unsafe namespace 허용, non-base62 parser 허용; scope table은 구현 전 type failure 포함)
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 11 suites, 148 tests PASS
  fresh Jest coverage (/tmp/api-keys-m04-coverage.ISwcKj) => statements 87.54%,
    branches 83.26%, functions 84.70%, lines 87.30%
  npm run build => PASS
  npm_config_cache=/tmp/api-keys-m04-npm-cache npm pack --dry-run --json
    => PASS, 46 entries; first default-cache attempt은 user cache EPERM 뒤 temp cache로 재실행
  npm run bench:smoke => PASS; local |unknown-known invalid| p50 0.2µs, bound 500µs
  npm audit --omit=dev --json => production vulnerabilities 0; sandbox DNS 실패 뒤 승인된
    registry access와 session temp cache로 재실행
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release jobs은 push 전이라 미실행. AK-M04는 storage
  schema/Prisma 또는 support matrix를 바꾸지 않아 profile C real PostgreSQL/strict consumer는
  계획된 검증 범위에서 제외했고 InMemory/custom 및 Prisma create spy로 mutation 전 거부를 검증했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M04 파일만 검토·commit해 pre-1.0 0.4.0 대상 단독 P1 PR로 merge한 뒤
  AK-M05의 observer/contextWriter whole-object mutation RED test를 추가한다.
```

### AK-M05 종료 인계

```text
Task: AK-M05
State: DONE
Start ref / end ref: 3477505 / 3477505 + session worktree (commit·PR·release 없음)
Changed files: src/payload-copy.ts, src/api-keys.service.ts, src/api-keys.guard.ts,
  test/integration/api-keys.service.test.ts, test/integration/api-keys.guard.test.ts,
  test/integration/rbac-compatibility.test.ts, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: public context/event/metric type은 source compatibility를 위해 mutable로 유지하고
  runtime defensive copy만 적용한다. sink/error reporter와 contextWriter/request.apiKey는 서로 다른
  object·array·Date를 받으며 Guard는 writer 완료 뒤 verified identity를 복원한다. deep-freeze는 하지 않는다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    test/integration/api-keys.guard.test.ts => expected FAIL; 3 tests failed, 73 passed
    (sync/async usage scope alias, rotated grace Date alias, writer tenant/key/scope/IP replacement)
  npm test -- --runInBand test/integration/api-keys.service.test.ts
    test/integration/api-keys.guard.test.ts test/integration/rbac-compatibility.test.ts
    => 3 suites, 77 tests PASS
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 11 suites, 151 tests PASS
  fresh Jest coverage (/tmp/api-keys-m05-final-coverage.ksWIDi) => statements 88.03%,
    branches 84.49%, functions 85.22%, lines 87.79%; payload-copy.ts statements/lines 100%
  npm run build => PASS
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release jobs은 push 전이라 미실행. AK-M05는 storage
  schema/Prisma/support matrix를 변경하지 않아 profile C real PostgreSQL과 packed Nest consumers는
  계획된 검증 범위에서 제외했다. adapter record Date ownership은 계획대로 AK-M16에 남겼다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M05 파일만 검토·commit해 별도 P1 PR로 merge한 뒤 AK-M06A에서 현재 tenant ID
  producer/consumer 형태를 목록화하고 reject/trim/preserve 정책 ADR을 작성한다.
```

### AK-M06A 종료 인계

```text
Task: AK-M06A
State: DONE
Start ref / end ref: f3a1bed / f3a1bed + session worktree (commit·PR·release 없음)
Changed files: docs/2026-08-30-tenant-identity-contract-adr.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: tenant ID는 1–255 UTF-16 code unit exact string이며 empty, runtime non-string,
  leading/trailing whitespace를 reject한다. internal whitespace/Unicode는 보존하고 trim/coerce,
  case fold, normalization하지 않는다. API Keys는 request.apiKey producer, RBAC는 trusted tenant
  reconciliation/authorization을 소유한다. legacy row는 coordinated migration 또는 key 재발급한다.
Commands and exact results:
  current source/storage/RBAC 0.2.1 tarball inventory => API Keys exact storage/list와 RBAC
    apiKeyContext-first trim/number-coerce 차이를 확인
  ADR relative link check => PASS; packaged README link는 package files 밖 문서이므로 absolute GitHub link
Unverified paths and reason: 없음; 이 task는 ADR·inventory·migration checklist만 소유한다.
External PR/release evidence: npm @nestarc/rbac latest 0.2.1 metadata를 확인했으며 M01/M02 미포함.
Next exact action: API Keys producer 구현을 유지하고 RBAC-M01/M02 포함 published artifact를 기다린다.
```

### AK-M06B 종료 인계

```text
Task: AK-M06B
State: BLOCKED
Start ref / end ref: f3a1bed / f3a1bed + session worktree (commit·PR·release 없음)
Changed files: src/input-validation.ts, src/input-validation.test.ts, src/api-keys.service.ts,
  src/index.ts, test/integration/api-keys.service.test.ts, scripts/test-rbac-consumer.js,
  package.json, scripts/test-strict-consumer.js, README.md, CHANGELOG.md,
  docs/2026-08-30-tenant-identity-contract-adr.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: ADR exact tenant를 create/list/storage/event/context에 사용하고 custom storage의
  invalid record는 repair하지 않고 fail closed한다. packed RBAC consumer는 candidate와 registry
  artifact identity를 검증하며 sibling checkout을 사용하지 않는다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    => expected FAIL; invalid tenant 6 cases failed, remaining 68 passed
  external RED: npm run test:consumer:rbac -- --rbac 0.2.1
    => exact packages installed; FAIL because RBAC resolved conflicting request.apiKeyContext
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 12 suites, 179 tests PASS
  fresh Jest coverage (/tmp/api-keys-m06-coverage-20260830-01) => statements 87.45%,
    branches 82.82%, functions 83.83%, lines 87.21%
  npm run build => PASS
  npm_config_cache=/tmp/api-keys-m06-npm-cache npm pack --dry-run --json
    => PASS, 48 entries, sha512-zs5jigyIUbMBdx6tJGeYJ0BKNC8ZgqpyxqtOMG+dtAQapoYPvpMeWyeXP0W951eEe9r6OV6hRYUj3SZSjcCAQw==
  npm run bench:smoke => PASS; local |unknown-known invalid| p50 0.3µs, bound 500µs
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS
Unverified paths and reason: canonical/trusted conflict PASS와 CI/release persistent gate는
  RBAC-M01/M02 포함 published version이 없어 불가능하다. 0.2.1 gate를 workflow에 넣으면 항상 RED다.
External PR/release evidence: @nestarc/rbac@0.2.1, gitHead 69bf0e192865566e67627f9cf5c1c35fcb458103,
  registry integrity sha512-9dqvRNC7sI3IKO/gUf6pRKbK4MSVvKXs0YgahYDsJkHZvhTMflYzaS5H9CnzViLMWuHV6eVmsXkWY8J52PVJ1w==.
Next exact action: RBAC-M01/M02 포함 exact version publish 뒤 test:consumer:rbac PASS, CI/release 연결,
  profile A/B/D 재실행 후 DONE 처리한다.
```

### AK-M06C 종료 인계

```text
Task: AK-M06C
State: DONE
Start ref / end ref: f3a1bed / f3a1bed + session worktree (commit·PR·release 없음)
Changed files: src/api-keys.service.ts, src/storage/api-key-storage.interface.ts,
  src/storage/in-memory-storage.ts, src/storage/prisma-storage.ts, src/index.ts,
  test/contract/storage-contract.ts, test/integration/api-keys.service.test.ts,
  scripts/test-strict-consumer.js, README.md, CHANGELOG.md,
  docs/2026-08-30-tenant-identity-contract-adr.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: additive revokeForTenant/rotateForTenant이 expected tenant를 atomic adapter
  mutation에 bind한다. mismatch와 missing은 api_key_record_not_found이며 custom capability 부재는
  ID-only fallback 없이 fail-fast한다. 기존 ID-only API는 trusted system-wide management용으로 유지한다.
Commands and exact results:
  InMemory contract + service tenant A/B negative/positive table => PASS in 12 suites/179 tests
  Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 => 각 1 suite, 20 tests PASS
  first parallel Prisma 6/7 attempt => Prisma 7 20 PASS, Prisma 6 generated-path collision FAIL;
    documented shared generated path 때문에 Prisma 6을 단독 재실행해 20 PASS
  npm run test:consumer:strict:legacy => exact Nest 10.4.20/Prisma 6.19.3 packed management PASS
  npm run test:consumer:strict:modern => exact Nest 11.2.1/Prisma 7.10.0 packed management PASS
  profile A/B/D 결과는 AK-M06B 인계와 동일하게 PASS
Unverified paths and reason: remote GitHub CI/release는 push 전이라 미실행. tenant-bound built-in
  path는 전체 local matrix와 packed consumer에서 검증했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M06C는 완료. M06B external prerequisite 충족 뒤 packed RBAC gate를 활성화한다.
```

### AK-M07A/B 종료 인계

```text
Task: AK-M07A
State: DONE
Start ref / end ref: f3a1bed / f3a1bed + session worktree (commit·PR·release 없음)
Changed files: src/types.ts, src/payload-copy.ts, src/api-keys.service.ts,
  src/api-keys.guard.ts, src/api-keys.module.ts, src/api-keys.module.test.ts,
  test/integration/api-keys.service.test.ts, test/integration/api-keys.guard.test.ts,
  scripts/test-strict-consumer.js, README.md, CHANGELOG.md,
  docs/2026-08-30-request-authorization-telemetry-adr.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: verification은 supplied credential의 format/secret/lifecycle 성공 여부이고,
  authorization은 missing credential과 environment/IP/scope request policy를 포함한다. Guard 403은
  verification success와 별도 authorization denial이며 accepted usage는 아니다. missing은
  auth_failed/verification metric을 만들지 않는다. request denial event/metric은 raw key, IP,
  prefix, tenant/key ID, scope, route를 포함하지 않는다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    test/integration/api-keys.guard.test.ts => expected FAIL; 2 suites failed to compile because
    ApiKeyAuthorizationMetric, authorizeRequest(), onAuthorizationMetric contract가 없었음
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 12 suites, 184 tests PASS
  fresh Jest coverage (/tmp/api-keys-m07-coverage.No3g85) => statements 87.91%,
    branches 83.02%, functions 85.04%, lines 87.70%; guard statements/lines 100%
  npm run test:consumer:http:nest10 => exact Nest 10.4.20 HTTP Guard PASS
  npm run test:consumer:http:nest11 => exact Nest 11.2.1 HTTP Guard PASS
  npm run build => PASS
  npm pack --dry-run --json => PASS, 48 entries,
    sha512-/CD8EZyQxHiELdgPUcLGnDT9Lzy2UTPnFGrbso8sNWomop63dVn/+nXuHTDfTy/rBLPB7W780LejwJbSZ0BmVg==
  npm run bench:smoke => PASS; local |unknown-known invalid| p50 0.1µs, bound 500µs
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release는 push 전이라 미실행. storage/schema를
  변경하지 않아 Prisma real DB matrix는 재실행하지 않았고 service/Guard InMemory contract와
  packed Nest consumers로 이 작업의 telemetry 경계를 검증했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M14에서 legacy onAuthFailed sync throw/thenable/async reject와 reporting
  callback 실패가 원래 ApiKeyError 및 AK-M07A telemetry를 바꾸지 않는 RED table을 추가한다.
```

```text
Task: AK-M07B
State: DONE
Start ref / end ref: f3a1bed / f3a1bed + session worktree (commit·PR·release 없음)
Changed files: AK-M07A와 동일
Contract decision: verify(rawKey)는 기존 credential-only API로 유지한다. additive
  authorizeRequest()가 required environment/scope와 explicit/resolved client IP를 집행하며 Guard와
  custom transport가 같은 primitive를 사용한다. 제한 key의 client IP가 없으면 fail closed한다.
Commands and exact results:
  service-only/request-aware IP RED와 Guard missing/environment/IP/scope table => 12 suites,
    184 tests PASS
  npm run test:consumer:strict:legacy => exact Nest 10.4.20/Prisma 6.19.3 packed direct consumer PASS
  npm run test:consumer:strict:modern => exact Nest 11.2.1/Prisma 7.10.0 packed direct consumer PASS
  Nest 10/11 HTTP packed consumers, profile A/B/D => AK-M07A 인계 결과와 같이 PASS
Unverified paths and reason: remote GitHub CI/release는 push 전이라 미실행. trusted proxy 자동
  설정은 비범위이며 default resolver는 계속 request.ip만 사용한다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M07A/B 파일을 같은 request-boundary 변경으로 검토·commit한 뒤 AK-M14를 진행한다.
```

### AK-M14 종료 인계

```text
Task: AK-M14
State: DONE
Start ref / end ref: 3454cb6 / 3454cb6 + session worktree (commit·PR·release 없음)
Changed files: src/api-keys.service.ts, src/api-keys.module.ts,
  test/integration/api-keys.service.test.ts, README.md, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: legacy onAuthFailed는 source-compatible하게 유지하지만 structured
  api_key.auth_failed onEvent로 대체하도록 deprecate한다. observer와 error reporter의 동기 예외,
  Promise/PromiseLike rejection은 원래 인증/telemetry 결과와 process rejection 경계에서 격리한다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    => 1 suite, 4 tests FAIL; sync throw가 원래 오류를 대체하고 thenable 미관찰 및 async rejection 발생
  npm test -- --runInBand test/integration/api-keys.service.test.ts
    => 1 suite, 89 tests PASS
  npm run lint => PASS
  ./node_modules/.bin/tsc --noEmit -p tsconfig.build.json => PASS
  npm test -- --runInBand => 12 suites, 188 tests PASS
  fresh Jest coverage (/tmp/api-keys-m14-coverage.YGi5SF) => statements 88.23%,
    branches 83.17%, functions 86.95%, lines 87.86%
  npm run build => PASS
  npm run test:consumer:http:nest10 => exact Nest 10.4.20 default HTTP filter PASS
  npm run test:consumer:http:nest11 => exact Nest 11.2.1 default HTTP filter PASS
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release는 push 전이라 미실행. storage/schema/지원
  matrix를 변경하지 않아 Prisma real DB와 strict Prisma consumers는 재실행하지 않았다. 최초
  sandbox packed-consumer 실행은 registry network 제한으로 dependency version을 확인하지 못해
  ERESOLVE했으며 승인된 network 재실행에서 두 exact Nest lane 모두 PASS했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M14 변경 파일을 검토·commit한 뒤 AK-M08A의 PR #16/#17/#20 base/check/diff를
  다시 조회하고 #16 → #17 → #20 순서의 재베이스 필요성을 판단한다.
```

### AK-M08A 종료 인계

```text
Task: AK-M08A
State: DONE
Start ref / end ref: local 7a75426, remote a24fe1d / local 055daa5, remote f00ce8f2
Changed files: remote PR #16 .github/workflows/ci.yml, .github/workflows/release.yml;
  PR #17 package-lock.json; PR #20 package.json, package-lock.json. Local merge also preserved
  the previously added HTTP consumer workflow jobs.
Contract decision: green PR을 #16 → #17 → #20 순서로 처리한다. 각 lockfile PR은 앞선 merge 뒤
  update-branch하고 동일한 Node 20/22 및 Prisma 5/6/7 check를 새 head에서 다시 통과해야 한다.
Commands and exact results:
  PR #16 head a92f4faf, run 33293341075 => 5 checks PASS; squash merge 306be401
  PUT pulls/17/update-branch => head 77676253, base 306be401
  gh run watch 33311083763 --exit-status => Node 20/22 + Prisma 5/6/7 PASS
  PR #17 squash merge => b3dbf139
  PUT pulls/20/update-branch => head 95ca8f4a, base b3dbf139
  gh run watch 33311145802 --exit-status => Node 20/22 + Prisma 5/6/7 PASS
  PR #20 squash merge => f00ce8f2
  main push runs 33311069629 / 33311139431 / 33311196114 => 모두 success
  git merge --no-edit origin/main => clean ort merge 055daa5; no conflict
Unverified paths and reason: 없음. 세 PR 모두 최신 순차 base에서 required source/DB checks를 통과했다.
External PR/release evidence: https://github.com/nestarc/api-keys/pull/16,
  https://github.com/nestarc/api-keys/pull/17, https://github.com/nestarc/api-keys/pull/20.
Next exact action: Nest common/core/testing 11.2.x exact-compatible trio의 clean install을 만든다.
```

### AK-M08B 종료 인계

```text
Task: AK-M08B
State: DONE
Start ref / end ref: 055daa5 / 055daa5 + session worktree (commit·PR·release 없음)
Changed files: package.json, package-lock.json, scripts/test-strict-consumer.js,
  scripts/test-rbac-consumer.js, .github/workflows/ci.yml, .github/workflows/release.yml,
  README.md, CHANGELOG.md, docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: root dev baseline은 common/core/testing `~11.2.3` trio다. source suite에 필요 없는
  platform package는 root에 추가하지 않고 exact Nest 10/11 HTTP consumer가 각 platform package를
  독립 설치한다. Nest 10.4.20은 legacy strict/HTTP lane으로 유지한다.
Commands and exact results:
  npm ci => 428 packages clean install, audit 0
  npm run lint + tsc --noEmit + npm test -- --runInBand => PASS, 12 suites/188 tests
  npm run test:consumer:strict:legacy => exact Nest 10.4.20/Prisma 6.19.3 PASS
  npm run test:consumer:strict:modern => exact Nest 11.2.3/Prisma 7.10.0 PASS
  npm run test:consumer:http:nest10 => exact Nest 10.4.20 default HTTP filter PASS
  npm run test:consumer:http:nest11 => exact Nest 11.2.3 default HTTP filter PASS
  Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 => 각 1 suite, 20 tests PASS
  npm explain file-type => file-type@21.3.4 through @nestjs/common@11.2.3; audit finding 없음
  npm audit --omit=dev --json + npm audit --json => production/full vulnerabilities 0
Unverified paths and reason: 변경 head의 remote CI/release는 push 전이라 미실행. local source,
  packed Nest consumers, real PostgreSQL matrix를 모두 실행했다.
External PR/release evidence: 없음; 단독 common major PR #18은 사용하지 않았다.
Next exact action: ESLint 10/parser/plugin/flat config를 하나의 호환 toolchain으로 정렬한다.
```

### AK-M08C 종료 인계

```text
Task: AK-M08C
State: DONE
Start ref / end ref: 055daa5 / 055daa5 + session worktree (commit·PR·release 없음)
Changed files: .eslintrc.cjs (removed), .eslintignore (removed), eslint.config.cjs,
  package.json, package-lock.json, CHANGELOG.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: ESLint 10 flat config가 기존 eslint:recommended,
  @typescript-eslint/recommended, Node/Jest globals, `_` argument ignore 의미를 보존한다. locked
  ESLint/@eslint/js Node floor `^20.19.0 || ^22.13.0 || >=24`는 AK-M09 입력으로만 기록하고
  공개 engines.node는 이 작업에서 바꾸지 않는다.
Commands and exact results:
  최초 simultaneous npm install => expected ERESOLVE; 기존 node_modules의 ESLint 8 peer tree와
    direct @eslint/js 10을 npm 11이 먼저 충돌 판정. force/legacy-peer-deps/override 사용 없음
  ESLint/parser/plugin 정상 교체 후 direct @eslint/js 고정, npm ci => PASS
  final root lock metadata 갱신 중 optional WASM peer closure EUSAGE를 발견해 npm install로
    generated lock entry를 정규화; 최종 npm ci => 428 packages, audit 0, PASS
  installed: eslint 10.9.1, @eslint/js 10.0.1, parser/plugin 8.68.0, globals 17.11.0
  npm run lint => PASS; tsc --noEmit => PASS; 12 suites/188 tests PASS
  fresh Jest coverage (/tmp/api-keys-m08-coverage.M0YW0N) => statements 88.23%,
    branches 84.10%, functions 86.95%, lines 87.86%
  npm run build => PASS
  npm pack --dry-run --json with session cache => PASS, 48 entries,
    sha512-zajAjYUnGPEpgbMkYRxrLLE9DPKiZWLR5WpTeOf4/ljx/rNrhhx3XHBTlEai+TQQsSm3wrLZSzGu3l9VL9DPUg==
  npm run bench:smoke => PASS; |unknown-known invalid| p50 0.3µs, bound 500µs
  profile C exact Prisma and Nest consumer results => AK-M08B 인계와 같이 PASS
  npm audit --omit=dev --json + npm audit --json => production/full vulnerabilities 0
  git diff --check => PASS after final documentation update
Unverified paths and reason: 변경 head의 remote CI/release는 push 전이라 미실행. Node 20 제거와
  exact Node 22 minimum 검증은 의도적으로 AK-M09가 소유한다.
External PR/release evidence: 없음; 실패한 단독 PR #19/#21을 현재 worktree의 통합 변경으로 대체했다.
Next exact action: AK-M09에서 Node 22 최소 patch와 Node 24로 profile A/B/C/D를 실행하고
  engines/types/CI/release/README 지원 계약을 정렬한다.
```

### AK-M09 종료 인계

```text
Task: AK-M09
State: DONE
Start ref / end ref: fa4093f / fa4093f + session worktree (commit·PR·release 없음)
Changed files: package.json, package-lock.json, scripts/test-strict-consumer.js,
  .github/workflows/ci.yml, .github/workflows/release.yml, README.md, CHANGELOG.md,
  docs/2026-08-30-node-support-policy-adr.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: engines.node는 exact 검증된 두 major만 포함하는
  ^22.13.0 || ^24.0.0이다. Node 22.13.0은 최소/source/DB/consumer/release-verify lane,
  Node 24는 source/publish lane이다. @types/node 하한은 ^22.13.0이며 packed strict consumer가
  engine metadata를 고정한다. Node 20 제거는 planned pre-1.0 0.4.0 breaking migration이고
  Node 26 등 새 major는 명시적 matrix evidence 전에는 지원하지 않는다.
Commands and exact results:
  exact Node 22.13.0 npm ci => 428 packages, vulnerabilities 0
  Node 22.13.0 profile A => lint/typecheck PASS, 12 suites/188 tests PASS
  Node 22.13.0 profile B (/tmp/api-keys-m09-final-node2213-coverage.gMuxei) =>
    statements 88.23%, branches 84.10%, functions 86.95%, lines 87.86%
  Node 22.13.0 profile C => Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 each
    1 suite/20 tests PASS; exact Nest 10.4.20/11.2.3 strict and HTTP consumers PASS
  Node 22.13.0 profile D => build PASS, pack 48 entries
    sha512-YrLsp69ZeAg5EfZ8StQnlx1UeGr89G2jOBb/FfZWiq98RU86YvqdSLWzQtaE+y5YKz8yZEubYCRtx3oXxBmofg==,
    benchmark |unknown-known invalid| p50 0.5µs below 500µs, production audit 0
  Node 24.11.1 profile A => lint/typecheck PASS, 12 suites/188 tests PASS
  Node 24.11.1 profile B (/tmp/api-keys-m09-final-node24-coverage.7RFFf5) =>
    statements 88.23%, branches 84.10%, functions 86.95%, lines 87.86%
  Node 24.11.1 profile C => Prisma 5.22.0/6.19.3/7.10.0 PostgreSQL 16 each
    1 suite/20 tests PASS; exact Nest 10.4.20/11.2.3 strict and HTTP consumers PASS
  Node 24.11.1 profile D => build PASS, session-cache pack same 48 entries/integrity,
    benchmark |unknown-known invalid| p50 0.1µs below 500µs, production audit 0
  engine boundary assertion => 22.12.0 false, 22.13.0 true, 24.0.0 true, 26.0.0 false
  npm audit --json => full vulnerabilities 0
  final exact Node 22.13.0 and Node 24.11.1 legacy/modern strict consumers => PASS with packed
    engine metadata assertion
Unverified paths and reason: 변경 head의 remote GitHub CI/release는 push 전이라 미실행했다.
  로컬에서는 workflow와 동일한 exact minimum/24 source profile 및 minimum DB/consumer graph를
  모두 실행했다. Node 20은 의도적으로 제거했으며 Node 26은 비지원 계약이라 실행하지 않았다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M10에서 Nest/Prisma/PostgreSQL/no-Prisma 선언·증거 표를 만들고 PostgreSQL
  14 boundary와 optional Prisma 미설치 packed consumer를 RED evidence로 시작한다.
```

### AK-M10 종료 인계

```text
Task: AK-M10
State: DONE
Start ref / end ref: 2488896 / 2488896 + session worktree (commit·PR·release 없음)
Changed files: scripts/test-prisma-e2e.js, scripts/test-postgres-matrix.js,
  scripts/test-no-prisma-consumer.js, package.json, .github/workflows/ci.yml,
  .github/workflows/release.yml, README.md, CHANGELOG.md,
  docs/2026-08-30-compatibility-evidence-policy.md,
  docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: full Cartesian matrix 대신 integration-boundary evidence를 유지한다.
  Nest 10.4.20/Prisma 6.19.3와 Nest 11.2.3/Prisma 7.10.0은 대표 diagonal이며, 두 surface를
  결합하는 변경이나 재현된 실패가 있을 때만 off-diagonal을 추가한다. PostgreSQL 14 하한은
  Prisma 5.22.0, PostgreSQL 16 current는 Prisma 5.22.0/6.19.3/7.10.0 모두로 검증한다.
  Prisma optional peer는 Prisma가 전혀 없는 별도 Nest 11.2.3 packed root consumer가 증명한다.
Commands and exact results:
  npm run test:consumer:no-prisma => exact Nest 11.2.3 strict install, skipLibCheck:false typecheck,
    root import, in-memory create/verify PASS; consumer lock/runtime에 @prisma/client 없음
  최초 npm run test:e2e:postgres-matrix => PostgreSQL 14/Prisma 5와 PostgreSQL 16/Prisma 5
    각 1 suite/20 tests PASS 뒤 PostgreSQL 초기화 경합 발견; pg_isready 대신 실제
    psql SHOW server_version_num 성공을 readiness/major 증거로 사용하도록 runner 보강
  최종 npm run test:e2e:postgres-matrix => PostgreSQL 14/Prisma 5.22.0 및 PostgreSQL 16/
    Prisma 5.22.0, 6.19.3, 7.10.0 각각 1 suite/20 tests PASS; disposable container 잔존 없음
  npm run test:consumer:strict:legacy => exact Nest 10.4.20/Prisma 6.19.3 PASS
  npm run test:consumer:strict:modern => exact Nest 11.2.3/Prisma 7.10.0 PASS
  npm run test:consumer:http:nest10 + nest11 => default HTTP contract 각각 PASS
  npm run lint + tsc --noEmit => PASS; npm test -- --runInBand => 12 suites/188 tests PASS
  node --check on three matrix/consumer scripts => PASS; CI/release YAML parse => PASS
  npm run build => PASS
  npm pack --dry-run --json --cache /tmp/api-keys-m10-pack.JUUsx3 => 48 entries PASS,
    sha512-eKXVqciUWLpyoUtrT2M8KrhiKdt8j4CsAd2vISO1hmZKMXEtBC5ZuRlQMF2HiJ8P628vwYoVaY72kQ/PjuBrdw==
  npm run bench:smoke => PASS; |unknown-known invalid| p50 0.1µs below 500µs
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS after final plan update
Unverified paths and reason: 변경 head의 remote GitHub CI/release는 push 전이라 미실행했다.
  ignored test/e2e/generated/prisma-client는 matrix가 exact Prisma 7.10.0 client로 마지막 재생성했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M11에서 fresh coverage와 real DB adapter gate 책임을 분리하고 threshold를
  제안한 뒤 의도적 regression이 CI gate를 실패시키는지 검증한다.
```

### AK-M11 종료 인계

```text
Task: AK-M11
State: DONE
Start ref / end ref: 7e1dd16 / 7e1dd16 + session worktree (commit·PR·release 없음)
Changed files: coverage-thresholds.json, jest.config.ts, scripts/check-coverage.js,
  scripts/test-coverage.js, package.json, .github/workflows/ci.yml,
  .github/workflows/release.yml, docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: Jest는 prisma-storage.ts를 제외하지 않은 fresh 전체 global
  statements/branches/functions/lines 88/84/86/87 floor를 강제한다. 동일 run의 JSON summary에서
  Guard 100/83/100/100, service 93/89/100/93, errors 100/100/100/100, key format
  97/92/100/97을 별도 checker가 강제한다. Prisma adapter 기능 증거는 이 수치를 부풀리는
  unit 제외가 아니라 별도 필수 PostgreSQL 14/16 + Prisma 5/6/7 real DB job이 담당한다.
Commands and exact results:
  npm run test:coverage -- --coverageDirectory=/tmp/api-keys-m11-coverage.PbZCYF =>
    12 suites/188 tests PASS; global 88.23/84.10/86.95/87.86와 4 critical-file floor PASS;
    prisma-storage.ts 6.06/0/7.69/6.06으로 포함
  modified JSON summary의 service lines 92.99 < 93 => checker expected exit 1
  temporary Jest global statements 100 > 88.23 => Jest expected exit 1
  npm run lint + tsc --noEmit + npm test -- --runInBand + npm run build => PASS,
    12 suites/188 tests PASS
  npm run test:e2e:postgres-matrix => PostgreSQL 14/Prisma 5.22.0 및 PostgreSQL 16/
    Prisma 5.22.0, 6.19.3, 7.10.0 각각 1 suite/20 tests PASS
  npm run test:consumer:strict:legacy + strict:modern + no-prisma => exact Nest 10.4.20/
    Prisma 6.19.3, Nest 11.2.3/Prisma 7.10.0, Nest 11.2.3/no-Prisma 모두 PASS
  npm run test:consumer:http:nest10 + nest11 => default HTTP contract 각각 PASS
  node --check on coverage scripts, Prettier check, CI/release YAML parse, git diff --check => PASS
Unverified paths and reason: 변경 head의 remote GitHub CI/release와 실제 artifact upload는 push 전이라
  미실행했다. 로컬에서 workflow와 동일한 coverage/DB/consumer commands와 artifact 입력 파일 생성을
  검증했다. ignored test/e2e/generated/prisma-client는 matrix가 exact Prisma 7.10.0으로 마지막 생성했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M15에서 expired/rotated/revoked key의 현재 default list 결과표를 만들고
  active/expired/grace 제품 계약을 결정한다.
```

### AK-M12 종료 인계

```text
Task: AK-M12
State: DONE
Start ref / end ref: 5747de4 / 5747de4 + session worktree (commit·PR·release 없음)
Changed files: src/types.ts, src/api-keys.service.ts,
  test/integration/api-keys.service.test.ts, scripts/test-strict-consumer.js, README.md,
  CHANGELOG.md, docs/2026-08-30-p0-p3-maintenance-work-plan.md
Contract decision: list()는 storage ApiKeyRecord[]를 explicit ApiKeySummary[]로 projection해
  hash/pepperVersion을 runtime과 declaration에서 제외한다. storage/verification/rotation 계약과
  includeRevoked filter는 그대로 유지한다. M12는 filter 정책과 독립적으로 완료하며 M15의
  active/expired/grace 결정은 별도 DECISION으로 남긴다. public return type narrowing은 계획된
  pre-1.0 0.4.0 breaking change다.
Commands and exact results:
  RED: npm test -- --runInBand test/integration/api-keys.service.test.ts
    -t "serialization-safe public summary" => expected FAIL; hash와 pepperVersion 두 field 노출
  npm run lint + tsc --noEmit + npm test -- --runInBand => PASS, 12 suites/189 tests
  npm run test:coverage -- --coverageDirectory=/tmp/api-keys-m12-coverage.3sM9bv =>
    global statements 88.27%, branches 84.01%, functions 87.17%, lines 87.90%;
    global 및 4 critical-file floor PASS
  NPM_CONFIG_CACHE=/tmp/api-keys-m12-npm-cache npm run test:consumer:strict:legacy =>
    exact Nest 10.4.20/Prisma 6.19.3 packed declaration/runtime PASS
  NPM_CONFIG_CACHE=/tmp/api-keys-m12-npm-cache npm run test:consumer:strict:modern =>
    exact Nest 11.2.3/Prisma 7.10.0 packed declaration/runtime PASS
  npm run build => PASS
  npm pack --dry-run --json --cache /tmp/api-keys-m12-pack-cache => 48 entries,
    sha512-UwsNLIHkZt6C/IMofQR0D+zweEvfyOI4jvNJvae52OG7TxSwUkKR3yRkwHa943c/jcEdTmCIWaME+6YEB2Ekkg==
  npm run bench:smoke => PASS; |unknown-known invalid| p50 0.7µs below 500µs
  npm audit --omit=dev --json => production vulnerabilities 0
  git diff --check => PASS
Unverified paths and reason: remote GitHub CI/release는 push 전이라 미실행. storage/schema/filter를
  변경하지 않아 PostgreSQL matrix와 no-Prisma/HTTP consumers는 재실행하지 않았다. 첫 packed
  consumer는 sandbox의 read-only 사용자 npm cache로 EPERM이었고 작업 전용 /tmp cache와 승인된
  registry network에서 exact legacy/modern lane을 모두 통과했다.
External PR/release evidence: 없음; 사용자 요청 범위에서 commit/PR/publish는 수행하지 않았다.
Next exact action: AK-M15에서 expired/rotated/revoked key의 현재 default list 결과표를 만들고
  active/expired/grace 제품 계약을 결정한다.
```
