# Prisma peer dependency compatibility 작업 계획

- 작성일: 2026-08-23 (Asia/Seoul)
- 기준 패키지: `@nestarc/api-keys@0.3.0`
- 대상 릴리스: `@nestarc/api-keys@0.3.1`
- 관련 저장소: `api-keys`, `nestjs-tenancy`
- 목적: Prisma 6을 사용하는 Nestarc ecosystem fixture가 `--legacy-peer-deps` 없이 strict install되도록 패키지 메타데이터와 호환성 검증을 정리한다.

## 작업 결과 (2026-08-23)

상태: **`0.3.1` npm 배포 및 peer metadata 검증 완료**

- `PrismaApiKeyStorage`의 기존 공통 storage contract와 Prisma 전용 field mapping,
  tenant isolation, transaction rollback 사례를 PostgreSQL 16에서 실행하도록 추가했다.
- Prisma CLI/client 5.22.0과 6.19.3을 동일 버전으로 맞춘 두 lane이 각각 11개
  E2E test를 통과했다.
- optional `@prisma/client` peer를 `^5.0.0 || ^6.0.0`으로 확대했고 Prisma 7은
  지원 범위에 포함하지 않았다.
- 실제 `npm pack` tarball과 Prisma 6.19.3을 독립 consumer에 strict 설치하고 package
  root 및 `PrismaApiKeyStorage` export를 확인했다. `--legacy-peer-deps`와 `--force`는
  사용하지 않았다.
- API Keys CI와 release workflow에 Prisma 5/6 PostgreSQL matrix 및 strict consumer
  gate를 추가했다.
- `nestjs-tenancy` ecosystem runner에서 `--legacy-peer-deps`와 관련 주석을 제거하고,
  로컬 API Keys tarball을 사용한 전체 ecosystem E2E 3개 test를 strict install로
  통과했다.
- `@nestarc/api-keys@0.3.1`이 npm `latest`로 배포됐고 registry manifest의 optional
  `@prisma/client` peer가 `^5.0.0 || ^6.0.0`인 것을 확인했다.
- 형제 저장소 탐색을 비활성화한 `nestjs-tenancy` published-only 경로에서 실제
  `@nestarc/api-keys@0.3.1` strict install, Prisma 6 client 생성, installed artifact
  version, tenant propagation 및 fail-closed를 포함한 전체 3개 E2E test가 통과했다.

실행 결과:

```text
API Keys lint/build                       PASS
API Keys unit/integration                 11 suites, 81 tests PASS
Prisma 5.22.0 PostgreSQL storage E2E      1 suite, 11 tests PASS
Prisma 6.19.3 PostgreSQL storage E2E      1 suite, 11 tests PASS
Prisma 6.19.3 strict tarball consumer     PASS
npm pack --dry-run                        41 files PASS
Tenancy ecosystem runner unit contract    1 suite, 4 tests PASS
Tenancy lint/build                        PASS
Tenancy unit/integration                  47 suites, 554 tests PASS
Tenancy strict ecosystem E2E              1 suite, 3 tests PASS
npm registry latest/version               0.3.1 PASS
npm registry optional Prisma peer         ^5.0.0 || ^6.0.0 PASS
Published-only strict ecosystem E2E        1 suite, 3 tests PASS
```

### 배포 후 확인 결과

2026-08-23 KST 기준 npm registry에서 다음을 직접 확인했다.

```text
version                              0.3.1
dist-tags.latest                     0.3.1
peerDependencies.@prisma/client      ^5.0.0 || ^6.0.0
peerDependenciesMeta optional        true
published at                         2026-08-23T13:41:13.357Z
```

따라서 API Keys의 배포와 package metadata 작업은 완료됐다. tenancy fixture의 artifact
version 기대값도 `0.3.1`로 갱신했고, 실제 published package만 사용하는 strict ecosystem
lane 전체가 통과했다.

## 1. 작업 전 상태

작업 시작 시 `@nestarc/api-keys@0.3.0`의 `package.json`은 Prisma client를 optional peer dependency로 제공하지만 지원 범위를 Prisma 5로만 선언했다.

```json
{
  "peerDependencies": {
    "@prisma/client": "^5.0.0"
  },
  "peerDependenciesMeta": {
    "@prisma/client": {
      "optional": true
    }
  },
  "devDependencies": {
    "@prisma/client": "^5.10.0"
  }
}
```

반면 `nestjs-tenancy`의 ecosystem fixture는 Nestarc 패키지들의 공통 범위인 Prisma `6.19.3`을 사용했다.

```text
@nestarc/api-keys@0.3.0        optional peer: @prisma/client ^5
ecosystem fixture              dependency:    @prisma/client 6.19.3
strict npm install             result:        ERESOLVE
```

optional peer는 패키지 설치 자체를 필수로 만들지 않을 뿐, 소비자가 해당 패키지를 설치했을 때 선언한 버전 범위 충돌까지 무시하지는 않는다. 이 때문에 당시 `nestjs-tenancy/scripts/test-ecosystem-e2e.js`는 명시적으로 `npm install --legacy-peer-deps`를 사용했다.

## 2. 런타임 관찰 결과

현재 Nestarc ecosystem E2E에서는 다음 런타임 경로가 Prisma 6.19.3과 함께 통과한다.

```text
API key 검증 및 tenant identity 결정
→ tenancy ALS context
→ RBAC subject/tenant 검사
→ Prisma transaction-local RLS
→ outbox
→ jobs context 복원
→ tenant webhook delivery
```

다만 이 E2E는 API Keys의 `PrismaApiKeyStorage`를 사용하지 않는다. 따라서 이 결과만으로 API Keys Prisma adapter 전체가 Prisma 6을 지원한다고 선언해서는 안 된다.

현재 adapter는 generated Prisma type을 직접 요구하지 않고 아래와 같은 구조적 `PrismaLike` 계약만 사용한다.

- `apiKey.create()`
- `apiKey.findUnique()`
- `apiKey.findMany()`
- `apiKey.update()`
- 선택적 batch `$transaction(operations)`

Prisma 5와 6 모두 이 형태를 제공할 가능성이 높지만, 실제 client로 adapter contract를 실행해 확인한 뒤 peer 범위를 넓혀야 한다.

## 3. 목표 지원 계약

이번 작업의 최소 목표는 다음과 같다.

```json
{
  "peerDependencies": {
    "@prisma/client": "^5.0.0 || ^6.0.0"
  }
}
```

- Prisma 5: 기존 지원 회귀 방지
- Prisma 6: 신규 지원 및 Nestarc ecosystem strict install 보장
- Prisma 7: 이번 작업에서 실제 검증하기 전에는 지원 범위에 추가하지 않음
- optional 속성: in-memory/custom storage 소비자를 위해 유지

단순히 peer 문자열만 수정하는 것은 완료로 보지 않는다. Prisma 5/6 런타임 검증과 strict consumer install이 함께 통과해야 한다.

## 4. 구현 작업

### 4.1 Prisma adapter 실DB 테스트 추가

Prisma schema와 PostgreSQL fixture를 추가하고 실제 generated client로 `PrismaApiKeyStorage`의 공통 storage contract를 실행한다.

최소 검증 항목:

1. API key insert 및 prefix 조회
2. ID 조회
3. tenant별 목록과 revoked filtering
4. revoke 및 last-used 갱신
5. rotation의 원자적 create/update
6. transaction 실패 시 기존 key가 부분 갱신되지 않음
7. 날짜, scopes, allowed CIDR 필드 mapping
8. tenant A/B 데이터 혼합 방지

권장 파일 구성:

```text
prisma/schema.test.prisma
test/e2e/prisma-storage.e2e-spec.ts
test/e2e/jest.e2e.config.ts
scripts/test-prisma-e2e.js
```

이미 존재하는 `test/contract/storage-contract.ts`를 재사용하고, Prisma adapter에만 필요한 transaction/rollback 사례를 추가한다.

### 4.2 Prisma 5/6 CI matrix 추가

CI에 다음 버전 matrix를 추가한다.

```yaml
strategy:
  fail-fast: false
  matrix:
    prisma: ['5.22.0', '6.19.3']
```

각 lane에서 `prisma`, `@prisma/client`을 동일한 버전으로 설치하고 client 생성 및 실DB adapter E2E를 실행한다. CLI/client major가 섞이면 테스트 runner가 fail-fast하도록 하는 것이 좋다.

### 4.3 패키지 메타데이터 갱신

실DB matrix가 통과한 뒤 다음을 갱신한다.

- `package.json`
  - `peerDependencies['@prisma/client']` → `^5.0.0 || ^6.0.0`
  - optional peer 속성 유지
- `package-lock.json`
  - root package metadata가 새 peer 범위를 반영하도록 정상적인 npm 명령으로 재생성
- `README.md`
  - 검증된 Prisma 5/6 지원 범위 명시
- `CHANGELOG.md`
  - peer compatibility 확대와 검증 범위 기록

devDependency를 Prisma 6으로 즉시 고정하면 Prisma 5 회귀를 놓칠 수 있으므로, 기본 개발 버전 하나와 CI matrix의 역할을 명확히 분리한다.

### 4.4 strict consumer install 테스트 추가

배포 산출물 기준으로 검증하기 위해 다음 형태의 독립 fixture를 사용한다.

1. `npm pack`으로 API Keys tarball 생성
2. 임시 consumer directory 생성
3. tarball과 Prisma 6.19.3을 dependency로 선언
4. `npm install` 실행
5. `--legacy-peer-deps`, `--force`를 사용하지 않았는지 확인
6. package root import와 `PrismaApiKeyStorage` import 확인

이 테스트는 source workspace의 hoisting이나 기존 `node_modules`에 의존하면 안 된다.

### 4.5 tenancy ecosystem workaround 제거

새 API Keys tarball 또는 배포 버전으로 strict install이 통과한 뒤 `nestjs-tenancy`에서 다음을 수정한다.

- `scripts/test-ecosystem-e2e.js`
  - `--legacy-peer-deps` 제거
  - API Keys Prisma 5-only peer 관련 주석 제거
- `test/ecosystem/fixture/README.md`
  - 알려진 metadata gap 설명 제거 또는 해결 기록으로 변경
- `docs/tenancy-strategy-validation-2026-08-21.md`
  - P2 strict install 제약을 완료 상태로 갱신

그 후 `npm run test:e2e:ecosystem`을 다시 실행해 API key → tenancy → RBAC → RLS/outbox → jobs → webhook 경로를 보존한다.

## 5. 완료 조건

다음 조건을 모두 만족할 때 완료로 판정한다.

- [x] Prisma 5 실제 client로 `PrismaApiKeyStorage` contract 통과
- [x] Prisma 6 실제 client로 같은 contract 통과
- [x] rotation transaction/rollback 실DB 검증 통과
- [x] `@prisma/client` peer가 `^5.0.0 || ^6.0.0`으로 갱신됨
- [x] optional peer 속성이 유지됨
- [x] tarball 기반 Prisma 6 consumer의 strict `npm install` 통과
- [x] API Keys lint/unit/build 통과
- [x] Prisma 5/6 E2E가 CI 및 release 전 검증에 포함됨
- [x] tenancy ecosystem runner에서 `--legacy-peer-deps` 제거
- [x] workaround 제거 후 tenancy ecosystem E2E 통과
- [x] README/CHANGELOG에 실제 검증 범위가 기록됨
- [x] `@nestarc/api-keys@0.3.1` npm 배포 및 `latest` 확인
- [x] published artifact의 optional Prisma peer metadata 확인
- [x] published-only Prisma 6 strict install 및 핵심 runtime test 통과
- [x] tenancy fixture artifact 기대 버전을 `0.3.1`로 갱신한 뒤 published-only 전체 suite 통과

## 6. 권장 검증 명령

API Keys 저장소:

```bash
npm ci
npm run lint
npm test -- --runInBand
npm run build
npm run test:e2e:prisma
npm pack --dry-run
```

Prisma matrix는 CI와 동일하게 각 lane에서 실행한다.

```bash
npm install prisma@5.22.0 @prisma/client@5.22.0 --no-save
npm run test:e2e:prisma

npm install prisma@6.19.3 @prisma/client@6.19.3 --no-save
npm run test:e2e:prisma
```

Tenancy 저장소:

```bash
npm run lint
npm test -- --runInBand
npm run build
npm run test:e2e:ecosystem
```

## 7. 비범위 및 주의사항

- Prisma 7 지원은 peer 범위에 추가하기 전에 실 PostgreSQL과 strict consumer로 검증한다.
  아래 `0.3.2` 후보 후속이 이 조건을 충족한다.
- API Keys의 in-memory/custom storage 사용자는 Prisma 설치를 강제받지 않아야 한다.
- peer 충돌을 없애기 위해 `@prisma/client`을 runtime dependency로 옮기지 않는다.
- `--legacy-peer-deps`를 영구적인 해결책으로 문서화하지 않는다.
- Prisma adapter가 transaction을 제공받았을 때 rotation은 반드시 원자성을 유지해야 한다.
- 이 API Keys 작업은 `@nestarc/jobs` handler auto-discovery 초기화 문제와 별개였다. 이후 Jobs `0.3.1`이 application-bootstrap discovery를 구현하고 tenancy의 수동 `HandlerRegistry` workaround를 제거했으며 published-only ecosystem E2E를 통과했다.

## 8. Cross-package 후속 완료 상태

Prisma 5/6 peer metadata와 `0.3.1` 배포 작업에는 남은 항목이 없다. 별개 후속이었던
`@nestarc/jobs` handler auto-discovery 초기화 계약도 Jobs `0.3.1`과 tenancy
published-only strict lane으로 완료됐다.

### `0.3.2` Nest 11 / Prisma 7 후보 후속 (2026-08-30)

TEN-M21의 API Keys 선행 조건을 충족하도록 다음을 별도 패치 후보에 추가했다.

- Nest peer를 `^10.0.0 || ^11.0.0`, optional Prisma client peer를
  `^5.0.0 || ^6.0.0 || ^7.0.0`으로 확대했다.
- exact Prisma CLI/client/adapter `7.10.0`을 격리 prefix에 strict 설치하고 새
  `prisma-client` generator, Prisma Config, `PrismaPg`를 사용해 PostgreSQL 16 storage
  contract 1 suite/11 tests를 통과했다.
- packed `0.3.2` tarball을 exact Nest `11.2.1`/Prisma `7.10.0` consumer에
  `--strict-peer-deps`로 설치하고 installed version, peer metadata, package example,
  `skipLibCheck: false` public declaration compile, Nest application-context의 API key
  create/verify runtime을 확인했다. 대소문자를 구분하지 않고 `yes/on`까지 npm bypass
  환경 설정을 거부하며 install 명령에도 `force=false`, `legacy-peer-deps=false`를 명시한다.
- 기존 exact Nest `10.4.20`/Prisma `6.19.3` strict consumer와 Prisma 5.22.0
  PostgreSQL contract도 그대로 통과했다.
- root dev-only `@nestarc/rbac@0.2.0`의 Prisma `<7` peer 때문에 root tree에 Prisma 7을
  직접 덮어쓰는 설치는 `ERESOLVE`한다. CI/release E2E runtime을 `$RUNNER_TEMP`에
  격리해 이 무관한 dev-tree 충돌을 피하며, `--force`와 `--legacy-peer-deps`는 사용하지 않는다.

이 기록은 아직 npm 배포 완료를 뜻하지 않는다. `@nestarc/api-keys@0.3.2` publish와 registry
peer metadata 확인 후에만 TEN-M21 published-only 준비 완료 증거로 사용할 수 있다.

회귀 확인용 프롬프트:

```text
docs/prisma-peer-compatibility-plan-2026-08-23.md와
nestjs-tenancy/docs/tenancy-strategy-validation-2026-08-21.md를 읽고,
완료된 @nestarc/api-keys@0.3.1 published baseline과 @nestarc/jobs@0.3.1
application-bootstrap handler discovery 계약을 보존하세요. @nestarc/api-keys@0.3.2가
배포되면 registry peer metadata를 확인한 뒤 exact Nest 11.2.1/Prisma 7.10.0
published-only ecosystem E2E를 회귀 검증해 주세요.
```
