# Nest 12 compatibility spike ADR

- 상태: `ACCEPTED`
- 결정일: 2026-08-31 (Asia/Seoul)
- 작업: `AK-M23`
- 조사 버전: Nest 12.0.1, Prisma 7.10.0, TypeScript 5.9.3

## Context

`@nestarc/api-keys`는 현재 Nest 10/11을 peer dependency로 선언하고 CommonJS runtime과
CommonJS로 분류되는 `.d.ts`를 배포한다. Nest 12.0.1은 stable이며 `@nestjs/common`과
`@nestjs/core` package metadata가 `type: module`로 바뀌었다. 단순히 peer 범위만 Nest 12까지
확대해도 기존 strict packed consumer의 install, declaration typecheck, runtime smoke와 실제 HTTP
Guard 계약이 모두 유지되는지 확인해야 한다.

이 spike는 evidence와 지원 결정만 소유한다. 배포 metadata, build output, source import 또는
persistent CI lane은 변경하지 않는다.

## Evidence

Node 24.11.1과 npm 11.6.2에서 local package candidate를 한 번씩 pack하고, 검증할 때만 candidate의
Nest peer 범위를 임시로 `^10.0.0 || ^11.0.0 || ^12.0.0`으로 넓혔다. 임시 변경은 각 실험 뒤
복원했으며 repository 결과물에는 포함하지 않았다.

### 기존 peer 범위

exact Nest 12.0.1/Prisma 7.10.0 strict consumer는 npm strict peer resolution에서 `ERESOLVE`로
실패했다. 직접 원인은 packed package가 `@nestjs/common`과 `@nestjs/core`를
`^10.0.0 || ^11.0.0`으로 선언한 점이다. 이는 현재 공개 지원 범위에 맞는 예상된 거절이다.

### 임시 peer 완화

peer 범위만 임시로 넓히면 strict install은 성공했고 다음 exact version이 설치됐다.

- `@nestjs/common@12.0.1`
- `@nestjs/core@12.0.1`
- `@prisma/client@7.10.0`
- `typescript@5.9.3`

그러나 `module: Node16`, `moduleResolution: Node16`, `strict: true`, `skipLibCheck: false` typecheck는
실패했다.

- `dist/api-keys.guard.d.ts`, `dist/api-keys.module.d.ts`, `dist/errors.d.ts`에서 Nest ESM package를
  CommonJS declaration이 import해 `TS1479`가 발생했다.
- decorator declaration의 `import("@nestjs/common")` type reference에는 resolution-mode가 없어
  `TS1542`가 발생했다.
- CommonJS consumer source의 Nest type-only import에서도 `TS1541`이 발생했다.

consumer를 `type: module`로 바꾼 변형에서는 consumer source의 `TS1541`만 사라졌고, packed
library declaration의 `TS1479`와 `TS1542`는 그대로 남았다. 따라서 consumer 설정 변경만으로
해결할 수 없다.

같은 임시 peer 완화 candidate의 Node 24 HTTP consumer는 실제 Nest application을 시작하고 기본
exception filter와 `ApiKeysGuard`를 거치는 10개 missing/malformed/invalid/lifecycle/environment/
scope/IP case를 모두 통과했다. 이는 현재 CommonJS runtime이 이 환경에서 Nest 12와 동작한다는
긍정적 증거지만 strict public declaration contract 실패를 상쇄하지 않는다.

공식 npm metadata 재조회에서 Nest 12.0.1 exact version과 다음 경계를 확인했다.

- `@nestjs/common`과 `@nestjs/core`는 `type: module`이다.
- `@nestjs/core`의 Node engine은 `>=20`이며 common/core peer는 `^12.0.0`이다.
- `reflect-metadata`와 RxJS peer는 현재 API Keys 지원 범위와 충돌하지 않는다.

## Decision

`AK-M23`에서는 Nest peer 범위를 확대하지 않는다. 공개 지원표와 persistent CI/release matrix는
Nest 10/11을 유지하며, Nest 12는 strict declaration consumer가 통과할 때까지 지원 대상으로
표시하지 않는다.

지원 판정은 install 성공이나 runtime smoke 하나가 아니라 다음 네 증거를 모두 요구한다.

1. strict peer install과 exact installed-version assertion
2. `skipLibCheck: false` public declaration typecheck
3. Nest DI/service runtime smoke
4. 기본 HTTP pipeline의 실제 Guard contract

declaration/package 경계 변경과 peer 범위 확대는 별도 `AK-M24` 작업에서 함께 결정한다. 그 작업은
최소한 다음 선택지를 비교해야 한다.

- canonical CommonJS runtime을 유지하면서 Nest ESM type을 소비할 수 있는 declaration을 만드는 방법
- import/require 조건별 declaration 또는 output을 분리하는 방법
- package 전체를 ESM으로 이동하는 breaking migration

어느 선택도 Nest 10/11의 CommonJS/native ESM loader identity, NodeNext/no-Prisma consumer와 public
API를 약화해서는 안 된다. Nest 12 peer 범위는 Node 22.13.0과 Node 24에서 strict/type/runtime/HTTP
matrix가 모두 green인 같은 변경에서만 확대한다.

## Consequences

- Nest 12 application이 Node 24에서 runtime smoke를 통과했더라도 현재 package install과 strict
  TypeScript 소비는 지원 계약이 아니다.
- `--force`, `--legacy-peer-deps`, `skipLibCheck: true`는 호환성 증거로 인정하지 않는다.
- `AK-M24`는 declaration/package strategy에 따라 breaking change가 될 수 있으므로 ADR 결정과
  migration note를 먼저 작성한다.
- 이번 spike는 Node 22.13.0 runtime을 실행하지 않았다. 이는 현재 Nest 12를 지원하지 않기로 한
  결정에는 영향을 주지 않지만, 향후 지원 확대의 필수 검증으로 남는다.

## Rejected decisions

### Runtime smoke만 근거로 peer 범위 확대

strict consumer가 public `.d.ts`를 compile하지 못하므로 TypeScript library의 지원 계약을 충족하지
않는다.

### Consumer에 ESM 또는 `skipLibCheck` 설정 요구

ESM consumer에서도 packed library declaration 오류가 남는다. `skipLibCheck`는 오류를 숨길 뿐
배포 declaration을 고치지 않으므로 거부한다.

### AK-M23에서 packaging 구현까지 수행

현재 CommonJS canonical runtime과 explicit exports 결정은 `AK-M21`의 공개 계약이다. 이를 바꾸는
작업은 peer metadata 한 줄보다 범위와 migration 위험이 커서 별도 결정/PR로 분리한다.
