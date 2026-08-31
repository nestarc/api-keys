# Nest 12 declaration compatibility ADR

- 상태: `ACCEPTED`
- 결정일: 2026-08-31 (Asia/Seoul)
- 작업: `AK-M24`
- 대상 릴리스: planned pre-1.0 `0.4.0`
- 검증 버전: Nest 10.4.20/11.2.3/12.0.1, Prisma 6.19.3/7.10.0, TypeScript 5.9.3

## Context

Nest 12.0.1은 `@nestjs/common`과 `@nestjs/core`를 ESM package로 분류한다. API Keys의 canonical
runtime과 배포 declaration은 CommonJS로 분류되므로, peer 범위만 Nest 12까지 넓히면 packed
declaration이 Nest ESM types를 `require` 방식으로 해석해 `TS1479`와 `TS1542`로 실패했다.
consumer를 ESM으로 바꿔도 library declaration 오류는 유지됐고, Node 24 HTTP runtime만 통과했다.

`AK-M21`은 CommonJS `require`와 native ESM `import`가 같은 runtime graph와 Nest DI token/class
identity를 공유하도록 한 상태다. Nest 12 지원 때문에 별도 ESM runtime을 추가하거나 package 전체를
ESM으로 바꾸면 이 계약과 pre-1.0 migration 범위가 함께 달라진다.

## Decision

canonical CommonJS runtime과 단일 declaration graph를 유지한다. 공개 declaration에서 참조하는 Nest
types만 TypeScript의 type-only import attribute
`with { "resolution-mode": "import" }`로 ESM 해석한다.

- `ApiKeysGuard`와 `ApiKeysModule`의 공개 Nest types는 명시적 type-only import로 분리한다.
- `Reflector`는 runtime injection token을 그대로 사용하되 `@Inject(Reflector)`를 명시하고 공개
  constructor type은 ESM-resolution type alias로 선언한다.
- `ApiKeyError`는 runtime에서 기존 `HttpException`을 그대로 상속한다. declaration에는 ESM-resolution
  `typeof import()`로 typed local base constructor를 emit해 `instanceof`, Nest 기본 filter, public
  inheritance contract를 보존한다.
- metadata decorators는 `CustomDecorator` 반환형을 명시해 inference가 attribute 없는
  `import("@nestjs/common")` type을 만들지 않게 한다.
- package root의 `require`, `import`, `default`는 계속 같은 `dist/index.js`를 가리킨다. conditional
  runtime/declaration output은 추가하지 않는다.

Nest peer는 `^10.0.0 || ^11.0.0 || ^12.0.0`으로 확대한다. exact Nest 12.0.1 strict install,
`skipLibCheck: false` declaration compile, application-context runtime, 실제 HTTP Guard/default-filter
10-case를 Node 22.13.0과 Node 24에서 모두 실행하는 전용 CI/release matrix를 유지한다. 기존 Nest
10.4.20/11.2.3 strict/HTTP, CommonJS/native ESM shared identity, NodeNext/no-Prisma 소비 계약도 유지한다.

## Versioning and migration

[`resolution-mode` on `import type`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-3.html#stable-support-resolution-mode-in-import-types)은
TypeScript 5.3에서 stable이 됐다. 따라서 이 변경의 declaration을
읽는 TypeScript consumer는 5.3 이상이어야 한다. 5.2 이하 consumer는 planned pre-1.0 `0.4.0`으로
올리기 전에 compiler를 업그레이드해야 한다. persistent strict matrix는 exact TypeScript 5.9.3으로
실행하며, 이 결정은 모든 5.3+ compiler 조합을 별도 지원 matrix로 선언하지 않는다.

Nest 12 추가 자체는 peer 범위의 additive 확대지만, declaration parser floor 상승은 기존 consumer에
영향을 줄 수 있으므로 이미 breaking changes를 모으는 planned `0.4.0`에 포함한다. `0.3.x` patch로
backport하지 않는다.

## Evidence contract

영구 Nest 12 strict fixture는 기존 CommonJS declaration에서 `TS1479` 4건과 `TS1542` 2건을 먼저
재현했다. bridge 적용 뒤 exact Nest 12.0.1/Prisma 7.10.0 tree, public declaration compile, Nest DI
runtime이 Node 22.13.0/24에서 통과했다. 같은 두 Node version에서 HTTP consumer의 missing,
malformed, invalid, lifecycle, environment, scope, IP 10-case도 모두 통과했다.

`--force`, `--legacy-peer-deps`, `skipLibCheck: true`는 이 증거에 사용하지 않는다. release workflow는
한 번 만든 candidate tarball을 두 Node lane이 그대로 내려받아 strict와 HTTP command를 실행한다.

## Consequences

- Nest 10/11/12가 하나의 CommonJS runtime과 public root declaration을 공유한다.
- 별도 ESM output, conditional export graph, loader별 class/token identity 분리가 없다.
- source의 Nest value import와 public Nest type import를 의도적으로 분리해야 한다. 새 public Nest
  type이 추가될 때도 `resolution-mode: "import"`를 유지해야 하며 Nest 12 strict fixture가 drift를
  검출한다.
- TypeScript 5.2 이하 declaration consumers는 planned `0.4.0` migration 때 compiler를 올려야 한다.

## Rejected alternatives

### CommonJS/ESM conditional declarations와 dual output

CommonJS declaration이 Nest 12 ESM type을 참조하는 문제는 CJS branch에 그대로 남으며, 결국 같은
resolution bridge가 필요하다. 별도 runtime output까지 만들면 release surface와 dual-package identity
위험만 늘어나므로 거부한다.

### Package 전체 ESM migration

Nest 12 하나를 지원하기 위해 `require()` public contract와 shared loader identity를 깨뜨리고 모든
consumer에 migration을 요구한다. 현재 CommonJS runtime은 두 지원 Node version에서 Nest 12 DI/HTTP를
통과하므로 필요성이 없다.

### Hand-written declaration 또는 post-build rewrite

source signature와 배포 declaration이 쉽게 drift하고 build/release가 별도 변환기에 의존한다. TypeScript가
공식 지원하는 type import attribute를 source에 명시해 compiler가 declaration을 emit하는 편이 더 작고
검증 가능하므로 거부한다.

### `skipLibCheck` 또는 consumer ESM 강제

`skipLibCheck`는 공개 declaration 오류를 숨길 뿐이며 consumer ESM 변형에서도 기존 library 오류가
남았다. package가 직접 만든 module-resolution 경계를 consumer에게 전가하므로 거부한다.
