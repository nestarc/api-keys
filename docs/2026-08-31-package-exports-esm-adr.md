# Package exports and ESM interoperability ADR

- 상태: `ACCEPTED`
- 결정일: 2026-08-31 (Asia/Seoul)
- 작업: `AK-M21`
- 대상 릴리스: planned pre-1.0 `0.4.0`

## Context

published `0.3.2` package는 `main: dist/index.js`와 `types: dist/index.d.ts`만 선언한다.
빌드는 CommonJS 하나를 만들며 `exports` map이 없어 tarball 안의 모든 `dist/**` 파일을 deep
import할 수 있다. 반대로 package root의 public API, Prisma 미설치 경로, schema/config example의
지원 subpath, CommonJS와 native ESM 소비 계약은 metadata로 명시돼 있지 않다.

2026-08-31 공개 GitHub code search에서 `@nestarc/api-keys/` 후보는 세 건이었다. 모두
`nestarc/nestjs-tenancy`의 유지보수 문서 또는 ecosystem fixture lockfile이었고 executable source의
deep import는 아니었다. `@nestarc/api-keys/dist`와 `@nestarc/api-keys/storage` 검색 결과는 0건이었다.
현재 저장소와 history도 package-name deep import를 사용하지 않는다. GitHub에 index되지 않은 private
consumer까지 없다고 증명할 수는 없으므로 deep import 차단은 additive patch로 취급하지 않는다.

현재 CommonJS build는 Node의 native ESM named import로 `ApiKeysService`,
`InMemoryApiKeyStorage`, `PrismaApiKeyStorage`를 불러오는 smoke를 통과한다. 따라서 ESM syntax
consumer를 지원하기 위해 별도 runtime graph를 만들 필요는 없다.

## Decision

CommonJS를 canonical runtime으로 유지하고 package root에 explicit `exports` map을 추가한다.

- `.`의 `types`는 `dist/index.d.ts`다.
- `.`의 `require`, `import`, `default`는 모두 같은 `dist/index.js`를 가리킨다.
- legacy resolver와 older TypeScript를 위해 기존 top-level `main`과 `types`도 유지한다.
- public runtime/declaration API는 package root 하나다. `dist/**`와 source-layout subpath는 private이며
  `ERR_PACKAGE_PATH_NOT_EXPORTED`로 차단한다.
- packaged assets는 `./prisma/schema.example.prisma`,
  `./prisma/schema.example.v7.prisma`, `./prisma/prisma.config.example.ts`를 exact subpath로 공개한다.
- metadata introspection을 위해 `./package.json`을 공개한다.

별도 ESM output은 만들지 않는다. `require()`와 `import`가 같은 CommonJS module instance와 class/token
identity를 공유하게 해 Nest decorator metadata, DI token, `instanceof`, singleton state가 format에 따라
갈라지는 dual-package hazard를 피한다. 이 결정은 native ESM syntax interoperability를 지원하지만
package 내부를 ESM으로 전환하거나 tree-shaking을 보장한다는 뜻은 아니다.

## Evidence contract

clean packed consumer가 다음을 지속 검증한다.

- package root의 CommonJS `require()`와 native ESM named `import`
- 두 loader가 반환하는 public class/token identity의 일치
- `type: module`, `moduleResolution: NodeNext`, `skipLibCheck: false` declaration compile
- `@prisma/client`가 lock/install tree에 없는 상태에서 root와 Prisma adapter symbol load
- 세 Prisma schema/config example과 `package.json`의 exact exported resolution
- undeclared `dist/**` deep import의 `ERR_PACKAGE_PATH_NOT_EXPORTED`
- release candidate의 `exports`, `main`, `types`, asset allowlist 일치

CI와 release는 동일한 module-format packed-consumer command를 release candidate에 실행한다.

## Versioning and migration

문서화되지 않은 deep import라도 기존 `0.3.x` tarball에서는 기술적으로 가능했다. `exports`가 이를
차단하므로 planned pre-1.0 `0.4.0`의 breaking change로 묶는다. deep import consumer는 package root의
public export로 이동해야 한다. root에서 빠진 legitimate API가 발견되면 private file layout을 다시
공개하지 않고 root export 필요성을 별도 검토한다.

## Rejected alternatives

### `main`/`types` only 유지

root API와 public asset boundary가 계속 암묵적이고, accidental deep import를 새 내부 구조와 함께 영구
지원하게 되므로 거부했다.

### 별도 ESM/CJS dual build

현재 native ESM consumer가 CommonJS build를 정상 import하며 제품 코드에 format별 최적화 요구가 없다.
두 runtime graph는 build/release surface와 dual-package identity 위험만 늘리므로 거부했다.

### `dist/*` compatibility wildcard 공개

현재 file layout 전체를 public API로 고정하고 future refactor를 막는다. 공개 검색에서 executable
deep import evidence도 없어 채택하지 않았다.
