# Public `ApiKeyStorage` contract runner ADR

- 상태: `ACCEPTED`
- 결정일: 2026-08-31 (Asia/Seoul)
- 작업: `AK-M20B`

## Context

README와 0.1 changelog는 custom `ApiKeyStorage` 구현자를 위한 reusable contract suite를
약속했지만, 실제 suite는 저장소의 `test/contract/storage-contract.ts`에만 있었다. npm tarball에는
그 파일이나 import 가능한 public test helper가 없었고, 내부 suite는 Jest 전역을 암묵적으로
요구했다. 외부 adapter 작성자는 atomic rotation을 포함한 현재 storage 계약을 같은 방식으로
검증할 수 없었다.

## Decision

runtime package root에서 `runApiKeyStorageContract()`, `ApiKeyStorageContractError`와 관련 타입을
export한다. runner는 Node의 assertion API만 사용하고 특정 test framework나 Prisma를 요구하지
않는다. 소비자는 disposable test storage를 생성하고 필요하면 `disposeStorage`로 fixture와 연결을
정리한다.

runner는 모든 required method와 다음 observable contract를 검증한다.

- insert, ID/prefix lookup, missing lookup
- tenant 격리, revoked filtering, `createdAt DESC, id ASC` 순서
- 입력과 반환 record의 array/`Date` defensive copy
- revoke와 last-used mutation
- successful rotation의 lineage와 모든 `Date` copy
- missing/revoked/rotated/replaced/expired old key의 `not_rotatable`
- 동시 rotation 중 정확히 하나만 `rotated`가 되는 atomic CAS
- 구현된 경우 tenant-bound revoke/rotation capability의 tenant mismatch 원자 거부

첫 실패는 adapter 이름과 stable check 이름을 가진 `ApiKeyStorageContractError`로 반환한다.
성공하면 실행된 check 이름을 반환해 optional capability가 실제로 검증됐는지 기록할 수 있다.

## Packaging and evidence

빌드된 JS와 declaration은 기존 `dist` allowlist에 포함되며 package root declaration이 export를
노출한다. clean packed consumer는 Prisma 없이 독립 custom adapter를 compile하고 runner를 실제로
실행한다. CI와 release는 같은 `test:consumer:storage-contract` command를 persistent packed-consumer
lane으로 유지한다.

## Rejected alternative

문구를 "저장소 내부 suite"로만 좁히는 선택은 package가 이미 custom storage interface와 migration
의무를 공개하고 있어 채택하지 않았다. source test를 복사하라는 recipe 역시 package version과
contract가 drift하고 Jest 결합을 다시 만들기 때문에 거부했다.
