# ADR: Node.js 22/24 support policy

- Date: 2026-08-30
- Status: Accepted
- Work item: `AK-M09`
- Target release: `0.4.0`

## Context

The published `0.3.2` package declares `engines.node >=20`. Its source CI tests Node 20 and 22,
while release publication runs on Node 24. The development toolchain now includes ESLint 10 and
`@eslint/js` 10, whose installed packages require `^20.19.0 || ^22.13.0 || >=24`. Node 20 is also
outside this repository's forward support policy.

A broad `>=22` declaration would include Node 22 patches below the installed toolchain's verified
floor. A broad open-ended CI claim would also imply support for future majors that have not been
tested with the package's NestJS, Prisma, and PostgreSQL consumers.

## Decision

Starting with the planned pre-1.0 `0.4.0` release:

- `engines.node` is `^22.13.0 || ^24.0.0`;
- Node 22.13.0 is the exact minimum support and compatibility lane;
- Node 24 is the current source-test and publication lane;
- `@types/node` uses the Node 22 line with the same 22.13.0 lower bound;
- Prisma, strict packed-consumer, and HTTP packed-consumer jobs run on Node 22.13.0 so the minimum
  remains a real runtime contract rather than metadata only;
- future Node majors, including Node 26, remain outside the engine range. They require an explicit
  matrix addition and recorded compatibility evidence.

The engine expression accepts supported patches within the Node 22 and Node 24 lines without
silently admitting Node 23, 25, 26, or a later major. The README's tested matrix is authoritative
for support evidence within those declared lines.

## Evidence required by this decision

Before `AK-M09` is complete, profiles A, B, C, and D run under exact Node 22.13.0 and Node 24. The
minimum profile includes a clean install, lint, typecheck, the complete unit/integration suite,
fresh coverage, build/package/benchmark/audit, Prisma 5/6/7 PostgreSQL contracts, and Nest 10/11
strict and HTTP packed consumers. Persistent CI retains both source runtimes, while DB and
consumer jobs pin the exact minimum.

## Migration and versioning

Dropping Node 20 can make installation fail through the package engine contract and permits future
code to rely on the Node 22.13.0 baseline. It is therefore treated as breaking for consumers. This
repository is pre-1.0 and groups the change into the planned `0.4.0` release rather than a `0.3.x`
patch.

Consumers must move production, build, test, migration, and deployment jobs to Node 22.13.0 or
Node 24 before installing `0.4.0`. Applications that cannot upgrade Node must stay on the `0.3.x`
release line.

## Alternatives considered

### Keep Node 20 until a later release

Rejected because it would retain an end-of-life runtime as a public package contract and leave the
new development toolchain's narrower patch floor disconnected from repository policy.

### Declare `>=22`

Rejected because it includes unverified Node 22.0.0 through 22.12.x even though the installed
ESLint toolchain begins its Node 22 range at 22.13.0.

### Declare only Node 22

Rejected because Node 24 already runs publication and is now covered by the complete source
profile. Keeping both active LTS-era runtimes provides a tested minimum and a current runtime.
