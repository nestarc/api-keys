# NestJS, Prisma, and PostgreSQL compatibility evidence policy

- Status: Accepted
- Date: 2026-08-30
- Owner task: `AK-M10`
- Applies to: the planned `@nestarc/api-keys` 0.4.x support contract

## Decision

The package maintains evidence by integration boundary instead of running the complete Cartesian
product of every NestJS, Prisma, PostgreSQL, and Node.js version. A supported major boundary must
have at least one persistent strict install/typecheck/runtime or real-database lane. A version is
not added to public peer metadata before that evidence exists.

| Boundary | Exact persistent evidence | Depth and responsibility |
| --- | --- | --- |
| NestJS 10 | 10.4.20 packed strict consumer with Prisma 6.19.3; 10.4.20 packed HTTP consumer | Strict npm peer resolution, public declaration typecheck, application-context runtime, and default HTTP Guard/exception behavior |
| NestJS 11 | 11.2.3 full source suite; 11.2.3 packed strict consumer with Prisma 7.10.0; 11.2.3 packed HTTP consumer | Development baseline plus the same packed and HTTP boundaries as NestJS 10 |
| Prisma 5 | 5.22.0 CLI/client against PostgreSQL 14 and 16 | Lowest Prisma and PostgreSQL boundary plus current PostgreSQL storage contract |
| Prisma 6 | 6.19.3 CLI/client against PostgreSQL 16 | Real generated-client storage contract; legacy packed representative pairs it with NestJS 10 |
| Prisma 7 | 7.10.0 CLI/client/`@prisma/adapter-pg` against PostgreSQL 16 | Real generated-client and driver-adapter storage contract; modern packed representative pairs it with NestJS 11 |
| PostgreSQL 14 | Prisma 5.22.0 storage contract on `postgres:14-alpine` | Public database support floor |
| PostgreSQL 16 | Prisma 5.22.0, 6.19.3, and 7.10.0 storage contracts on `postgres:16-alpine` | Current database lane and all supported Prisma majors |
| Prisma omitted | NestJS 11.2.3 packed root consumer with no `@prisma/client` lock/install entry | Strict install, public declaration typecheck with `skipLibCheck: false`, root import, Nest application-context boot, and in-memory create/verify runtime |

The source suite runs on exact Node.js 22.13.0 and Node 24. The DB and packed-consumer lanes run on
the exact supported Node.js minimum, 22.13.0, so a transitive engine-floor increase fails before
release. The separate Node support decision is recorded in
[`2026-08-30-node-support-policy-adr.md`](./2026-08-30-node-support-policy-adr.md).

## Matrix shape

NestJS integration and Prisma integration meet different public boundaries. NestJS consumes the
module, service, Guard, decorators, errors, and storage interface. `PrismaApiKeyStorage` consumes a
structural `PrismaLike` client and does not import NestJS runtime APIs. Therefore the two packed
legacy/modern representatives are retained, but NestJS 10 + Prisma 7 and NestJS 11 + Prisma 6 are
not permanent off-diagonal lanes.

This is not a claim that untested combinations are intrinsically safe. A dependency release or
code change that couples the two boundaries must add a targeted off-diagonal smoke test. A failure
in a consumer report also creates evidence for adding the affected combination. Permanent lanes
are kept only when they protect a distinct public boundary.

PostgreSQL follows the same minimum-evidence rule. PostgreSQL 14 is exercised with the lowest
supported Prisma major, while PostgreSQL 16 exercises every Prisma major. The project does not run
all six PostgreSQL/Prisma combinations because the current adapter SQL contract does not vary by
NestJS and the four selected lanes cover both version boundaries and all Prisma implementations.

## Reproducible commands

```bash
npm run test:e2e:postgres-matrix
npm run test:consumer:strict:legacy
npm run test:consumer:strict:modern
npm run test:consumer:no-prisma
npm run test:consumer:http:nest10
npm run test:consumer:http:nest11
```

`test:e2e:postgres-matrix` requires Docker. It creates isolated exact Prisma runtime roots for
5.22.0, 6.19.3, and 7.10.0, then runs the PostgreSQL 14 boundary lane and the three PostgreSQL 16
lanes. It deliberately ignores `PRISMA_E2E_DATABASE_URL` so the named command always proves the
declared container majors. The lower-level `test:e2e:prisma` command remains available for one
caller-provided exact runtime and database; by itself it is not complete matrix evidence.

The no-Prisma consumer installs the packed artifact as an independent root dependency and fails if
`@prisma/client` resolves or appears in its lockfile. Existing strict consumers install Prisma and
cannot be used as evidence that the peer is optional.

CI runs these commands for every pull request and repeats them before a tagged release can publish.

## Changing support

- Adding a NestJS major requires exact strict install/typecheck/runtime and HTTP evidence.
- Adding a Prisma major requires an exact real PostgreSQL lane and matching driver adapter where
  Prisma requires one.
- Lowering or raising PostgreSQL support requires a real boundary lane and synchronized public
  documentation.
- A newly coupled integration surface or reproduced cross-version failure may justify a targeted
  off-diagonal lane; support ranges alone do not justify a full Cartesian matrix.
- Removing an existing supported major is a pre-1.0 breaking support change and requires a
  migration note.
