# @nestarc/api-keys

Secure, tenant-scoped API keys for NestJS + Prisma. SHA-256 hashed, Stripe-style scopes, test/live environments.

## Install

```bash
npm install @nestarc/api-keys
```

## Quickstart

```typescript
import { Module } from '@nestjs/common';
import { ApiKeysModule, PrismaApiKeyStorage } from '@nestarc/api-keys';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

@Module({
  imports: [
    ApiKeysModule.forRoot({
      namespace: 'acme',
      peppers: { 1: process.env.API_KEY_PEPPER! },
      storage: new PrismaApiKeyStorage(prisma),
    }),
  ],
})
export class AppModule {}
```

Add the schema model from `prisma/schema.example.prisma` into your own `schema.prisma` and run a migration.

### Protect a route

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiKeysGuard, RequireScope } from '@nestarc/api-keys';

@Controller('reports')
@UseGuards(ApiKeysGuard)
export class ReportsController {
  @Get()
  @RequireScope('reports', 'read')
  list() {
    return [];
  }
}
```

### Issue a key

```typescript
const { id, key } = await apiKeys.create({
  tenantId: 'tenant_123',
  name: 'Primary',
  scopes: [{ resource: 'reports', level: 'read' }],
});
// key is returned ONCE; show it to the user and discard.
```

## Key format

```text
nk_live_<12-char-prefix>_<32-char-secret>
```

## Docs

- [`docs/prd.md`](docs/prd.md) Product requirements
- [`docs/spec.md`](docs/spec.md) Technical spec

## License

MIT
