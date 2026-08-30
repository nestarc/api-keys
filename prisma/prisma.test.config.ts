import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.test.v7.prisma',
  datasource: {
    url: env('DATABASE_URL'),
  },
});
