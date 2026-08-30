import path from 'node:path';
import type { Config } from 'jest';

const prismaRuntimeModules = process.env.PRISMA_E2E_RUNTIME_ROOT
  ? path.join(process.env.PRISMA_E2E_RUNTIME_ROOT, 'node_modules')
  : undefined;

const config: Config = {
  rootDir: '../..',
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/e2e/**/*.e2e-spec.ts'],
  moduleDirectories: [prismaRuntimeModules, 'node_modules'].filter(
    (directory): directory is string => Boolean(directory),
  ),
  maxWorkers: 1,
};

export default config;
