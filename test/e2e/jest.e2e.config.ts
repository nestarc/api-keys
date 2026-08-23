import type { Config } from 'jest';

const config: Config = {
  rootDir: '../..',
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/e2e/**/*.e2e-spec.ts'],
  maxWorkers: 1,
};

export default config;
