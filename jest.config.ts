import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts', '!src/index.ts'],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'json-summary'],
  coverageThreshold: {
    // Keep aligned with coverage-thresholds.json, which also defines critical files.
    global: {
      statements: 88,
      branches: 84,
      functions: 86,
      lines: 87,
    },
  },
  setupFilesAfterEnv: [],
};

export default config;
