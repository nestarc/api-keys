const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { inspectTarball, resolveConsumerCandidate } = require('./package-candidate');

const projectRoot = path.resolve(__dirname, '..');
const NEST_VERSION = '11.2.3';
const PUBLIC_ASSETS = [
  'prisma/schema.example.prisma',
  'prisma/schema.example.v7.prisma',
  'prisma/prisma.config.example.ts',
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? projectRoot,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit',
    env: options.env ?? process.env,
  });

  if (result.status !== 0) {
    if (options.capture) {
      process.stderr.write(result.stdout ?? '');
      process.stderr.write(result.stderr ?? '');
    }
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
  }

  return (result.stdout ?? '').trim();
}

function strictNpmEnv(tempDir) {
  return {
    ...process.env,
    npm_config_cache: path.join(tempDir, 'npm-cache'),
    NPM_CONFIG_CACHE: path.join(tempDir, 'npm-cache'),
    npm_config_force: 'false',
    NPM_CONFIG_FORCE: 'false',
    npm_config_legacy_peer_deps: 'false',
    NPM_CONFIG_LEGACY_PEER_DEPS: 'false',
    npm_config_strict_peer_deps: 'true',
    NPM_CONFIG_STRICT_PEER_DEPS: 'true',
  };
}

function writeConsumerFiles(consumerDir) {
  fs.writeFileSync(
    path.join(consumerDir, 'commonjs.cjs'),
    `const assert = require('node:assert/strict');
const fs = require('node:fs');
const apiKeys = require('@nestarc/api-keys');

(async () => {
  const imported = await import('@nestarc/api-keys');
  for (const name of ['ApiKeysService', 'InMemoryApiKeyStorage', 'PrismaApiKeyStorage']) {
    assert.equal(typeof apiKeys[name], 'function', name + ' must be a CommonJS root export');
    assert.strictEqual(imported[name], apiKeys[name], name + ' identity must match across loaders');
  }

  assert.throws(
    () => require.resolve('@nestarc/api-keys/dist/types'),
    (error) => error && error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  );

  for (const subpath of ${JSON.stringify(PUBLIC_ASSETS)}) {
    const resolved = require.resolve('@nestarc/api-keys/' + subpath);
    assert.equal(fs.statSync(resolved).isFile(), true, subpath + ' must resolve to a file');
  }
  const manifestPath = require.resolve('@nestarc/api-keys/package.json');
  assert.equal(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).name, '@nestarc/api-keys');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`,
  );

  fs.writeFileSync(
    path.join(consumerDir, 'module.mjs'),
    `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  ApiKeysService,
  InMemoryApiKeyStorage,
  PrismaApiKeyStorage,
} from '@nestarc/api-keys';

const require = createRequire(import.meta.url);
const commonjs = require('@nestarc/api-keys');
assert.strictEqual(ApiKeysService, commonjs.ApiKeysService);
assert.strictEqual(InMemoryApiKeyStorage, commonjs.InMemoryApiKeyStorage);
assert.strictEqual(PrismaApiKeyStorage, commonjs.PrismaApiKeyStorage);
assert.equal(typeof new InMemoryApiKeyStorage().findById, 'function');

try {
  require.resolve('@prisma/client');
  throw new Error('@prisma/client unexpectedly resolved from the module-format consumer');
} catch (error) {
  if (error && error.code !== 'MODULE_NOT_FOUND') throw error;
}
`,
  );

  fs.writeFileSync(
    path.join(consumerDir, 'typecheck.mts'),
    `import {
  ApiKeysService,
  InMemoryApiKeyStorage,
  PrismaApiKeyStorage,
  type ApiKeyContext,
  type PrismaLike,
} from '@nestarc/api-keys';

const storage = new InMemoryApiKeyStorage();
const prismaAdapter: typeof PrismaApiKeyStorage = PrismaApiKeyStorage;
type AdapterInput = PrismaLike;

async function verify(service: ApiKeysService, rawKey: string): Promise<ApiKeyContext> {
  return service.verify(rawKey);
}

void storage;
void prismaAdapter;
void (undefined as unknown as AdapterInput);
void verify;
`,
  );

  fs.writeFileSync(
    path.join(consumerDir, 'tsconfig.json'),
    `${JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          skipLibCheck: false,
          noEmit: true,
          types: ['node'],
        },
        include: ['typecheck.mts'],
      },
      null,
      2,
    )}\n`,
  );
}

function assertPackageMetadata(manifest) {
  assert.equal(manifest.main, 'dist/index.js');
  assert.equal(manifest.types, 'dist/index.d.ts');
  assert.deepEqual(manifest.exports, {
    '.': {
      types: './dist/index.d.ts',
      require: './dist/index.js',
      import: './dist/index.js',
      default: './dist/index.js',
    },
    './prisma/schema.example.prisma': './prisma/schema.example.prisma',
    './prisma/schema.example.v7.prisma': './prisma/schema.example.v7.prisma',
    './prisma/prisma.config.example.ts': './prisma/prisma.config.example.ts',
    './package.json': './package.json',
  });
}

function assertNoPrisma(consumerDir) {
  const lock = JSON.parse(fs.readFileSync(path.join(consumerDir, 'package-lock.json'), 'utf8'));
  assert.equal(
    Object.keys(lock.packages ?? {}).some((entry) => entry.includes('node_modules/@prisma/client')),
    false,
    'module-format consumer lock unexpectedly contains @prisma/client',
  );
}

function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-module-consumer-'));

  try {
    const npmEnv = strictNpmEnv(tempDir);
    const packedArtifact = resolveConsumerCandidate({
      tempDirectory: path.join(tempDir, 'candidate'),
      env: npmEnv,
    });
    assertPackageMetadata(inspectTarball(packedArtifact.tarballPath).packageJson);
    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-module-format-consumer',
          private: true,
          version: '1.0.0',
          type: 'module',
          devDependencies: {
            '@types/node': '22.20.1',
            typescript: '5.9.3',
          },
          dependencies: {
            '@nestarc/api-keys': `file:${packedArtifact.tarballPath}`,
            '@nestjs/common': NEST_VERSION,
            '@nestjs/core': NEST_VERSION,
            'reflect-metadata': '0.2.2',
            rxjs: '7.8.2',
          },
        },
        null,
        2,
      )}\n`,
    );
    writeConsumerFiles(consumerDir);

    run(
      'npm',
      [
        'install',
        '--no-audit',
        '--no-fund',
        '--strict-peer-deps=true',
        '--legacy-peer-deps=false',
        '--force=false',
      ],
      { cwd: consumerDir, env: npmEnv },
    );
    assertNoPrisma(consumerDir);

    run(
      process.execPath,
      [path.join(consumerDir, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'],
      { cwd: consumerDir },
    );
    run(process.execPath, ['commonjs.cjs'], { cwd: consumerDir });
    run(process.execPath, ['module.mjs'], { cwd: consumerDir });

    console.log('CommonJS/native ESM packed consumer passed without Prisma');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
