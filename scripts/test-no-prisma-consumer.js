const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolveConsumerCandidate } = require('./package-candidate');

const projectRoot = path.resolve(__dirname, '..');
const NEST_VERSION = '11.2.3';
const EXPECTED_NEST_PEER = '^10.0.0 || ^11.0.0';
const EXPECTED_PRISMA_PEER = '^5.0.0 || ^6.0.0 || ^7.0.0';

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
    path.join(consumerDir, 'typecheck.ts'),
    `import {
  ApiKeysModule,
  ApiKeysService,
  InMemoryApiKeyStorage,
  PrismaApiKeyStorage,
  type ApiKeyContext,
  type PrismaLike,
} from '@nestarc/api-keys';
import type { DynamicModule } from '@nestjs/common';

const storage = new InMemoryApiKeyStorage();
const moduleDefinition: DynamicModule = ApiKeysModule.forRoot({
  namespace: 'noprismatypes',
  peppers: { 1: 'no-prisma-type-pepper' },
  storage,
});
const prismaAdapterType: typeof PrismaApiKeyStorage = PrismaApiKeyStorage;
type AdapterInput = PrismaLike;

async function verify(service: ApiKeysService, rawKey: string): Promise<ApiKeyContext> {
  return service.verify(rawKey);
}

void moduleDefinition;
void prismaAdapterType;
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
          module: 'Node16',
          moduleResolution: 'Node16',
          strict: true,
          skipLibCheck: false,
          noEmit: true,
          types: ['node'],
        },
        include: ['typecheck.ts'],
      },
      null,
      2,
    )}\n`,
  );
  fs.writeFileSync(
    path.join(consumerDir, 'smoke.js'),
    `require('reflect-metadata');
const { Module } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const {
  ApiKeysModule,
  ApiKeysService,
  InMemoryApiKeyStorage,
  PrismaApiKeyStorage,
} = require('@nestarc/api-keys');

if (typeof PrismaApiKeyStorage !== 'function') {
  throw new Error('The root export must load without Prisma installed');
}
try {
  require.resolve('@prisma/client');
  throw new Error('@prisma/client unexpectedly resolved from the no-Prisma consumer');
} catch (error) {
  if (error && error.code !== 'MODULE_NOT_FOUND') throw error;
}

class ConsumerModule {}
Module({
  imports: [
    ApiKeysModule.forRoot({
      namespace: 'noprismaruntime',
      peppers: { 1: 'no-prisma-runtime-pepper' },
      storage: new InMemoryApiKeyStorage(),
    }),
  ],
})(ConsumerModule);

(async () => {
  const app = await NestFactory.createApplicationContext(ConsumerModule, { logger: false });
  try {
    const service = app.get(ApiKeysService);
    const created = await service.create({
      tenantId: 'tenant_no_prisma',
      name: 'No Prisma consumer',
      scopes: [{ resource: 'consumer', level: 'read' }],
    });
    const context = await service.verify(created.key);
    if (context.tenantId !== 'tenant_no_prisma') {
      throw new Error('The no-Prisma runtime smoke test lost the tenant identity');
    }
  } finally {
    await app.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`,
  );
}

function installedVersion(consumerDir, packageName) {
  return JSON.parse(
    fs.readFileSync(
      path.join(consumerDir, 'node_modules', ...packageName.split('/'), 'package.json'),
      'utf8',
    ),
  ).version;
}

function assertConsumerLock(consumerDir, packedArtifact) {
  const lock = JSON.parse(fs.readFileSync(path.join(consumerDir, 'package-lock.json'), 'utf8'));
  const installedPackages = Object.keys(lock.packages ?? {});
  if (installedPackages.some((entry) => entry.includes('node_modules/@prisma/client'))) {
    throw new Error('Consumer lock unexpectedly contains @prisma/client');
  }
  const lockedArtifact = lock.packages?.['node_modules/@nestarc/api-keys'];
  if (!lockedArtifact?.resolved?.startsWith('file:')) {
    throw new Error('Consumer lock does not identify API Keys as a file tarball');
  }
  if (lockedArtifact.integrity !== packedArtifact.integrity) {
    throw new Error('Consumer lock integrity does not match npm pack output');
  }
}

function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-no-prisma-consumer-'));

  try {
    const npmEnv = strictNpmEnv(tempDir);
    const packedArtifact = resolveConsumerCandidate({
      tempDirectory: tempDir,
      env: npmEnv,
    });
    const tarballPath = packedArtifact.tarballPath;

    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-no-prisma-consumer',
          private: true,
          version: '1.0.0',
          devDependencies: {
            '@types/node': '22.20.1',
            typescript: '5.9.3',
          },
          dependencies: {
            '@nestarc/api-keys': `file:${tarballPath}`,
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
    run('npm', ['ls', '--depth=0'], { cwd: consumerDir, env: npmEnv });
    assertConsumerLock(consumerDir, packedArtifact);
    for (const packageName of ['@nestjs/common', '@nestjs/core']) {
      const actual = installedVersion(consumerDir, packageName);
      if (actual !== NEST_VERSION) {
        throw new Error(`Expected ${packageName}@${NEST_VERSION}, installed ${actual}`);
      }
    }

    const packageRoot = path.join(consumerDir, 'node_modules', '@nestarc', 'api-keys');
    const packedPackage = JSON.parse(
      fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'),
    );
    if (packedPackage.peerDependencies['@nestjs/common'] !== EXPECTED_NEST_PEER) {
      throw new Error('Packed peer metadata does not declare the verified Nest 10/11 range');
    }
    if (packedPackage.peerDependencies['@prisma/client'] !== EXPECTED_PRISMA_PEER) {
      throw new Error('Packed peer metadata does not declare the verified Prisma 5/6/7 range');
    }
    if (!packedPackage.peerDependenciesMeta['@prisma/client']?.optional) {
      throw new Error('Packed @prisma/client peer must remain optional');
    }

    run(
      process.execPath,
      [path.join(consumerDir, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'],
      { cwd: consumerDir },
    );
    run(process.execPath, ['smoke.js'], { cwd: consumerDir });
    console.log(`No-Prisma packed consumer passed with Nest ${NEST_VERSION}`);
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
