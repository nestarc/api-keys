const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const DEFAULT_NEST_VERSION = '11.2.3';
const DEFAULT_PRISMA_VERSION = '7.10.0';
const EXPECTED_NEST_PEER = '^10.0.0 || ^11.0.0';
const EXPECTED_PRISMA_PEER = '^5.0.0 || ^6.0.0 || ^7.0.0';
const EXPECTED_NODE_ENGINE = '^22.13.0 || ^24.0.0';

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

function enabled(value) {
  return (
    typeof value === 'string' && ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase())
  );
}

function npmConfigEnabled(configName) {
  const expectedName = `npm_config_${configName}`;
  return Object.entries(process.env).some(
    ([name, value]) => name.toLowerCase().replaceAll('-', '_') === expectedName && enabled(value),
  );
}

function strictNpmEnv() {
  return {
    ...process.env,
    npm_config_force: 'false',
    NPM_CONFIG_FORCE: 'false',
    npm_config_legacy_peer_deps: 'false',
    NPM_CONFIG_LEGACY_PEER_DEPS: 'false',
    npm_config_strict_peer_deps: 'true',
    NPM_CONFIG_STRICT_PEER_DEPS: 'true',
  };
}

function parseVersions(args) {
  const versions = {
    nest: DEFAULT_NEST_VERSION,
    prisma: DEFAULT_PRISMA_VERSION,
  };

  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if ((flag !== '--nest' && flag !== '--prisma') || !value) {
      throw new Error('Usage: test-strict-consumer.js [--nest <exact>] [--prisma <exact>]');
    }
    if (!/^\d+\.\d+\.\d+$/.test(value)) {
      throw new Error(`${flag} requires an exact x.y.z version; received ${value}`);
    }
    versions[flag.slice(2)] = value;
  }

  return versions;
}

function readInstalledVersion(consumerDir, packageName) {
  return JSON.parse(
    fs.readFileSync(
      path.join(consumerDir, 'node_modules', ...packageName.split('/'), 'package.json'),
    ),
  ).version;
}

function assertInstalledVersion(consumerDir, packageName, expected) {
  const actual = readInstalledVersion(consumerDir, packageName);
  if (actual !== expected) {
    throw new Error(`Expected ${packageName}@${expected}, installed ${actual}`);
  }
}

function writeNestSmokeTest(consumerDir) {
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
  throw new Error('PrismaApiKeyStorage is not exported');
}

class ConsumerModule {}
Module({
  imports: [
    ApiKeysModule.forRoot({
      namespace: 'strict',
      peppers: { 1: 'strict-consumer-pepper' },
      storage: new InMemoryApiKeyStorage(),
    }),
  ],
})(ConsumerModule);

(async () => {
  const app = await NestFactory.createApplicationContext(ConsumerModule, { logger: false });
  try {
    const apiKeys = app.get(ApiKeysService);
    const created = await apiKeys.create({
      tenantId: 'tenant_strict',
      name: 'Strict consumer',
      scopes: [{ resource: 'consumer', level: 'read' }],
    });
    const context = await apiKeys.verify(created.key);
    if (context.tenantId !== 'tenant_strict') {
      throw new Error('Nest runtime smoke test lost the API key tenant');
    }
    const summaries = await apiKeys.list('tenant_strict');
    const createdSummary = summaries.find((summary) => summary.id === created.id);
    if (!createdSummary || createdSummary.name !== 'Strict consumer') {
      throw new Error('Public list summary lost expected management metadata');
    }
    const serializedSummaries = JSON.stringify(summaries);
    if (
      serializedSummaries.includes('hash') ||
      serializedSummaries.includes('pepperVersion') ||
      serializedSummaries.includes(created.key) ||
      serializedSummaries.includes(created.key.split('_')[3])
    ) {
      throw new Error('Public list summary exposed verifier material');
    }
    const ipRestricted = await apiKeys.create({
      tenantId: 'tenant_strict',
      name: 'Restricted direct consumer',
      scopes: [{ resource: 'consumer', level: 'read' }],
      allowedIpCidrs: ['203.0.113.0/24'],
    });
    await apiKeys.verify(ipRestricted.key);
    let missingIpCode;
    try {
      await apiKeys.authorizeRequest({ rawKey: ipRestricted.key });
    } catch (error) {
      missingIpCode = error?.code;
    }
    if (missingIpCode !== 'api_key_ip_not_allowed') {
      throw new Error('Request-aware verification did not fail closed without a client IP');
    }
    const authorizedContext = await apiKeys.authorizeRequest({
      rawKey: ipRestricted.key,
      clientIp: '203.0.113.42',
      requiredEnvironment: 'live',
      requiredScope: { resource: 'consumer', level: 'read' },
    });
    if (authorizedContext.keyId !== ipRestricted.id) {
      throw new Error('Request-aware verification lost the API key identity');
    }
    let crossTenantCode;
    try {
      await apiKeys.revokeForTenant('tenant_attacker', created.id);
    } catch (error) {
      crossTenantCode = error?.code;
    }
    if (crossTenantCode !== 'api_key_record_not_found') {
      throw new Error('Tenant-bound revoke did not hide the cross-tenant record');
    }
    await apiKeys.verify(created.key);
    const replacement = await apiKeys.rotateForTenant('tenant_strict', created.id);
    const replacementContext = await apiKeys.verify(replacement.key);
    if (replacementContext.tenantId !== 'tenant_strict') {
      throw new Error('Tenant-bound rotation lost the exact tenant');
    }
    await apiKeys.revokeForTenant('tenant_strict', replacement.id);
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

function writeTypeScriptConsumer(consumerDir) {
  fs.writeFileSync(
    path.join(consumerDir, 'typecheck.ts'),
    `import {
  ApiKeysModule,
  ApiKeysService,
  InMemoryApiKeyStorage,
  PrismaApiKeyStorage,
  createTestKey,
  type ApiKeyAuthorizationMetric,
  type ApiKeyContext,
  type ApiKeyRequestAuthorizationInput,
  type ApiKeySummary,
  type PrismaLike,
} from '@nestarc/api-keys';
import type { DynamicModule } from '@nestjs/common';

const storage = new InMemoryApiKeyStorage();
const apiKeysModule: DynamicModule = ApiKeysModule.forRoot({
  namespace: 'types',
  peppers: { 1: 'type-consumer-pepper' },
  storage,
});
const prismaStorage = new PrismaApiKeyStorage({} as PrismaLike);

async function verifyPublicTypes(service: ApiKeysService): Promise<ApiKeyContext> {
  const fixture = await createTestKey(service);
  return fixture.context;
}

async function verifyTenantBoundManagementTypes(service: ApiKeysService): Promise<void> {
  await service.revokeForTenant('tenant_types', 'key_types');
  await service.rotateForTenant('tenant_types', 'key_types', { gracePeriodMs: 1_000 });
}

async function verifyPublicListTypes(service: ApiKeysService): Promise<ApiKeySummary[]> {
  const summaries = await service.list('tenant_types', { includeRevoked: true });
  for (const summary of summaries) {
    void summary.prefix;
    void summary.expiresAt;
    // @ts-expect-error Verifier hashes are storage-only and absent from public summaries.
    void summary.hash;
    // @ts-expect-error Pepper versions are storage-only and absent from public summaries.
    void summary.pepperVersion;
  }
  return summaries;
}

async function verifyRequestAuthorizationTypes(
  service: ApiKeysService,
  input: ApiKeyRequestAuthorizationInput,
): Promise<ApiKeyContext> {
  const metric: ApiKeyAuthorizationMetric = {
    type: 'api_key.authorization',
    outcome: 'success',
    durationMs: 1,
  };
  void metric;
  return service.authorizeRequest(input);
}

void apiKeysModule;
void prismaStorage;
void verifyPublicTypes;
void verifyTenantBoundManagementTypes;
void verifyPublicListTypes;
void verifyRequestAuthorizationTypes;
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
}

function main() {
  if (npmConfigEnabled('legacy_peer_deps')) {
    throw new Error('Strict consumer test refuses enabled npm_config_legacy_peer_deps');
  }
  if (npmConfigEnabled('force')) {
    throw new Error('Strict consumer test refuses enabled npm_config_force');
  }

  const versions = parseVersions(process.argv.slice(2));
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-strict-consumer-'));
  try {
    run('npm', ['run', 'build']);
    const packEntries = JSON.parse(
      run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', tempDir], {
        capture: true,
      }),
    );
    const packedArtifact = packEntries[0];

    if (!packedArtifact?.filename || !packedArtifact.integrity || !packedArtifact.version) {
      throw new Error('npm pack --json did not report filename, version, and integrity');
    }

    const tarballPath = path.join(tempDir, packedArtifact.filename);
    const computedIntegrity = `sha512-${createHash('sha512')
      .update(fs.readFileSync(tarballPath))
      .digest('base64')}`;
    if (computedIntegrity !== packedArtifact.integrity) {
      throw new Error('npm pack integrity does not match the tarball bytes');
    }
    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-strict-consumer',
          private: true,
          version: '1.0.0',
          devDependencies: {
            '@types/node': '22.20.1',
            typescript: '5.9.3',
          },
          dependencies: {
            '@nestarc/api-keys': `file:${tarballPath}`,
            '@nestjs/common': versions.nest,
            '@nestjs/core': versions.nest,
            '@prisma/client': versions.prisma,
            'reflect-metadata': '0.2.2',
            rxjs: '7.8.2',
          },
        },
        null,
        2,
      )}\n`,
    );
    writeNestSmokeTest(consumerDir);
    writeTypeScriptConsumer(consumerDir);

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
      {
        cwd: consumerDir,
        env: strictNpmEnv(),
      },
    );
    run('npm', ['ls', '--depth=0'], { cwd: consumerDir });
    run(
      process.execPath,
      [path.join(consumerDir, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'],
      { cwd: consumerDir },
    );
    run(process.execPath, ['smoke.js'], { cwd: consumerDir });

    assertInstalledVersion(consumerDir, '@nestjs/common', versions.nest);
    assertInstalledVersion(consumerDir, '@nestjs/core', versions.nest);
    assertInstalledVersion(consumerDir, '@prisma/client', versions.prisma);

    const packageRoot = path.join(consumerDir, 'node_modules', '@nestarc', 'api-keys');
    const packedPackage = JSON.parse(
      fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'),
    );
    if (packedPackage.version !== packedArtifact.version) {
      throw new Error(
        `Packed version ${packedArtifact.version} installed as ${packedPackage.version}`,
      );
    }
    if (packedPackage.engines?.node !== EXPECTED_NODE_ENGINE) {
      throw new Error(`Packed engine metadata must be ${EXPECTED_NODE_ENGINE}`);
    }

    const consumerLock = JSON.parse(
      fs.readFileSync(path.join(consumerDir, 'package-lock.json'), 'utf8'),
    );
    const lockedArtifact = consumerLock.packages?.['node_modules/@nestarc/api-keys'];
    if (!lockedArtifact?.resolved?.startsWith('file:')) {
      throw new Error('Consumer lock does not identify API Keys as a file tarball');
    }
    if (lockedArtifact.version !== packedArtifact.version) {
      throw new Error('Consumer lock version does not match npm pack output');
    }
    if (lockedArtifact.integrity !== packedArtifact.integrity) {
      throw new Error('Consumer lock integrity does not match npm pack output');
    }
    if (packedPackage.peerDependencies['@nestjs/common'] !== EXPECTED_NEST_PEER) {
      throw new Error('Packed peer metadata does not declare the verified Nest 10/11 range');
    }
    if (packedPackage.peerDependencies['@nestjs/core'] !== EXPECTED_NEST_PEER) {
      throw new Error('Packed peer metadata does not declare the verified Nest 10/11 range');
    }
    if (packedPackage.peerDependencies['@prisma/client'] !== EXPECTED_PRISMA_PEER) {
      throw new Error('Packed peer metadata does not declare the verified Prisma 5/6/7 range');
    }
    if (!packedPackage.peerDependenciesMeta['@prisma/client']?.optional) {
      throw new Error('Packed @prisma/client peer must remain optional');
    }
    for (const example of [
      'prisma/schema.example.prisma',
      'prisma/schema.example.v7.prisma',
      'prisma/prisma.config.example.ts',
    ]) {
      if (!fs.existsSync(path.join(packageRoot, example))) {
        throw new Error(`Packed package is missing ${example}`);
      }
    }

    console.log(
      `Strict tarball consumer passed with Nest ${versions.nest} and Prisma ${versions.prisma}`,
    );
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
