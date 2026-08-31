const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolveConsumerCandidate } = require('./package-candidate');

const projectRoot = path.resolve(__dirname, '..');
const NEST_VERSION = '11.2.3';

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

function writeConsumer(consumerDir) {
  fs.writeFileSync(
    path.join(consumerDir, 'consumer.ts'),
    `import {
  runApiKeyStorageContract,
  type ApiKeyRecord,
  type ApiKeyStorage,
  type ListApiKeysOptions,
  type RotateApiKeyStorageInput,
  type RotateApiKeyStorageResult,
  type TenantBoundRevokeApiKeyStorageInput,
  type TenantBoundRevokeApiKeyStorageResult,
  type TenantBoundRotateApiKeyStorageInput,
} from '@nestarc/api-keys';

function clone(record: ApiKeyRecord): ApiKeyRecord {
  return {
    ...record,
    scopes: [...record.scopes],
    allowedIpCidrs: [...(record.allowedIpCidrs ?? [])],
    lastUsedAt: record.lastUsedAt && new Date(record.lastUsedAt),
    expiresAt: record.expiresAt && new Date(record.expiresAt),
    revokedAt: record.revokedAt && new Date(record.revokedAt),
    rotatedAt: record.rotatedAt && new Date(record.rotatedAt),
    createdAt: new Date(record.createdAt),
  };
}

class ConsumerStorage implements ApiKeyStorage {
  private readonly records = new Map<string, ApiKeyRecord>();

  async insert(record: ApiKeyRecord): Promise<void> {
    if (this.records.has(record.id)) throw new Error('duplicate id');
    if ([...this.records.values()].some((item) => item.prefix === record.prefix)) {
      throw new Error('duplicate prefix');
    }
    this.records.set(record.id, clone(record));
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const record = this.records.get(id);
    return record ? clone(record) : null;
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    const record = [...this.records.values()].find((item) => item.prefix === prefix);
    return record ? clone(record) : null;
  }

  async listByTenant(
    tenantId: string,
    opts: ListApiKeysOptions = {},
  ): Promise<ApiKeyRecord[]> {
    return [...this.records.values()]
      .filter((record) => record.tenantId === tenantId)
      .filter((record) => opts.includeRevoked || record.revokedAt === null)
      .sort((left, right) => {
        const byCreatedAt = right.createdAt.getTime() - left.createdAt.getTime();
        return byCreatedAt || left.id.localeCompare(right.id);
      })
      .map(clone);
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    const record = this.required(id);
    record.revokedAt = new Date(at);
  }

  async revokeForTenant(
    input: TenantBoundRevokeApiKeyStorageInput,
  ): Promise<TenantBoundRevokeApiKeyStorageResult> {
    const record = this.records.get(input.keyId);
    if (!record || record.tenantId !== input.expectedTenantId) return 'not_found';
    record.revokedAt = new Date(input.revokedAt);
    return 'revoked';
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    const record = this.required(id);
    record.lastUsedAt = new Date(at);
  }

  async rotate(input: RotateApiKeyStorageInput): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatching(input);
  }

  async rotateForTenant(
    input: TenantBoundRotateApiKeyStorageInput,
  ): Promise<RotateApiKeyStorageResult> {
    return this.rotateMatching(input, input.expectedTenantId);
  }

  private rotateMatching(
    input: RotateApiKeyStorageInput,
    expectedTenantId?: string,
  ): RotateApiKeyStorageResult {
    const oldRecord = this.records.get(input.oldKeyId);
    if (
      !oldRecord ||
      (expectedTenantId !== undefined && oldRecord.tenantId !== expectedTenantId) ||
      (expectedTenantId !== undefined && input.newRecord.tenantId !== expectedTenantId) ||
      oldRecord.revokedAt !== null ||
      oldRecord.rotatedAt !== null ||
      oldRecord.replacedByKeyId !== null ||
      (oldRecord.expiresAt !== null && oldRecord.expiresAt <= input.rotatedAt)
    ) {
      return 'not_rotatable';
    }
    if (this.records.has(input.newRecord.id)) throw new Error('duplicate id');
    oldRecord.expiresAt = new Date(input.oldExpiresAt);
    oldRecord.rotatedAt = new Date(input.rotatedAt);
    oldRecord.replacedByKeyId = input.newRecord.id;
    this.records.set(input.newRecord.id, clone(input.newRecord));
    return 'rotated';
  }

  private required(id: string): ApiKeyRecord {
    const record = this.records.get(id);
    if (!record) throw new Error('not found');
    return record;
  }
}

void runApiKeyStorageContract({
  name: 'packed consumer adapter',
  createStorage: () => new ConsumerStorage(),
}).then((result) => {
  if (!result.checks.includes('rotation is exactly once under concurrency')) {
    throw new Error('atomic rotation check did not run');
  }
  console.log('Public storage contract passed ' + result.checks.length + ' checks');
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
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
          outDir: 'dist',
        },
        include: ['consumer.ts'],
      },
      null,
      2,
    )}\n`,
  );
}

function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-storage-contract-consumer-'));
  try {
    const npmEnv = strictNpmEnv(tempDir);
    const packedArtifact = resolveConsumerCandidate({ tempDirectory: tempDir, env: npmEnv });
    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-storage-contract-consumer',
          private: true,
          version: '1.0.0',
          devDependencies: { '@types/node': '22.20.1', typescript: '5.9.3' },
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
    writeConsumer(consumerDir);
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
    const lock = JSON.parse(fs.readFileSync(path.join(consumerDir, 'package-lock.json'), 'utf8'));
    if (Object.keys(lock.packages ?? {}).some((entry) => entry.includes('@prisma/client'))) {
      throw new Error('Storage contract consumer unexpectedly installed @prisma/client');
    }
    run(
      process.execPath,
      [path.join(consumerDir, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'],
      { cwd: consumerDir },
    );
    run(process.execPath, ['dist/consumer.js'], { cwd: consumerDir });
    console.log('Packed no-Prisma custom storage contract consumer passed');
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
