const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolveConsumerCandidate } = require('./package-candidate');

const projectRoot = path.resolve(__dirname, '..');

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

function parseNestVersion(args) {
  if (args.length !== 2 || args[0] !== '--nest' || !/^\d+\.\d+\.\d+$/.test(args[1])) {
    throw new Error('Usage: test-http-consumer.js --nest <exact x.y.z version>');
  }
  return args[1];
}

function writeHttpSmoke(consumerDir) {
  fs.writeFileSync(
    path.join(consumerDir, 'http-smoke.js'),
    `require('reflect-metadata');
const { Controller, Get, Module, UseGuards } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const {
  ApiKeysGuard,
  ApiKeysModule,
  ApiKeysService,
  InMemoryApiKeyStorage,
  RequireEnvironment,
  RequireScope,
} = require('@nestarc/api-keys');

class AppController {
  auth() { return { ok: true }; }
  environment() { return { ok: true }; }
  scope() { return { ok: true }; }
  ip() { return { ok: true }; }
}

function decorateRoute(name, path, decorators = []) {
  const descriptor = Object.getOwnPropertyDescriptor(AppController.prototype, name);
  Get(path)(AppController.prototype, name, descriptor);
  for (const decorator of decorators) {
    decorator(AppController.prototype, name, descriptor);
  }
  UseGuards(ApiKeysGuard)(AppController.prototype, name, descriptor);
}

decorateRoute('auth', 'auth');
decorateRoute('environment', 'environment', [RequireEnvironment('test')]);
decorateRoute('scope', 'scope', [RequireScope('reports', 'write')]);
decorateRoute('ip', 'ip');
Controller()(AppController);

class AppModule {}
Module({
  imports: [
    ApiKeysModule.forRoot({
      namespace: 'http',
      peppers: { 1: 'http-consumer-pepper' },
      storage: new InMemoryApiKeyStorage(),
    }),
  ],
  controllers: [AppController],
})(AppModule);

function wrongSecret(rawKey) {
  return rawKey.slice(0, -1) + (rawKey.endsWith('a') ? 'b' : 'a');
}

async function main() {
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    const apiKeys = app.get(ApiKeysService);
    const active = await apiKeys.create({
      tenantId: 'tenant_http',
      name: 'active',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    const revoked = await apiKeys.create({
      tenantId: 'tenant_http',
      name: 'revoked',
      scopes: [{ resource: 'reports', level: 'read' }],
    });
    await apiKeys.revoke(revoked.id);
    const expired = await apiKeys.create({
      tenantId: 'tenant_http',
      name: 'expired',
      scopes: [{ resource: 'reports', level: 'read' }],
      expiresAt: new Date('2000-01-01T00:00:00.000Z'),
    });
    const ipRestricted = await apiKeys.create({
      tenantId: 'tenant_http',
      name: 'ip restricted',
      scopes: [{ resource: 'reports', level: 'write' }],
      allowedIpCidrs: ['203.0.113.0/24'],
    });

    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    if (!address || typeof address === 'string') {
      throw new Error('Nest HTTP server did not expose a TCP port');
    }
    const baseUrl = 'http://127.0.0.1:' + address.port;
    const unknown = 'http_live_' + 'z'.repeat(12) + '_' + 'z'.repeat(32);
    const tamperedEnvironment = active.key.replace('_live_', '_test_');
    const cases = [
      ['missing', '/auth', undefined, 401, 'api_key_missing'],
      ['malformed', '/auth', 'garbage', 401, 'api_key_malformed'],
      ['unknown', '/auth', unknown, 401, 'api_key_invalid'],
      ['tampered environment', '/auth', tamperedEnvironment, 401, 'api_key_invalid'],
      ['wrong secret on revoked prefix', '/auth', wrongSecret(revoked.key), 401, 'api_key_invalid'],
      ['revoked', '/auth', revoked.key, 401, 'api_key_revoked'],
      ['expired', '/auth', expired.key, 401, 'api_key_expired'],
      ['environment', '/environment', active.key, 403, 'api_key_environment_mismatch'],
      ['scope', '/scope', active.key, 403, 'api_key_scope_insufficient'],
      ['ip', '/ip', ipRestricted.key, 403, 'api_key_ip_not_allowed'],
    ];

    for (const [name, route, rawKey, expectedStatus, expectedCode] of cases) {
      const response = await fetch(baseUrl + route, {
        headers: rawKey ? { authorization: 'Bearer ' + rawKey } : {},
      });
      const body = await response.json();
      if (response.status !== expectedStatus) {
        throw new Error(name + ': expected HTTP ' + expectedStatus + ', received ' + response.status);
      }
      if (body.code !== expectedCode || body.statusCode !== expectedStatus) {
        throw new Error(name + ': unexpected body ' + JSON.stringify(body));
      }
      const keys = Object.keys(body).sort();
      if (keys.join(',') !== 'code,statusCode') {
        throw new Error(name + ': public body contains unexpected fields ' + keys.join(','));
      }
      const serialized = JSON.stringify(body).toLowerCase();
      for (const forbidden of ['reason', 'hash', 'pepper', 'stack']) {
        if (serialized.includes(forbidden)) {
          throw new Error(name + ': public body exposed ' + forbidden);
        }
      }
      if (rawKey && serialized.includes(rawKey.toLowerCase())) {
        throw new Error(name + ': public body exposed the raw API key');
      }
    }

    console.log('Nest HTTP default-filter contract passed');
  } finally {
    await app.close();
  }
}

main().catch((error) => {
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

function main() {
  const nestVersion = parseNestVersion(process.argv.slice(2));
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-http-consumer-'));
  try {
    const npmEnv = {
      ...process.env,
      npm_config_cache: path.join(tempDir, 'npm-cache'),
    };
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
          name: 'api-keys-http-consumer',
          private: true,
          version: '1.0.0',
          dependencies: {
            '@nestarc/api-keys': `file:${tarballPath}`,
            '@nestjs/common': nestVersion,
            '@nestjs/core': nestVersion,
            '@nestjs/platform-express': nestVersion,
            'reflect-metadata': '0.2.2',
            rxjs: '7.8.2',
          },
        },
        null,
        2,
      )}\n`,
    );
    writeHttpSmoke(consumerDir);

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
    for (const packageName of ['@nestjs/common', '@nestjs/core', '@nestjs/platform-express']) {
      const actual = installedVersion(consumerDir, packageName);
      if (actual !== nestVersion) {
        throw new Error(`Expected ${packageName}@${nestVersion}, installed ${actual}`);
      }
    }
    run(process.execPath, ['http-smoke.js'], { cwd: consumerDir });
    console.log(`HTTP tarball consumer passed with Nest ${nestVersion}`);
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
