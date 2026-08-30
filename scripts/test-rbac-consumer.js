const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const NEST_VERSION = '11.2.3';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? projectRoot,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit',
    env: {
      ...process.env,
      npm_config_force: 'false',
      npm_config_legacy_peer_deps: 'false',
      npm_config_strict_peer_deps: 'true',
    },
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

function parseRbacVersion(args) {
  if (args.length !== 2 || args[0] !== '--rbac' || !/^\d+\.\d+\.\d+$/.test(args[1])) {
    throw new Error('Usage: test-rbac-consumer.js --rbac <exact published x.y.z version>');
  }
  return args[1];
}

function writeSmokeTest(consumerDir) {
  fs.writeFileSync(
    path.join(consumerDir, 'smoke.js'),
    `require('reflect-metadata');
const { Reflector } = require('@nestjs/core');
const {
  ApiKeysGuard,
  ApiKeysService,
  InMemoryApiKeyStorage,
  Sha256Hasher,
} = require('@nestarc/api-keys');
const {
  Can,
  InMemoryRbacStorage,
  RbacGuard,
  RbacService,
} = require('@nestarc/rbac');
const { createApiKeySubjectResolver } = require('@nestarc/rbac/integrations/api-keys');

function executionContext(request, handler = () => undefined, controller = class {}) {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => handler,
    getClass: () => controller,
  };
}

async function resolveOrUndefined(resolver, context) {
  try {
    return await resolver(context);
  } catch {
    return undefined;
  }
}

(async () => {
  const tenantId = 'tenant café';
  const apiKeys = new ApiKeysService({
    storage: new InMemoryApiKeyStorage(),
    hasher: new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 }),
    namespace: 'packed',
    idFactory: () => 'key_exact',
  });
  const created = await apiKeys.create({
    tenantId,
    name: 'Packed RBAC consumer',
    scopes: [{ resource: 'reports', level: 'read' }],
  });
  const request = { headers: { authorization: 'Bearer ' + created.key } };
  const apiContext = executionContext(request);
  const apiGuard = new ApiKeysGuard(apiKeys, new Reflector());
  if ((await apiGuard.canActivate(apiContext)) !== true) {
    throw new Error('ApiKeysGuard did not accept the packed candidate key');
  }
  if (!request.apiKey || request.apiKey.tenantId !== tenantId) {
    throw new Error('ApiKeysGuard did not write the exact canonical request.apiKey tenant');
  }

  const resolver = createApiKeySubjectResolver();
  const canonical = await resolver(apiContext);
  if (canonical?.id !== created.id || canonical?.tenantId !== tenantId) {
    throw new Error('RBAC did not preserve the canonical request.apiKey identity');
  }

  request.apiKeyContext = { ...request.apiKey };
  const identicalLegacy = await resolver(apiContext);
  if (identicalLegacy?.id !== created.id || identicalLegacy?.tenantId !== tenantId) {
    throw new Error('RBAC rejected identical canonical and legacy API-key identities');
  }

  request.apiKeyContext = { ...request.apiKey, tenantId: 'tenant_attacker' };
  const conflictingLegacy = await resolveOrUndefined(resolver, apiContext);
  if (conflictingLegacy !== undefined && conflictingLegacy !== null) {
    throw new Error('RBAC resolved conflicting request.apiKeyContext instead of failing closed');
  }

  const legacyOnlyRequest = { apiKeyContext: { keyId: ' key_exact', tenantId: ' tenant_a' } };
  const repairedLegacy = await resolveOrUndefined(
    resolver,
    executionContext(legacyOnlyRequest),
  );
  if (repairedLegacy !== undefined && repairedLegacy !== null) {
    throw new Error('RBAC trimmed or coerced a non-canonical legacy API-key identity');
  }

  class ReportsController {
    read() {}
  }
  const descriptor = Object.getOwnPropertyDescriptor(ReportsController.prototype, 'read');
  Can('reports.read', { tenant: 'required' })(ReportsController.prototype, 'read', descriptor);
  const handler = ReportsController.prototype.read;
  const rbacStorage = new InMemoryRbacStorage();
  const subject = { type: 'api_key', id: created.id, tenantId };
  const role = await rbacStorage.upsertRole({
    tenantId,
    key: 'reader',
    permissions: ['reports.read'],
  });
  await rbacStorage.assignRole({ tenantId, subject, roleId: role.id });

  async function authorize(trustedTenantId) {
    const options = {
      storage: rbacStorage,
      subjectResolver: resolver,
      tenantResolver: () => trustedTenantId,
      tenant: { requiredByDefault: true },
    };
    const rbacGuard = new RbacGuard(
      new Reflector(),
      new RbacService(options),
      options,
      { get: () => { throw new Error('unexpected resource resolver'); } },
    );
    const guardedRequest = { ...request, apiKeyContext: { ...request.apiKey } };
    return rbacGuard.canActivate(
      executionContext(guardedRequest, handler, ReportsController),
    );
  }

  if ((await authorize(tenantId)) !== true) {
    throw new Error('RBAC rejected matching canonical and trusted tenant identities');
  }

  let mismatchDenied = false;
  try {
    await authorize('tenant_attacker');
  } catch {
    mismatchDenied = true;
  }
  if (!mismatchDenied) {
    throw new Error('RBAC authorized a canonical API-key/trusted-tenant mismatch');
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`,
  );
}

function main() {
  const rbacVersion = parseRbacVersion(process.argv.slice(2));
  const registry = JSON.parse(
    run(
      'npm',
      [
        'view',
        `@nestarc/rbac@${rbacVersion}`,
        'version',
        'gitHead',
        'dist.tarball',
        'dist.integrity',
        '--json',
      ],
      { capture: true },
    ),
  );
  const registryTarball = registry.dist?.tarball ?? registry['dist.tarball'];
  const registryIntegrity = registry.dist?.integrity ?? registry['dist.integrity'];
  if (
    registry.version !== rbacVersion ||
    typeof registry.gitHead !== 'string' ||
    typeof registryTarball !== 'string' ||
    typeof registryIntegrity !== 'string'
  ) {
    throw new Error('RBAC registry metadata is incomplete or does not match the exact version');
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-rbac-consumer-'));
  try {
    run('npm', ['run', 'build']);
    const [packedArtifact] = JSON.parse(
      run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', tempDir], {
        capture: true,
      }),
    );
    const tarballPath = path.join(tempDir, packedArtifact.filename);
    const computedIntegrity = `sha512-${createHash('sha512')
      .update(fs.readFileSync(tarballPath))
      .digest('base64')}`;
    if (computedIntegrity !== packedArtifact.integrity) {
      throw new Error('API Keys candidate integrity does not match its packed bytes');
    }

    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-rbac-consumer',
          private: true,
          version: '1.0.0',
          dependencies: {
            '@nestarc/api-keys': `file:${tarballPath}`,
            '@nestarc/rbac': rbacVersion,
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
    writeSmokeTest(consumerDir);
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
      { cwd: consumerDir },
    );
    run('npm', ['ls', '--depth=0'], { cwd: consumerDir });
    run(process.execPath, ['smoke.js'], { cwd: consumerDir });

    const lock = JSON.parse(fs.readFileSync(path.join(consumerDir, 'package-lock.json')));
    const lockedApiKeys = lock.packages?.['node_modules/@nestarc/api-keys'];
    const lockedRbac = lock.packages?.['node_modules/@nestarc/rbac'];
    if (
      lockedApiKeys?.version !== packedArtifact.version ||
      lockedApiKeys?.integrity !== packedArtifact.integrity ||
      !lockedApiKeys?.resolved?.startsWith('file:')
    ) {
      throw new Error('Consumer lock does not identify the exact API Keys candidate tarball');
    }
    if (
      lockedRbac?.version !== rbacVersion ||
      lockedRbac?.integrity !== registryIntegrity ||
      lockedRbac?.resolved !== registryTarball
    ) {
      throw new Error('Consumer lock does not identify the exact published RBAC artifact');
    }

    console.log(
      `Packed API Keys ${packedArtifact.version} passed with published RBAC ${rbacVersion} ` +
        `(${registry.gitHead}, ${registryIntegrity})`,
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
