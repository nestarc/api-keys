const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const PRISMA_VERSIONS = ['5.22.0', '6.19.3', '7.10.0'];
const POSTGRES_LANES = [
  { postgres: '14', prisma: '5.22.0', role: 'PostgreSQL support boundary' },
  { postgres: '16', prisma: '5.22.0', role: 'Prisma 5 supported-major evidence' },
  { postgres: '16', prisma: '6.19.3', role: 'Prisma 6 supported-major evidence' },
  { postgres: '16', prisma: '7.10.0', role: 'Prisma 7 supported-major evidence' },
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

function assertDocker() {
  try {
    run('docker', ['info'], { capture: true });
  } catch (error) {
    throw new Error('The PostgreSQL compatibility matrix requires a running Docker daemon.', {
      cause: error,
    });
  }
}

function installPrismaRuntime(matrixRoot, version, npmCache) {
  const runtimeRoot = path.join(matrixRoot, `prisma-${version}`);
  const packages = [`prisma@${version}`, `@prisma/client@${version}`];
  if (version.startsWith('7.')) {
    packages.push(`@prisma/adapter-pg@${version}`);
  }

  console.log(`Installing exact Prisma runtime ${version}`);
  run(
    'npm',
    [
      'install',
      '--prefix',
      runtimeRoot,
      '--no-save',
      '--package-lock=false',
      '--no-audit',
      '--no-fund',
      ...packages,
    ],
    {
      env: {
        ...process.env,
        npm_config_cache: npmCache,
      },
    },
  );
  return runtimeRoot;
}

function main() {
  assertDocker();
  const matrixRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-postgres-matrix-'));

  try {
    const npmCache = path.join(matrixRoot, 'npm-cache');
    const runtimeRoots = new Map(
      PRISMA_VERSIONS.map((version) => [
        version,
        installPrismaRuntime(matrixRoot, version, npmCache),
      ]),
    );

    for (const lane of POSTGRES_LANES) {
      console.log(
        `Running ${lane.role}: Prisma ${lane.prisma} / PostgreSQL ${lane.postgres}`,
      );
      const env = {
        ...process.env,
        PRISMA_E2E_POSTGRES_IMAGE: `postgres:${lane.postgres}-alpine`,
        PRISMA_E2E_RUNTIME_ROOT: runtimeRoots.get(lane.prisma),
      };
      delete env.PRISMA_E2E_DATABASE_URL;
      run(process.execPath, [path.join(projectRoot, 'scripts/test-prisma-e2e.js')], { env });
    }

    console.log('PostgreSQL 14/16 and Prisma 5/6/7 compatibility matrix passed');
  } finally {
    fs.rmSync(matrixRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
