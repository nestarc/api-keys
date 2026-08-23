const { spawnSync } = require('node:child_process');
const path = require('node:path');

const POSTGRES_IMAGE = 'postgres:16-alpine';
const TEST_DATABASE = 'api_keys_e2e';
const TEST_PASSWORD = 'postgres';
const TEST_USER = 'postgres';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: path.resolve(__dirname, '..'),
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

function packageVersion(name) {
  return require(`${name}/package.json`).version;
}

function assertMatchingPrismaMajors() {
  const cliVersion = packageVersion('prisma');
  const clientVersion = packageVersion('@prisma/client');
  const cliMajor = cliVersion.split('.')[0];
  const clientMajor = clientVersion.split('.')[0];

  if (cliMajor !== clientMajor) {
    throw new Error(
      `Prisma CLI/client major mismatch: prisma ${cliVersion}, @prisma/client ${clientVersion}`,
    );
  }

  console.log(`Testing Prisma CLI ${cliVersion} with @prisma/client ${clientVersion}`);
}

function startPostgres() {
  const containerName = `api-keys-prisma-e2e-${process.pid}`;

  try {
    run('docker', ['info'], { capture: true });
  } catch (error) {
    throw new Error(
      'PRISMA_E2E_DATABASE_URL is not set and Docker is unavailable. ' +
        'Provide a disposable PostgreSQL database or start Docker.',
      { cause: error },
    );
  }

  run('docker', [
    'run',
    '--detach',
    '--rm',
    '--name',
    containerName,
    '--env',
    `POSTGRES_USER=${TEST_USER}`,
    '--env',
    `POSTGRES_PASSWORD=${TEST_PASSWORD}`,
    '--env',
    `POSTGRES_DB=${TEST_DATABASE}`,
    '--publish',
    '127.0.0.1::5432',
    POSTGRES_IMAGE,
  ]);

  const portOutput = run('docker', ['port', containerName, '5432/tcp'], { capture: true });
  const port = portOutput.match(/:(\d+)$/)?.[1];
  if (!port) {
    run('docker', ['stop', containerName]);
    throw new Error(`Could not determine the PostgreSQL port from: ${portOutput}`);
  }

  for (let attempt = 0; attempt < 60; attempt += 1) {
    const ready = spawnSync(
      'docker',
      ['exec', containerName, 'pg_isready', '--username', TEST_USER, '--dbname', TEST_DATABASE],
      { stdio: 'ignore' },
    );
    if (ready.status === 0) {
      return {
        containerName,
        databaseUrl: `postgresql://${TEST_USER}:${TEST_PASSWORD}@127.0.0.1:${port}/${TEST_DATABASE}?schema=public`,
      };
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }

  run('docker', ['stop', containerName]);
  throw new Error('PostgreSQL did not become ready within 30 seconds');
}

function main() {
  assertMatchingPrismaMajors();

  let container;
  let databaseUrl = process.env.PRISMA_E2E_DATABASE_URL;
  if (!databaseUrl) {
    container = startPostgres();
    databaseUrl = container.databaseUrl;
  }

  const env = { ...process.env, DATABASE_URL: databaseUrl };
  const prismaRoot = path.dirname(require.resolve('prisma/package.json'));
  const prismaCli = path.join(prismaRoot, 'build', 'index.js');

  try {
    run(process.execPath, [prismaCli, 'generate', '--schema', 'prisma/schema.test.prisma'], {
      env,
    });
    run(
      process.execPath,
      [prismaCli, 'db', 'push', '--schema', 'prisma/schema.test.prisma', '--skip-generate'],
      { env },
    );
    run(
      process.execPath,
      [require.resolve('jest/bin/jest'), '--config', 'test/e2e/jest.e2e.config.ts', '--runInBand'],
      { env },
    );
  } finally {
    if (container) {
      run('docker', ['stop', container.containerName]);
    }
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
