const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const prismaRuntimeRoot = path.resolve(process.env.PRISMA_E2E_RUNTIME_ROOT ?? projectRoot);
const DEFAULT_POSTGRES_IMAGE = 'postgres:16-alpine';
const TEST_DATABASE = 'api_keys_e2e';
const TEST_PASSWORD = 'postgres';
const TEST_USER = 'postgres';
const PRISMA_5_6_SCHEMA = 'prisma/schema.test.prisma';
const PRISMA_7_CONFIG = 'prisma/prisma.test.config.ts';
const PRISMA_7_SCHEMA = 'prisma/schema.test.v7.prisma';
const GENERATED_CLIENT = path.join(projectRoot, 'test/e2e/generated/prisma-client');

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

function packageVersion(name) {
  let entryPath;
  try {
    entryPath = require.resolve(`${name}/package.json`, {
      paths: [prismaRuntimeRoot],
    });
  } catch {
    entryPath = require.resolve(name, { paths: [prismaRuntimeRoot] });
  }

  let directory = path.dirname(entryPath);
  while (true) {
    const packageJson = path.join(directory, 'package.json');
    if (fs.existsSync(packageJson)) {
      const manifest = JSON.parse(fs.readFileSync(packageJson, 'utf8'));
      if (manifest.name === name && typeof manifest.version === 'string') {
        return manifest.version;
      }
    }

    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }

  throw new Error(`Unable to resolve installed version for ${name}`);
}

function prismaCliPath() {
  const packageJson = require.resolve('prisma/package.json', {
    paths: [prismaRuntimeRoot],
  });
  return path.join(path.dirname(packageJson), 'build', 'index.js');
}

function createPrisma7Config() {
  if (prismaRuntimeRoot === projectRoot) {
    return { path: PRISMA_7_CONFIG, cleanup: () => undefined };
  }

  const configPath = path.join(prismaRuntimeRoot, `.api-keys-prisma-${process.pid}.config.ts`);
  const schemaPath = path.join(projectRoot, PRISMA_7_SCHEMA);
  fs.writeFileSync(
    configPath,
    `import { defineConfig, env } from 'prisma/config';\n\n` +
      `export default defineConfig({\n` +
      `  schema: ${JSON.stringify(schemaPath)},\n` +
      `  datasource: { url: env('DATABASE_URL') },\n` +
      `});\n`,
  );
  return {
    path: configPath,
    cleanup: () => fs.rmSync(configPath, { force: true }),
  };
}

function createLegacySchema() {
  if (prismaRuntimeRoot === projectRoot) {
    return { path: PRISMA_5_6_SCHEMA, cleanup: () => undefined };
  }

  const sourceSchema = fs.readFileSync(path.join(projectRoot, PRISMA_5_6_SCHEMA), 'utf8');
  const outputPath = path.join(projectRoot, 'test/e2e/generated/prisma-client');
  const isolatedSchema = sourceSchema.replace(
    /output\s+=\s+"[^"]+"/,
    `output = ${JSON.stringify(outputPath)}`,
  );
  if (isolatedSchema === sourceSchema) {
    throw new Error('Could not rewrite the legacy Prisma client output path');
  }

  const schemaPath = path.join(prismaRuntimeRoot, `.api-keys-prisma-${process.pid}.schema.prisma`);
  fs.writeFileSync(schemaPath, isolatedSchema);
  return {
    path: schemaPath,
    cleanup: () => fs.rmSync(schemaPath, { force: true }),
  };
}

function resolvePrismaRuntime() {
  const cliVersion = packageVersion('prisma');
  const clientVersion = packageVersion('@prisma/client');
  const major = Number.parseInt(cliVersion.split('.')[0], 10);

  if (cliVersion !== clientVersion) {
    throw new Error(
      `Prisma CLI/client version mismatch: prisma ${cliVersion}, @prisma/client ${clientVersion}`,
    );
  }
  if (![5, 6, 7].includes(major)) {
    throw new Error(`Unsupported Prisma E2E major: ${cliVersion}`);
  }

  if (major === 7) {
    const adapterVersion = packageVersion('@prisma/adapter-pg');
    if (adapterVersion !== cliVersion) {
      throw new Error(
        `Prisma 7 adapter version mismatch: prisma ${cliVersion}, @prisma/adapter-pg ${adapterVersion}`,
      );
    }
  }

  console.log(
    `Testing Prisma CLI/client ${cliVersion}` +
      (major === 7 ? ' with the matching @prisma/adapter-pg' : ''),
  );
  return { major, version: cliVersion };
}

function postgresImage() {
  const image = process.env.PRISMA_E2E_POSTGRES_IMAGE ?? DEFAULT_POSTGRES_IMAGE;
  if (!/^postgres:(14|16)-alpine$/.test(image)) {
    throw new Error(
      'PRISMA_E2E_POSTGRES_IMAGE must be postgres:14-alpine or postgres:16-alpine',
    );
  }
  return image;
}

function startPostgres() {
  const image = postgresImage();
  const expectedMajor = image.match(/^postgres:(14|16)-alpine$/)[1];
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
    image,
  ]);

  const portOutput = run('docker', ['port', containerName, '5432/tcp'], { capture: true });
  const port = portOutput.match(/:(\d+)$/)?.[1];
  if (!port) {
    run('docker', ['stop', containerName]);
    throw new Error(`Could not determine the PostgreSQL port from: ${portOutput}`);
  }

  for (let attempt = 0; attempt < 60; attempt += 1) {
    const versionResult = spawnSync(
      'docker',
      [
        'exec',
        containerName,
        'psql',
        '--username',
        TEST_USER,
        '--dbname',
        TEST_DATABASE,
        '--tuples-only',
        '--no-align',
        '--command',
        'SHOW server_version_num',
      ],
      { encoding: 'utf8', stdio: 'pipe' },
    );
    if (versionResult.status === 0) {
      const serverVersionNumber = (versionResult.stdout ?? '').trim();
      if (!serverVersionNumber.startsWith(expectedMajor)) {
        run('docker', ['stop', containerName]);
        throw new Error(
          `Expected PostgreSQL ${expectedMajor}, received server_version_num ${serverVersionNumber}`,
        );
      }
      console.log(`Testing PostgreSQL ${expectedMajor} from ${image}`);
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
  const prismaRuntime = resolvePrismaRuntime();

  let container;
  let databaseUrl = process.env.PRISMA_E2E_DATABASE_URL;
  if (!databaseUrl) {
    container = startPostgres();
    databaseUrl = container.databaseUrl;
  }

  const env = {
    ...process.env,
    DATABASE_URL: databaseUrl,
    NODE_PATH: [path.join(prismaRuntimeRoot, 'node_modules'), process.env.NODE_PATH]
      .filter(Boolean)
      .join(path.delimiter),
    PRISMA_E2E_MAJOR: String(prismaRuntime.major),
    PRISMA_E2E_RUNTIME_ROOT: prismaRuntimeRoot,
    PRISMA_E2E_VERSION: prismaRuntime.version,
  };
  const prismaCli = prismaCliPath();
  const legacySchema = prismaRuntime.major < 7 ? createLegacySchema() : undefined;
  const prisma7Config = prismaRuntime.major === 7 ? createPrisma7Config() : undefined;

  try {
    fs.rmSync(GENERATED_CLIENT, { recursive: true, force: true });
    const schema = prismaRuntime.major === 7 ? PRISMA_7_SCHEMA : legacySchema.path;
    run(process.execPath, [prismaCli, 'generate', '--schema', schema], {
      env,
    });
    const dbPushArgs =
      prismaRuntime.major === 7
        ? [prismaCli, 'db', 'push', '--config', prisma7Config.path]
        : [prismaCli, 'db', 'push', '--schema', legacySchema.path, '--skip-generate'];
    run(process.execPath, dbPushArgs, { env });
    run(
      process.execPath,
      [require.resolve('jest/bin/jest'), '--config', 'test/e2e/jest.e2e.config.ts', '--runInBand'],
      { env },
    );
  } finally {
    legacySchema?.cleanup();
    prisma7Config?.cleanup();
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
