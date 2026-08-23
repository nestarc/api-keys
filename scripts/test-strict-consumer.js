const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? projectRoot,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit',
    env: process.env,
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
  return value === '1' || value === 'true';
}

function main() {
  if (enabled(process.env.npm_config_legacy_peer_deps)) {
    throw new Error('Strict consumer test refuses npm_config_legacy_peer_deps');
  }
  if (enabled(process.env.npm_config_force)) {
    throw new Error('Strict consumer test refuses npm_config_force');
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-strict-consumer-'));
  try {
    run('npm', ['run', 'build']);
    const tarballName = run(
      'npm',
      ['pack', '--ignore-scripts', '--silent', '--pack-destination', tempDir],
      { capture: true },
    )
      .split(/\r?\n/)
      .at(-1);

    if (!tarballName) {
      throw new Error('npm pack did not report a tarball name');
    }

    const tarballPath = path.join(tempDir, tarballName);
    const consumerDir = path.join(tempDir, 'consumer');
    fs.mkdirSync(consumerDir);
    fs.writeFileSync(
      path.join(consumerDir, 'package.json'),
      `${JSON.stringify(
        {
          name: 'api-keys-strict-consumer',
          private: true,
          version: '1.0.0',
          dependencies: {
            '@nestarc/api-keys': `file:${tarballPath}`,
            '@nestjs/common': '^10.0.0',
            '@nestjs/core': '^10.0.0',
            '@prisma/client': '6.19.3',
            'reflect-metadata': '^0.2.0',
            rxjs: '^7.0.0',
          },
        },
        null,
        2,
      )}\n`,
    );

    run('npm', ['install', '--no-audit', '--no-fund'], { cwd: consumerDir });
    run(
      process.execPath,
      [
        '-e',
        "const pkg = require('@nestarc/api-keys'); " +
          "if (typeof pkg.PrismaApiKeyStorage !== 'function') " +
          "throw new Error('PrismaApiKeyStorage is not exported');",
      ],
      { cwd: consumerDir },
    );

    const packedPackage = JSON.parse(
      fs.readFileSync(
        path.join(consumerDir, 'node_modules', '@nestarc', 'api-keys', 'package.json'),
        'utf8',
      ),
    );
    if (packedPackage.peerDependencies['@prisma/client'] !== '^5.0.0 || ^6.0.0') {
      throw new Error('Packed peer metadata does not declare the verified Prisma 5/6 range');
    }

    console.log('Strict tarball consumer install passed with @prisma/client 6.19.3');
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
