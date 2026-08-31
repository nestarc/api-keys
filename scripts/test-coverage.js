const path = require('node:path');
const { spawnSync } = require('node:child_process');

const projectRoot = path.resolve(__dirname, '..');

function parseCoverageDirectory(args) {
  if (args.length === 0) {
    return 'coverage';
  }

  if (args.length === 1 && args[0].startsWith('--coverageDirectory=')) {
    const directory = args[0].slice('--coverageDirectory='.length);
    if (!directory) {
      throw new Error('--coverageDirectory must not be empty.');
    }
    return directory;
  }

  if (args.length === 2 && args[0] === '--coverageDirectory') {
    if (!args[1]) {
      throw new Error('--coverageDirectory must not be empty.');
    }
    return args[1];
  }

  throw new Error('Only --coverageDirectory=<path> is supported by the coverage runner.');
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    stdio: 'inherit',
  });

  if (result.error) {
    throw result.error;
  }

  return result.status ?? 1;
}

let coverageDirectory;
try {
  coverageDirectory = parseCoverageDirectory(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 2;
}

if (coverageDirectory) {
  const jestStatus = run(process.execPath, [
    require.resolve('jest/bin/jest'),
    '--ci',
    '--runInBand',
    '--coverage',
    `--coverageDirectory=${coverageDirectory}`,
  ]);

  if (jestStatus !== 0) {
    process.exitCode = jestStatus;
  } else {
    process.exitCode = run(process.execPath, [
      path.join(__dirname, 'check-coverage.js'),
      path.join(coverageDirectory, 'coverage-summary.json'),
    ]);
  }
}
