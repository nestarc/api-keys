const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const projectRoot = path.resolve(__dirname, '..');
const METADATA_FILENAME = 'release-candidate.json';
const REQUIRED_FILES = [
  'LICENSE',
  'README.md',
  'dist/index.d.ts',
  'dist/index.js',
  'package.json',
  'prisma/prisma.config.example.ts',
  'prisma/schema.example.prisma',
  'prisma/schema.example.v7.prisma',
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

function hash(buffer, algorithm, encoding) {
  return createHash(algorithm).update(buffer).digest(encoding);
}

function parseTar(buffer) {
  const archive = zlib.gunzipSync(buffer);
  const entries = [];
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const readString = (start, length) =>
      header
        .subarray(start, start + length)
        .toString('utf8')
        .replace(/\0.*$/s, '');
    const name = readString(0, 100);
    const prefix = readString(345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const sizeText = readString(124, 12).trim();
    const size = sizeText ? Number.parseInt(sizeText, 8) : 0;
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error(`Invalid tar entry size for ${fullName}`);
    }
    const type = String.fromCharCode(header[156] || 48);
    const contentStart = offset + 512;
    if (type === '0' || type === '\0') {
      entries.push({
        path: fullName,
        size,
        content: archive.subarray(contentStart, contentStart + size),
      });
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function packagePaths(entries) {
  return entries
    .map((entry) => entry.path)
    .filter((entryPath) => entryPath.startsWith('package/'))
    .map((entryPath) => entryPath.slice('package/'.length))
    .sort();
}

function verifyContentAllowlist(paths) {
  for (const file of paths) {
    const allowed =
      file === 'LICENSE' ||
      file === 'README.md' ||
      file === 'package.json' ||
      file.startsWith('dist/') ||
      [
        'prisma/prisma.config.example.ts',
        'prisma/schema.example.prisma',
        'prisma/schema.example.v7.prisma',
      ].includes(file);
    if (!allowed) {
      throw new Error(`Release candidate contains non-allowlisted file: ${file}`);
    }
  }
  for (const required of REQUIRED_FILES) {
    if (!paths.includes(required)) {
      throw new Error(`Release candidate is missing required file: ${required}`);
    }
  }
}

function inspectTarball(tarballPath) {
  const bytes = fs.readFileSync(tarballPath);
  const entries = parseTar(bytes);
  const paths = packagePaths(entries);
  verifyContentAllowlist(paths);
  const packageEntry = entries.find((entry) => entry.path === 'package/package.json');
  if (!packageEntry) {
    throw new Error('Release candidate does not contain package/package.json');
  }
  const packageJson = JSON.parse(packageEntry.content.toString('utf8'));
  return {
    bytes,
    packageJson,
    files: paths,
    size: bytes.length,
    sha256: hash(bytes, 'sha256', 'hex'),
    integrity: `sha512-${hash(bytes, 'sha512', 'base64')}`,
  };
}

function createCandidate({
  outputDirectory,
  cwd = projectRoot,
  env = process.env,
  cacheDirectory,
}) {
  fs.mkdirSync(outputDirectory, { recursive: true });
  const existing = fs
    .readdirSync(outputDirectory)
    .filter((name) => name === METADATA_FILENAME || name.endsWith('.tgz'));
  if (existing.length > 0) {
    throw new Error(`Candidate output directory is not empty: ${outputDirectory}`);
  }

  const packEnv = {
    ...env,
    npm_config_cache:
      cacheDirectory ?? path.join(path.dirname(outputDirectory), '.api-keys-npm-cache'),
    NPM_CONFIG_CACHE:
      cacheDirectory ?? path.join(path.dirname(outputDirectory), '.api-keys-npm-cache'),
  };
  const packEntries = JSON.parse(
    run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', outputDirectory], {
      cwd,
      capture: true,
      env: packEnv,
    }),
  );
  if (packEntries.length !== 1 || !packEntries[0]?.filename) {
    throw new Error('npm pack --json must report exactly one tarball');
  }
  const packed = packEntries[0];
  const tarballPath = path.join(outputDirectory, packed.filename);
  const inspected = inspectTarball(tarballPath);
  if (packed.integrity !== inspected.integrity) {
    throw new Error('npm pack integrity does not match the candidate tarball bytes');
  }
  if (
    packed.name !== inspected.packageJson.name ||
    packed.version !== inspected.packageJson.version
  ) {
    throw new Error('npm pack metadata does not match package/package.json');
  }

  const metadata = {
    formatVersion: 1,
    filename: packed.filename,
    name: packed.name,
    version: packed.version,
    size: inspected.size,
    sha256: inspected.sha256,
    integrity: inspected.integrity,
    files: inspected.files,
  };
  fs.writeFileSync(
    path.join(outputDirectory, METADATA_FILENAME),
    `${JSON.stringify(metadata, null, 2)}\n`,
  );
  return { ...metadata, tarballPath };
}

function verifyCandidate({ directory }) {
  const metadataPath = path.join(directory, METADATA_FILENAME);
  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  if (metadata.formatVersion !== 1 || path.basename(metadata.filename) !== metadata.filename) {
    throw new Error('Release candidate metadata has an unsupported format or unsafe filename');
  }
  const tarballs = fs.readdirSync(directory).filter((name) => name.endsWith('.tgz'));
  if (tarballs.length !== 1 || tarballs[0] !== metadata.filename) {
    throw new Error('Release candidate directory must contain exactly the metadata tarball');
  }
  const tarballPath = path.join(directory, metadata.filename);
  const inspected = inspectTarball(tarballPath);
  for (const field of ['name', 'version']) {
    if (metadata[field] !== inspected.packageJson[field]) {
      throw new Error(`Release candidate ${field} does not match package/package.json`);
    }
  }
  for (const field of ['size', 'sha256', 'integrity']) {
    if (metadata[field] !== inspected[field]) {
      throw new Error(`Release candidate ${field} does not match the tarball bytes`);
    }
  }
  if (JSON.stringify(metadata.files) !== JSON.stringify(inspected.files)) {
    throw new Error('Release candidate file manifest does not match the tarball contents');
  }
  return { ...metadata, tarballPath };
}

function resolveConsumerCandidate({ tempDirectory, cwd = projectRoot, env = process.env }) {
  const externalDirectory = env.API_KEYS_PACKAGE_CANDIDATE_DIR;
  if (externalDirectory) {
    return verifyCandidate({ directory: path.resolve(externalDirectory) });
  }
  run('npm', ['run', 'build'], { cwd, env });
  return createCandidate({ outputDirectory: tempDirectory, cwd, env });
}

function parseCli(args) {
  const command = args[0];
  const options = {};
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!['--directory', '--github-output'].includes(flag) || !value) {
      throw new Error(
        'Usage: package-candidate.js <create|verify> --directory <path> [--github-output <path>]',
      );
    }
    options[flag.slice(2).replace('-', '')] = value;
  }
  if (!['create', 'verify'].includes(command) || !options.directory) {
    throw new Error(
      'Usage: package-candidate.js <create|verify> --directory <path> [--github-output <path>]',
    );
  }
  return {
    command,
    directory: path.resolve(options.directory),
    githubOutput: options.githuboutput,
  };
}

function main() {
  const options = parseCli(process.argv.slice(2));
  const result =
    options.command === 'create'
      ? createCandidate({ outputDirectory: options.directory })
      : verifyCandidate({ directory: options.directory });
  if (options.githubOutput) {
    fs.appendFileSync(
      options.githubOutput,
      `tarball=${result.tarballPath}\nversion=${result.version}\nsha256=${result.sha256}\nintegrity=${result.integrity}\n`,
    );
  }
  console.log(
    `Release candidate ${options.command === 'create' ? 'created' : 'verified'}: ` +
      `${result.filename} sha256:${result.sha256} ${result.integrity}`,
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}

module.exports = {
  createCandidate,
  inspectTarball,
  resolveConsumerCandidate,
  verifyCandidate,
};
