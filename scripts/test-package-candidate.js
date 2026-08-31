const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createCandidate, verifyCandidate } = require('./package-candidate');

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-package-candidate-'));
  const candidateDirectory = path.join(root, 'candidate');
  const tamperedDirectory = path.join(root, 'tampered');
  try {
    const created = createCandidate({ outputDirectory: candidateDirectory });
    const verified = verifyCandidate({ directory: candidateDirectory });
    assert.equal(verified.sha256, created.sha256);
    assert.equal(verified.integrity, created.integrity);
    assert.ok(verified.files.includes('dist/index.js'));
    assert.ok(verified.files.includes('dist/storage/storage-contract.d.ts'));
    assert.ok(verified.files.includes('dist/storage/storage-contract.js'));
    assert.ok(verified.files.includes('prisma/schema.example.v7.prisma'));
    assert.ok(verified.files.every((file) => !file.startsWith('src/')));
    assert.ok(verified.files.every((file) => !file.startsWith('test/')));

    fs.cpSync(candidateDirectory, tamperedDirectory, { recursive: true });
    const tamperedPath = path.join(tamperedDirectory, verified.filename);
    const bytes = fs.readFileSync(tamperedPath);
    bytes[bytes.length - 1] ^= 1;
    fs.writeFileSync(tamperedPath, bytes);
    assert.throws(
      () => verifyCandidate({ directory: tamperedDirectory }),
      /does not match the tarball bytes|incorrect (data|length) check|invalid distance/,
    );

    console.log('Release candidate allowlist and byte-identity fixtures passed');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
