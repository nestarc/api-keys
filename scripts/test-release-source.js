const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyReleaseSource } = require('./verify-release-source');

function git(cwd, args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function writeReleaseFiles(directory, version, changelogVersion = version) {
  fs.writeFileSync(
    path.join(directory, 'package.json'),
    `${JSON.stringify({ name: '@nestarc/api-keys', version }, null, 2)}\n`,
  );
  fs.writeFileSync(
    path.join(directory, 'CHANGELOG.md'),
    `# Changelog\n\n## [Unreleased]\n\n## [${changelogVersion}] - 2026-08-31\n`,
  );
}

function createFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'api-keys-release-source-'));
  git(directory, ['init', '--initial-branch=main']);
  git(directory, ['config', 'user.name', 'Release Fixture']);
  git(directory, ['config', 'user.email', 'release-fixture@example.invalid']);
  writeReleaseFiles(directory, '1.2.3');
  git(directory, ['add', 'package.json', 'CHANGELOG.md']);
  git(directory, ['commit', '-m', 'release 1.2.3']);
  git(directory, ['tag', 'v1.2.3']);
  return directory;
}

function expectFailure(fn, pattern) {
  assert.throws(fn, pattern);
}

function main() {
  const success = createFixture();
  const outsideMain = createFixture();
  const packageMismatch = createFixture();
  const versionMismatch = createFixture();

  try {
    const successCommit = git(success, ['rev-parse', 'v1.2.3^{commit}']);
    const result = verifyReleaseSource({
      projectRoot: success,
      tag: 'v1.2.3',
      commit: successCommit,
      mainRef: 'main',
    });
    assert.equal(result.version, '1.2.3');
    assert.equal(result.commit, successCommit);

    git(outsideMain, ['checkout', '-b', 'release-only']);
    fs.writeFileSync(path.join(outsideMain, 'release-only.txt'), 'not on main\n');
    git(outsideMain, ['add', 'release-only.txt']);
    git(outsideMain, ['commit', '-m', 'release outside main']);
    git(outsideMain, ['tag', 'v1.2.4']);
    writeReleaseFiles(outsideMain, '1.2.4');
    git(outsideMain, ['add', 'package.json', 'CHANGELOG.md']);
    git(outsideMain, ['commit', '-m', 'version outside main']);
    git(outsideMain, ['tag', '--force', 'v1.2.4']);
    const outsideCommit = git(outsideMain, ['rev-parse', 'v1.2.4^{commit}']);
    expectFailure(
      () =>
        verifyReleaseSource({
          projectRoot: outsideMain,
          tag: 'v1.2.4',
          commit: outsideCommit,
          mainRef: 'main',
        }),
      /not an ancestor of canonical main/,
    );

    writeReleaseFiles(packageMismatch, '1.2.4', '1.2.3');
    expectFailure(
      () =>
        verifyReleaseSource({
          projectRoot: packageMismatch,
          tag: 'v1.2.3',
          commit: git(packageMismatch, ['rev-parse', 'v1.2.3^{commit}']),
          mainRef: 'main',
        }),
      /does not match package\.json version/,
    );

    writeReleaseFiles(versionMismatch, '1.2.3', '1.2.2');
    expectFailure(
      () =>
        verifyReleaseSource({
          projectRoot: versionMismatch,
          tag: 'v1.2.3',
          commit: git(versionMismatch, ['rev-parse', 'v1.2.3^{commit}']),
          mainRef: 'main',
        }),
      /CHANGELOG\.md does not contain/,
    );

    console.log('Release source ancestry and version fixtures passed');
  } finally {
    fs.rmSync(success, { recursive: true, force: true });
    fs.rmSync(outsideMain, { recursive: true, force: true });
    fs.rmSync(packageMismatch, { recursive: true, force: true });
    fs.rmSync(versionMismatch, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
