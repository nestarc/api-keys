const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function git(projectRoot, args, allowStatusOne = false) {
  const result = spawnSync('git', args, {
    cwd: projectRoot,
    encoding: 'utf8',
    stdio: 'pipe',
  });
  if (allowStatusOne && result.status === 1) {
    return { matched: false, output: '' };
  }
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(' ')} failed with exit code ${result.status}: ${(result.stderr ?? '').trim()}`,
    );
  }
  return allowStatusOne
    ? { matched: true, output: (result.stdout ?? '').trim() }
    : (result.stdout ?? '').trim();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function verifyReleaseSource({ projectRoot, tag, commit, mainRef }) {
  if (!tag || !commit || !mainRef) {
    throw new Error('tag, commit, and mainRef are required');
  }

  const packageJson = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
  const version = packageJson.version;
  if (typeof version !== 'string' || !version) {
    throw new Error('package.json must contain a non-empty version');
  }
  if (tag !== `v${version}`) {
    throw new Error(`Tag ${tag} does not match package.json version ${version}`);
  }

  const resolvedCommit = git(projectRoot, ['rev-parse', `${commit}^{commit}`]);
  const tagCommit = git(projectRoot, ['rev-parse', `refs/tags/${tag}^{commit}`]);
  if (resolvedCommit !== tagCommit) {
    throw new Error(`Tag ${tag} resolves to ${tagCommit}, not workflow commit ${resolvedCommit}`);
  }

  git(projectRoot, ['rev-parse', '--verify', `${mainRef}^{commit}`]);
  const ancestry = git(projectRoot, ['merge-base', '--is-ancestor', resolvedCommit, mainRef], true);
  if (!ancestry.matched) {
    throw new Error(`Tag commit ${resolvedCommit} is not an ancestor of canonical main ${mainRef}`);
  }

  const changelog = fs.readFileSync(path.join(projectRoot, 'CHANGELOG.md'), 'utf8');
  const releaseHeading = new RegExp(
    `^## \\[${escapeRegExp(version)}\\] - \\d{4}-\\d{2}-\\d{2}$`,
    'm',
  );
  if (!releaseHeading.test(changelog)) {
    throw new Error(
      `CHANGELOG.md does not contain an exact "## [${version}] - YYYY-MM-DD" release heading`,
    );
  }

  return { tag, version, commit: resolvedCommit, mainRef };
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!['--tag', '--commit', '--main-ref'].includes(flag) || !value) {
      throw new Error(
        'Usage: verify-release-source.js --tag <vX.Y.Z> --commit <sha> --main-ref <ref>',
      );
    }
    options[flag.slice(2).replace('-', '')] = value;
  }
  return {
    tag: options.tag,
    commit: options.commit,
    mainRef: options.mainref,
  };
}

function main() {
  const result = verifyReleaseSource({
    projectRoot: path.resolve(__dirname, '..'),
    ...parseArgs(process.argv.slice(2)),
  });
  console.log(
    `Release source verified: ${result.tag} (${result.commit}) is on ${result.mainRef}; ` +
      `package.json and CHANGELOG.md agree on ${result.version}`,
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

module.exports = { verifyReleaseSource };
