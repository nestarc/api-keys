const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function requireMatch(source, pattern, message) {
  assert.match(source, pattern, message);
}

function main() {
  const ciWorkflow = fs.readFileSync(
    path.resolve(__dirname, '..', '.github/workflows/ci.yml'),
    'utf8',
  );
  const workflow = fs.readFileSync(
    path.resolve(__dirname, '..', '.github/workflows/release.yml'),
    'utf8',
  );

  for (const command of [
    'npm run test:release:source',
    'npm run test:release:candidate',
    'npm run test:release:workflow',
  ]) {
    assert.ok(ciWorkflow.includes(command), `source CI does not persistently run ${command}`);
  }

  requireMatch(workflow, /^permissions:\n  contents: read$/m, 'workflow must default to read-only');
  requireMatch(workflow, /^  prepare-release:\n/m, 'release candidate preparation job is missing');
  requireMatch(workflow, /fetch-depth: 0/, 'release checkout must include ancestry history');
  requireMatch(
    workflow,
    /refs\/heads\/main:refs\/remotes\/origin\/main/,
    'canonical origin/main fetch is missing',
  );
  requireMatch(workflow, /npm run release:verify-source/, 'source release contract is not run');
  requireMatch(
    workflow,
    /npm run release:prepare-candidate/,
    'release candidate is not packed once',
  );
  requireMatch(workflow, /uses: actions\/upload-artifact@v7/, 'candidate upload is missing');
  requireMatch(workflow, /name: release-candidate/, 'candidate artifact name is unstable');
  requireMatch(workflow, /retention-days: 1/, 'candidate retention must be intentionally short');

  for (const job of ['verify-http', 'verify-packed-consumer', 'publish']) {
    const start = workflow.indexOf(`  ${job}:`);
    assert.notEqual(start, -1, `${job} job is missing`);
    const remaining = workflow.slice(start + 3);
    const nextJob = remaining.search(/\n  [a-z][a-z0-9-]+:\n/);
    const next = nextJob === -1 ? -1 : start + 3 + nextJob;
    const body = workflow.slice(start, next === -1 ? undefined : next);
    requireMatch(body, /prepare-release/, `${job} does not depend on the candidate job`);
    requireMatch(
      body,
      /uses: actions\/download-artifact@v8/,
      `${job} does not download the exact candidate`,
    );
    assert.doesNotMatch(body, /npm pack/, `${job} must not repack the release candidate`);
    if (job === 'publish') {
      assert.doesNotMatch(body, /npm run build/, 'publish must not rebuild the release candidate');
    }
  }

  requireMatch(
    workflow,
    /API_KEYS_PACKAGE_CANDIDATE_DIR:/,
    'consumer jobs are not pinned to the downloaded candidate',
  );
  requireMatch(
    workflow,
    /npm run release:verify-candidate --[\s\S]*?--github-output/,
    'publish job does not verify candidate bytes and expose the exact tarball path',
  );
  requireMatch(
    workflow,
    /npm publish "\$\{\{ steps\.candidate\.outputs\.tarball \}\}"/,
    'publish must consume the verified tarball path',
  );
  requireMatch(workflow, /id-token: write/, 'trusted publishing OIDC permission is missing');
  requireMatch(workflow, /environment: npm/, 'trusted publishing environment is missing');

  const packCommands = workflow.match(/npm run release:prepare-candidate/g) ?? [];
  assert.equal(packCommands.length, 1, 'release workflow must prepare exactly one candidate');
  assert.doesNotMatch(
    workflow,
    /run: npm publish --access/,
    'publish job still rebuilds a package from the checkout',
  );

  console.log('Release workflow pack-once command graph passed');
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
