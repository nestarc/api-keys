const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function requireMatch(source, pattern, message) {
  assert.match(source, pattern, message);
}

function jobBodies(workflow) {
  const jobsStart = workflow.indexOf('\njobs:\n');
  assert.notEqual(jobsStart, -1, 'workflow jobs block is missing');
  const jobsSource = workflow.slice(jobsStart + '\njobs:\n'.length);
  const matches = [...jobsSource.matchAll(/^  ([a-z][a-z0-9-]+):\n/gm)];

  return matches.map((match, index) => ({
    name: match[1],
    body: jobsSource.slice(
      match.index,
      index + 1 < matches.length ? matches[index + 1].index : undefined,
    ),
  }));
}

function assertWorkflowPolicy(name, workflow) {
  requireMatch(
    workflow,
    /^concurrency:\n  group: [^\n]+\n  cancel-in-progress: (?:true|false)$/m,
    `${name} concurrency policy is missing`,
  );

  for (const job of jobBodies(workflow)) {
    requireMatch(job.body, /^    timeout-minutes: \d+$/m, `${name} ${job.name} timeout is missing`);
  }

  const actionUses = [
    ...workflow.matchAll(/uses: (actions\/[a-z-]+)@([^\s#]+)(?:\s+#\s+(v\d+))?/g),
  ];
  assert.ok(actionUses.length > 0, `${name} has no first-party Actions references`);
  for (const [, action, ref, version] of actionUses) {
    assert.match(ref, /^[0-9a-f]{40}$/, `${name} ${action} must use a full commit SHA`);
    assert.match(version ?? '', /^v\d+$/, `${name} ${action} must retain a major-version comment`);
  }
}

function dependabotGroupBody(source, group) {
  const marker = `      ${group}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `Dependabot ${group} group is missing`);
  const remaining = source.slice(start + marker.length);
  const nextGroup = remaining.search(/^      [a-z][a-z0-9-]+:\n/m);
  return remaining.slice(0, nextGroup === -1 ? undefined : nextGroup);
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
  const dependabot = fs.readFileSync(
    path.resolve(__dirname, '..', '.github/dependabot.yml'),
    'utf8',
  );

  assertWorkflowPolicy('CI', ciWorkflow);
  assertWorkflowPolicy('release', workflow);

  const actionRefs = new Map();
  for (const source of [ciWorkflow, workflow]) {
    for (const [, action, ref] of source.matchAll(/uses: (actions\/[a-z-]+)@([0-9a-f]{40})/g)) {
      const previous = actionRefs.get(action);
      assert.ok(!previous || previous === ref, `${action} drifts between CI and release`);
      actionRefs.set(action, ref);
    }
  }

  for (const command of [
    'npm run test:release:source',
    'npm run test:release:candidate',
    'npm run test:release:workflow',
    'npm run test:audit-policy',
    'npm run audit:ci',
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
  requireMatch(
    workflow,
    /uses: actions\/upload-artifact@[0-9a-f]{40}\s+# v7/,
    'candidate upload is missing',
  );
  requireMatch(workflow, /name: release-candidate/, 'candidate artifact name is unstable');
  requireMatch(workflow, /retention-days: 1/, 'candidate retention must be intentionally short');

  for (const job of ['verify-http', 'verify-nest12', 'verify-packed-consumer', 'publish']) {
    const start = workflow.indexOf(`  ${job}:`);
    assert.notEqual(start, -1, `${job} job is missing`);
    const remaining = workflow.slice(start + 3);
    const nextJob = remaining.search(/\n  [a-z][a-z0-9-]+:\n/);
    const next = nextJob === -1 ? -1 : start + 3 + nextJob;
    const body = workflow.slice(start, next === -1 ? undefined : next);
    requireMatch(body, /prepare-release/, `${job} does not depend on the candidate job`);
    requireMatch(
      body,
      /uses: actions\/download-artifact@[0-9a-f]{40}\s+# v8/,
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
  requireMatch(
    workflow,
    /npm run audit:ci/,
    'release does not enforce the dependency audit policy',
  );

  const compatibilityContract = {
    name: 'PostgreSQL 14/16 and Prisma 5/6/7',
    command: 'npm run test:e2e:postgres-matrix',
  };
  for (const [name, source] of [
    ['CI', ciWorkflow],
    ['release', workflow],
  ]) {
    assert.equal(
      source.split(compatibilityContract.name).length - 1,
      1,
      `${name} must expose the exact PostgreSQL/Prisma compatibility job name once`,
    );
    assert.equal(
      source.split(compatibilityContract.command).length - 1,
      1,
      `${name} must run the exact PostgreSQL/Prisma compatibility command once`,
    );
    assert.equal(
      source.split('test:consumer:storage-contract').length - 1,
      1,
      `${name} must run the public storage contract packed consumer once`,
    );
    assert.equal(
      source.split('test:consumer:module-formats').length - 1,
      1,
      `${name} must run the CommonJS/native ESM packed consumer once`,
    );
  }

  for (const [name, source, jobName] of [
    ['CI', ciWorkflow, 'nest12-compatibility'],
    ['release', workflow, 'verify-nest12'],
  ]) {
    const job = jobBodies(source).find((candidate) => candidate.name === jobName);
    assert.ok(job, `${name} Nest 12 compatibility job is missing`);
    requireMatch(
      job.body,
      /node: \['22\.13\.0', '24'\]/,
      `${name} Nest 12 job must cover exact Node 22.13.0 and Node 24`,
    );
    requireMatch(
      job.body,
      /npm run test:consumer:strict:nest12/,
      `${name} Nest 12 strict consumer is missing`,
    );
    requireMatch(
      job.body,
      /npm run test:consumer:http:nest12/,
      `${name} Nest 12 HTTP consumer is missing`,
    );
  }

  const dependencyGroups = {
    'nest-trio': ['@nestjs/common', '@nestjs/core', '@nestjs/testing'],
    jest: ['jest', '@types/jest', 'ts-jest'],
    'eslint-typescript-eslint': ['eslint', '@eslint/js', '@typescript-eslint/*'],
  };
  for (const [group, dependencies] of Object.entries(dependencyGroups)) {
    const body = dependabotGroupBody(dependabot, group);
    requireMatch(
      body,
      /dependency-type: development/,
      `Dependabot ${group} must be development-only`,
    );
    requireMatch(
      body,
      /update-types: \['minor', 'patch'\]/,
      `Dependabot ${group} update types drifted`,
    );
    for (const dependency of dependencies) {
      assert.ok(body.includes(`- '${dependency}'`), `Dependabot ${group} omits ${dependency}`);
    }
  }

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
