const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const POLICY_PATH = path.resolve(__dirname, '..', '.github', 'audit-exceptions.json');

function vulnerabilityTotal(report) {
  const total = report?.metadata?.vulnerabilities?.total;
  if (!Number.isInteger(total) || total < 0) {
    throw new Error('npm audit report does not contain a valid vulnerability total');
  }
  return total;
}

function advisoryId(advisory) {
  const ghsa = advisory.url?.match(/\b(GHSA-[0-9A-Za-z-]+)\b/i)?.[1];
  return ghsa?.toUpperCase() ?? `npm:${advisory.source}`;
}

function auditAdvisories(report) {
  const advisories = new Map();
  for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vulnerability.via ?? []) {
      if (typeof via === 'string') continue;
      const finding = {
        id: advisoryId(via),
        package: via.name ?? via.dependency ?? vulnerability.name,
        severity: via.severity ?? vulnerability.severity,
      };
      advisories.set(`${finding.id}:${finding.package}`, finding);
    }
  }
  return [...advisories.values()];
}

function validatePolicy(policy, today) {
  if (policy?.schemaVersion !== 1 || !Array.isArray(policy.exceptions)) {
    throw new Error('audit exception policy must use schemaVersion 1 and an exceptions array');
  }

  const keys = new Set();
  for (const exception of policy.exceptions) {
    if (
      typeof exception.id !== 'string' ||
      typeof exception.package !== 'string' ||
      typeof exception.reason !== 'string' ||
      exception.reason.trim().length === 0 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(exception.expires ?? '')
    ) {
      throw new Error('each audit exception requires id, package, YYYY-MM-DD expires, and reason');
    }
    const key = `${exception.id}:${exception.package}`;
    if (keys.has(key)) throw new Error(`duplicate dev audit exception ${key}`);
    keys.add(key);
    if (exception.expires < today) {
      throw new Error(`expired dev audit exception ${key} (${exception.expires})`);
    }
  }
}

function evaluateAuditReport(report, policy, today, options = {}) {
  const total = vulnerabilityTotal(report);
  if (options.production) {
    if (total !== 0) {
      throw new Error(`production audit must contain zero vulnerabilities; received ${total}`);
    }
    return { total, advisories: [], unusedExceptions: [] };
  }

  validatePolicy(policy, today);
  const advisories = auditAdvisories(report);
  if (total > 0 && advisories.length === 0) {
    throw new Error('npm audit reported vulnerabilities without identifiable advisories');
  }

  const approved = new Map(
    policy.exceptions.map((exception) => [`${exception.id}:${exception.package}`, exception]),
  );
  for (const advisory of advisories) {
    const key = `${advisory.id}:${advisory.package}`;
    if (!approved.delete(key)) {
      throw new Error(
        `unapproved dev audit advisory ${advisory.id} for ${advisory.package} (${advisory.severity})`,
      );
    }
  }

  return { total, advisories, unusedExceptions: [...approved.keys()] };
}

function runNpmAudit(args) {
  const result = spawnSync('npm', ['audit', '--json', ...args], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error(`npm audit did not return JSON: ${result.stderr.trim() || 'no error output'}`);
  }
  if (report.error) {
    throw new Error(
      `npm audit failed: ${report.error.summary || report.error.message || report.message || 'unknown error'}`,
    );
  }
  return report;
}

function main() {
  const policy = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  const today = new Date().toISOString().slice(0, 10);
  const production = evaluateAuditReport(runNpmAudit(['--omit=dev']), policy, today, {
    production: true,
  });
  const development = evaluateAuditReport(runNpmAudit([]), policy, today);

  for (const unused of development.unusedExceptions) {
    console.warn(`Unused dev audit exception: ${unused}`);
  }
  console.log(
    `Dependency audit policy passed: production ${production.total}, full ${development.total}, active exceptions ${development.advisories.length}`,
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

module.exports = { evaluateAuditReport };
