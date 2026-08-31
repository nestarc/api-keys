const assert = require('node:assert/strict');

const { evaluateAuditReport } = require('./audit-policy');

function report(vulnerabilities = {}) {
  const totals = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  for (const vulnerability of Object.values(vulnerabilities)) {
    totals[vulnerability.severity] += 1;
    totals.total += 1;
  }
  return { vulnerabilities, metadata: { vulnerabilities: totals } };
}

const finding = {
  name: 'fixture-package',
  severity: 'high',
  isDirect: false,
  via: [
    {
      source: 123456,
      name: 'fixture-package',
      dependency: 'fixture-package',
      title: 'fixture advisory',
      url: 'https://github.com/advisories/GHSA-AAAA-BBBB-CCCC',
      severity: 'high',
    },
  ],
  effects: [],
  range: '<1.2.3',
  nodes: ['node_modules/fixture-package'],
  fixAvailable: false,
};

assert.doesNotThrow(() =>
  evaluateAuditReport(report(), { schemaVersion: 1, exceptions: [] }, '2026-08-31'),
);
assert.throws(
  () =>
    evaluateAuditReport(
      report({ 'fixture-package': finding }),
      { schemaVersion: 1, exceptions: [] },
      '2026-08-31',
    ),
  /unapproved dev audit advisory GHSA-AAAA-BBBB-CCCC/,
);
assert.doesNotThrow(() =>
  evaluateAuditReport(
    report({ 'fixture-package': finding }),
    {
      schemaVersion: 1,
      exceptions: [
        {
          id: 'GHSA-AAAA-BBBB-CCCC',
          package: 'fixture-package',
          expires: '2026-09-07',
          reason: 'fixture awaiting an upstream release',
        },
      ],
    },
    '2026-08-31',
  ),
);
assert.throws(
  () =>
    evaluateAuditReport(
      report({ 'fixture-package': finding }),
      {
        schemaVersion: 1,
        exceptions: [
          {
            id: 'GHSA-AAAA-BBBB-CCCC',
            package: 'fixture-package',
            expires: '2026-08-30',
            reason: 'expired fixture',
          },
        ],
      },
      '2026-08-31',
    ),
  /expired dev audit exception/,
);
assert.throws(
  () =>
    evaluateAuditReport(
      report({ 'fixture-package': finding }),
      { schemaVersion: 1, exceptions: [] },
      '2026-08-31',
      { production: true },
    ),
  /production audit must contain zero vulnerabilities/,
);

console.log('Dependency audit policy fixtures passed');
