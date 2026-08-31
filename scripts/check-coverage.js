const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const thresholds = require('../coverage-thresholds.json');
const metrics = ['statements', 'branches', 'functions', 'lines'];

function summaryEntry(summary, target) {
  if (target === 'global') {
    return summary.total;
  }

  const absoluteTarget = path.resolve(projectRoot, target);
  const directMatch = summary[absoluteTarget];
  if (directMatch) {
    return directMatch;
  }

  const normalizedTarget = absoluteTarget.split(path.sep).join('/');
  return Object.entries(summary).find(
    ([file]) => file.split(path.sep).join('/') === normalizedTarget,
  )?.[1];
}

function formatRows(results) {
  const lines = [
    'Coverage floor summary',
    '',
    'target | statements | branches | functions | lines',
    '--- | ---: | ---: | ---: | ---:',
  ];

  for (const result of results) {
    lines.push(
      `${result.target} | ${metrics
        .map((metric) => `${result.actual[metric]}% (floor ${result.floor[metric]}%)`)
        .join(' | ')}`,
    );
  }

  return `${lines.join('\n')}\n`;
}

function checkCoverage(summaryPath) {
  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  const targets = [['global', thresholds.global], ...Object.entries(thresholds.files)];
  const results = [];
  const failures = [];

  for (const [target, floor] of targets) {
    const entry = summaryEntry(summary, target);
    if (!entry) {
      failures.push(`${target}: coverage summary entry is missing`);
      continue;
    }

    const actual = Object.fromEntries(metrics.map((metric) => [metric, entry[metric].pct]));
    results.push({ target, actual, floor });

    for (const metric of metrics) {
      if (actual[metric] < floor[metric]) {
        failures.push(`${target} ${metric}: ${actual[metric]}% is below ${floor[metric]}%`);
      }
    }
  }

  const resultLabel = failures.length === 0 ? 'PASS' : 'FAIL';
  const failureDetails = failures.length === 0 ? '' : `\nFailures:\n- ${failures.join('\n- ')}\n`;
  const report = `${formatRows(results)}\nResult: ${resultLabel}\n${failureDetails}`;
  const reportPath = path.join(path.dirname(summaryPath), 'coverage-floor.txt');
  fs.writeFileSync(reportPath, report);
  process.stdout.write(report);

  if (failures.length > 0) {
    return false;
  }

  process.stdout.write('Coverage floor passed.\n');
  return true;
}

if (require.main === module) {
  const summaryPath = process.argv[2];
  if (!summaryPath) {
    process.stderr.write('Usage: node scripts/check-coverage.js <coverage-summary.json>\n');
    process.exitCode = 2;
  } else if (!checkCoverage(path.resolve(summaryPath))) {
    process.exitCode = 1;
  }
}

module.exports = { checkCoverage };
