const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

const projectRoot = path.resolve(__dirname, '..');
const jestRequire = createRequire(require.resolve('jest-config'));
const merge = jestRequire('deepmerge');
const { mergeConfig, normalize } = require('jest-config');

function payload() {
  return JSON.parse('{"__proto__":{"securityProbe":true}}');
}

function assertSafe(record) {
  assert.equal(Object.getPrototypeOf(record), Object.prototype);
  assert.equal(record.securityProbe, undefined);
  assert.equal(Object.hasOwn(record, '__proto__'), false);
  assert.equal({}.securityProbe, undefined);
}

async function main() {
  // Verify the replacement at the caller, not just by importing vendor/ directly.
  assert.equal(
    fs.readFileSync(jestRequire.resolve('deepmerge'), 'utf8'),
    fs.readFileSync(path.join(projectRoot, 'vendor/deepmerge/index.js'), 'utf8'),
  );

  assertSafe(merge(Object.create(null), payload()));
  assertSafe(merge(payload(), {}));
  assertSafe(merge(payload(), payload()));
  assertSafe(merge.all([payload(), {}]));
  assertSafe(merge({ records: [payload()] }, { records: [] }).records[0]);
  assertSafe(merge({ records: [] }, { records: [payload()] }).records[0]);
  for (const placeholder of [null, undefined, false, 0, 'value']) {
    assertSafe(merge({ session: placeholder }, { session: payload() }).session);
    assertSafe(mergeConfig({ session: placeholder }, { session: payload() }).session);
  }

  const symbol = Symbol('configuration');
  const target = { nested: { left: 1 }, records: [{ left: 1 }], [symbol]: { left: 1 } };
  const source = { nested: { right: 2 }, records: [{ right: 2 }], [symbol]: { right: 2 } };
  const merged = merge(target, source);
  assert.deepEqual(merged, {
    nested: { left: 1, right: 2 },
    records: [{ left: 1 }, { right: 2 }],
    [symbol]: { left: 1, right: 2 },
  });
  merged.nested.left = 3;
  merged.records[0].left = 3;
  assert.equal(target.nested.left, 1);
  assert.equal(target.records[0].left, 1);
  assert.deepEqual(source.records, [{ right: 2 }]);
  assert.deepEqual(merge.all([{ one: 1 }, { two: 2 }, { one: 3 }]), { one: 3, two: 2 });
  assert.deepEqual(merge.all([]), {});
  assert.throws(() => merge.all({}), /first argument should be an array/);
  assert.deepEqual(merge({ value: [] }, { value: { enabled: true } }), {
    value: { enabled: true },
  });
  const date = new Date('2026-01-01T00:00:00Z');
  const expression = /value/i;
  const special = merge({}, { date, expression });
  assert.equal(special.date, date);
  assert.equal(special.expression, expression);
  const shared = { value: true };
  assert.equal(merge({}, { shared }, { clone: false }).shared, shared);
  assert.deepEqual(merge([1], [2], { arrayMerge: (_target, input) => input }), [2]);
  assert.deepEqual(
    merge({ nested: { left: 1 } }, { nested: { right: 2 } }, {
      customMerge: (key) => key === 'nested' ? () => ({ custom: true }) : undefined,
    }),
    { nested: { custom: true } },
  );
  // These ordinary own properties are data, not prototype setters.
  const ordinary = JSON.parse('{"constructor":{"prototype":{"value":1}},"prototype":2}');
  assert.deepEqual(merge(ordinary, {}), ordinary);
  const inherited = Object.create({ inherited: true });
  inherited.own = true;
  assert.deepEqual(merge({}, inherited), { own: true });

  // Exercise Jest's second caller: merging globals supplied by a preset and config.
  const normalized = await normalize({
    rootDir: projectRoot,
    preset: path.join(__dirname, 'fixtures/deepmerge-preset.js'),
    globals: { session: payload(), features: ['config'] },
  }, {});
  assertSafe(normalized.options.globals.session);
  assert.deepEqual(normalized.options.globals.features, ['preset', 'config']);
  console.log('Patched deepmerge: poisoning regressions and Jest compatibility passed');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
