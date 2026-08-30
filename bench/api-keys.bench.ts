/**
 * api-keys benchmark — measures authentication overhead and timing-safe property.
 *
 * Scenarios:
 *   A) Raw SHA-256 hash (baseline) — irreducible crypto floor
 *   B) Sha256Hasher.hash() — hasher wrapper overhead
 *   C) Sha256Hasher.verify() — hash + timing-safe compare
 *   D) ApiKeysService.verify() — HAPPY path (parse + lookup + hash + compare + context)
 *   E) ApiKeysService.verify() — UNKNOWN prefix (dummy hash + compare)
 *   F) ApiKeysService.verify() — KNOWN prefix with wrong secret (real hash + compare)
 *   G) create() + verify() round-trip — key-issuance throughput
 *
 * Key measurement: |E_p50 − F_p50| is bounded (target: < 50µs). This is a noisy
 * wall-clock smoke benchmark, not a claim of perfectly identical latency. The
 * deterministic tests separately assert that both paths execute their intended
 * hash-and-compare work.
 *
 * Usage:
 *   npx ts-node bench/api-keys.bench.ts
 *   npx ts-node bench/api-keys.bench.ts --iterations 5000 --warmup 500
 */
import { createHash } from 'node:crypto';
import { ApiKeyError } from '../src/errors';
import { Sha256Hasher } from '../src/hasher';
import { generateKey } from '../src/key-format';
import { ApiKeysService } from '../src/api-keys.service';
import type { ApiKeyStorage } from '../src/storage/api-key-storage.interface';
import type { ApiKeyRecord } from '../src/types';

/**
 * Prefix-indexed storage that mirrors what a production Prisma adapter backed by
 * a UNIQUE INDEX(prefix) provides: O(1) lookup regardless of hit or miss. The
 * default `InMemoryApiKeyStorage` does a linear scan which makes miss paths
 * O(n) — that asymmetry would mask the service's real timing-safe behavior in
 * this benchmark. Use this adapter here so what we measure is the SERVICE's
 * timing characteristic, not the in-memory adapter's.
 */
class BalancedInMemoryStorage implements ApiKeyStorage {
  private readonly byId = new Map<string, ApiKeyRecord>();
  private readonly byPrefix = new Map<string, ApiKeyRecord>();

  async insert(record: ApiKeyRecord): Promise<void> {
    if (this.byPrefix.has(record.prefix)) {
      throw new Error(`duplicate prefix: ${record.prefix}`);
    }
    const snapshot = { ...record };
    this.byId.set(record.id, snapshot);
    this.byPrefix.set(record.prefix, snapshot);
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    const record = this.byPrefix.get(prefix);
    return record ? { ...record } : null;
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const record = this.byId.get(id);
    return record ? { ...record } : null;
  }

  async listByTenant(tenantId: string, opts: { includeRevoked?: boolean } = {}): Promise<ApiKeyRecord[]> {
    const out: ApiKeyRecord[] = [];
    for (const record of this.byId.values()) {
      if (record.tenantId !== tenantId) continue;
      if (!opts.includeRevoked && record.revokedAt !== null) continue;
      out.push({ ...record });
    }
    return out;
  }

  async markRevoked(id: string, at: Date): Promise<void> {
    const record = this.byId.get(id);
    if (!record) throw new Error(`not found: ${id}`);
    record.revokedAt = at;
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    const record = this.byId.get(id);
    if (!record) return;
    record.lastUsedAt = at;
  }

  async rotate(input: {
    oldKeyId: string;
    newRecord: ApiKeyRecord;
    oldExpiresAt: Date;
    rotatedAt: Date;
  }): Promise<void> {
    const oldRecord = this.byId.get(input.oldKeyId);
    if (!oldRecord) throw new Error(`not found: ${input.oldKeyId}`);
    if (this.byId.has(input.newRecord.id)) {
      throw new Error(`duplicate id: ${input.newRecord.id}`);
    }
    if (this.byPrefix.has(input.newRecord.prefix)) {
      throw new Error(`duplicate prefix: ${input.newRecord.prefix}`);
    }

    oldRecord.expiresAt = input.oldExpiresAt;
    oldRecord.rotatedAt = input.rotatedAt;
    oldRecord.replacedByKeyId = input.newRecord.id;

    const snapshot = { ...input.newRecord };
    this.byId.set(snapshot.id, snapshot);
    this.byPrefix.set(snapshot.prefix, snapshot);
  }
}

// ── CLI args ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function flag(name: string, fallback: string): string {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
}
const ITERATIONS = Number(flag('iterations', '5000'));
const WARMUP = Number(flag('warmup', '500'));
const TIMING_THRESHOLD_MS = Number(flag('timing-threshold-ms', '0.05'));

// ── Stats ─────────────────────────────────────────────────────────────
interface Stats {
  avg: number;
  p50: number;
  p95: number;
  p99: number;
}

function computeStats(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    avg: sum / sorted.length,
    p50: sorted[Math.floor(sorted.length * 0.5)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
    p99: sorted[Math.floor(sorted.length * 0.99)],
  };
}

function fmt(ms: number): string {
  return ms < 1 ? `${(ms * 1000).toFixed(1)}µs` : `${ms.toFixed(3)}ms`;
}

function printStats(label: string, stats: Stats): void {
  console.log(
    `  ${label.padEnd(52)} Avg ${fmt(stats.avg).padStart(9)}  P50 ${fmt(stats.p50).padStart(9)}  P95 ${fmt(stats.p95).padStart(9)}  P99 ${fmt(stats.p99).padStart(9)}`,
  );
}

// ── Runner ────────────────────────────────────────────────────────────
async function measure(
  label: string,
  fn: (i: number) => Promise<void> | void,
): Promise<Stats> {
  for (let i = 0; i < WARMUP; i++) {
    await fn(ITERATIONS + i);
  }
  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    await fn(i);
    samples.push(performance.now() - start);
  }
  const stats = computeStats(samples);
  printStats(label, stats);
  return stats;
}

// ── Main ──────────────────────────────────────────────────────────────
async function run() {
  console.log(`\napi-keys Benchmark`);
  console.log(`  iterations: ${ITERATIONS}, warmup: ${WARMUP}\n`);

  const PEPPER = 'x'.repeat(64);
  const hasher = new Sha256Hasher({ peppers: { 1: PEPPER }, currentVersion: 1 });

  // ── A) Raw SHA-256 baseline ────────────────────────────────────
  const rawSecret = 'a'.repeat(32);
  const rawStats = await measure('A) Raw crypto.createHash(sha256)  — baseline', () => {
    createHash('sha256').update(rawSecret + PEPPER).digest('hex');
  });

  // ── B) Sha256Hasher.hash() ─────────────────────────────────────
  const hashStats = await measure('B) Sha256Hasher.hash()', () => {
    hasher.hash(rawSecret);
  });

  // ── C) Sha256Hasher.verify() ───────────────────────────────────
  const preHashed = hasher.hash(rawSecret);
  const verifyHasherStats = await measure('C) Sha256Hasher.verify()  — hash + timing-safe', () => {
    hasher.verify(rawSecret, preHashed.hash, preHashed.pepperVersion);
  });

  // ── Service setup ──────────────────────────────────────────────
  // Prefix-indexed storage so lookup is O(1) on both hit and miss, matching
  // how a production Prisma adapter with UNIQUE INDEX(prefix) behaves. This
  // lets the bench isolate the SERVICE's timing-safe behavior from the
  // storage adapter's lookup cost.
  const storage = new BalancedInMemoryStorage();
  // Keep default debounceMs so scheduleTouch() short-circuits after the first call
  // per record — otherwise we pollute the happy-path measurement with a growing
  // microtask backlog of storage.touchLastUsed() writes.
  const service = new ApiKeysService({ storage, hasher, namespace: 'bench' });
  const tenantId = 'tenant_bench';

  // Pre-seed 1000 keys so the service runs against a realistic-sized set.
  const validKeys: string[] = [];
  const SEED_COUNT = 1000;
  for (let i = 0; i < SEED_COUNT; i++) {
    const { key } = await service.create({
      tenantId,
      name: `k-${i}`,
      scopes: [{ resource: 'bench', level: 'read' }],
    });
    validKeys.push(key);
  }

  // Generate an unknown-prefix key and a known-prefix key with a wrong secret.
  const unknownPrefixKey = generateKey({ namespace: 'bench', environment: 'live' }).raw;
  const knownPrefixWrongSecretKey = `${validKeys[0].slice(0, -1)}${
    validKeys[0].endsWith('a') ? 'b' : 'a'
  }`;

  // ── D) Service.verify() happy path ─────────────────────────────
  const happyStats = await measure(
    'D) ApiKeysService.verify()  — HAPPY path',
    async (i) => {
      await service.verify(validKeys[i % validKeys.length]);
    },
  );

  // ── E) Service.verify() unknown prefix ─────────────────────────
  let unknownCaught = 0;
  const unknownStats = await measure(
    'E) ApiKeysService.verify()  — UNKNOWN prefix',
    async () => {
      try {
        await service.verify(unknownPrefixKey);
      } catch (err) {
        if (err instanceof ApiKeyError) unknownCaught += 1;
      }
    },
  );
  if (unknownCaught !== ITERATIONS + WARMUP) {
    console.error(
      `\n✗ expected ${ITERATIONS + WARMUP} unknown-prefix ApiKeyError instances, got ${unknownCaught}`,
    );
    process.exit(1);
  }

  // ── F) Service.verify() known prefix, wrong secret ─────────────
  let knownCaught = 0;
  const knownInvalidStats = await measure(
    'F) ApiKeysService.verify()  — KNOWN prefix, wrong secret',
    async () => {
      try {
        await service.verify(knownPrefixWrongSecretKey);
      } catch (err) {
        if (err instanceof ApiKeyError) knownCaught += 1;
      }
    },
  );
  if (knownCaught !== ITERATIONS + WARMUP) {
    console.error(
      `\n✗ expected ${ITERATIONS + WARMUP} known-prefix ApiKeyError instances, got ${knownCaught}`,
    );
    process.exit(1);
  }

  // ── G) create() + verify() round-trip ──────────────────────────
  const roundTripStats = await measure(
    'G) create() + verify()  — round-trip',
    async (i) => {
      const { key } = await service.create({
        tenantId,
        name: `rt-${i}`,
        scopes: [{ resource: 'bench', level: 'read' }],
      });
      await service.verify(key);
    },
  );

  // ── Summary & correctness checks ───────────────────────────────
  console.log('\n  Summary');
  console.log(`  ──────────────────────────────────────────────────────`);

  const hasherOverhead = hashStats.avg - rawStats.avg;
  console.log(`  Hasher wrapper overhead (B − A):                  ~${fmt(hasherOverhead)}  (${((hasherOverhead / rawStats.avg) * 100).toFixed(1)}% of raw SHA-256)`);
  console.log(`  Service.verify() happy-path (D, avg):             ~${fmt(happyStats.avg)}`);
  console.log(`  Service.verify() unknown-prefix (E, avg):         ~${fmt(unknownStats.avg)}`);
  console.log(`  Service.verify() known-invalid (F, avg):          ~${fmt(knownInvalidStats.avg)}`);
  console.log(`  Round-trip create+verify (G, avg):                ~${fmt(roundTripStats.avg)}`);
  console.log(`  Auth throughput (1/D.avg):                        ~${(1000 / happyStats.avg).toFixed(0)} verifications/sec per core`);

  // Bounded timing validation. This smoke check does not claim identical wall-clock latency.
  const deltaP50 = Math.abs(unknownStats.p50 - knownInvalidStats.p50);
  const deltaPct = (deltaP50 / knownInvalidStats.p50) * 100;

  console.log(`\n  Timing-safe check`);
  console.log(`  ──────────────────────────────────────────────────────`);
  console.log(`  |E − F| @ P50:                                   ${fmt(deltaP50)}  (${deltaPct.toFixed(1)}% of known-invalid P50)`);
  console.log(`  Threshold:                                        ${fmt(TIMING_THRESHOLD_MS)}  (${((TIMING_THRESHOLD_MS / knownInvalidStats.p50) * 100).toFixed(1)}% of known-invalid P50)`);

  if (deltaP50 > TIMING_THRESHOLD_MS) {
    console.error(`\n  ✗ FAIL — unknown and known-invalid paths diverge by more than ${fmt(TIMING_THRESHOLD_MS)}.`);
    console.error(`       Inspect dummyVerify() and known-prefix hash/compare work before release.`);
    process.exit(1);
  }
  console.log(`  ✓ PASS — unknown and known-invalid paths are within ${fmt(TIMING_THRESHOLD_MS)} at P50.`);

  console.log('\nDone.\n');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
