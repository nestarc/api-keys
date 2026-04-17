/**
 * api-keys benchmark — measures authentication overhead and timing-safe property.
 *
 * Scenarios:
 *   A) Raw SHA-256 hash (baseline) — irreducible crypto floor
 *   B) Sha256Hasher.hash() — hasher wrapper overhead
 *   C) Sha256Hasher.verify() — hash + timing-safe compare
 *   D) ApiKeysService.verify() — HAPPY path (parse + lookup + hash + compare + context)
 *   E) ApiKeysService.verify() — INVALID key (should be close to D; validates timing-safe claim)
 *   F) create() + verify() round-trip — key-issuance throughput
 *
 * Key measurement: |D_p50 − E_p50| should be small (target: < 50µs). If the invalid
 * path is measurably faster than the happy path, an attacker can distinguish "key
 * exists" from "key doesn't exist" via response timing — which defeats the
 * timing-safe property this package claims.
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
}

// ── CLI args ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function flag(name: string, fallback: string): string {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
}
const ITERATIONS = Number(flag('iterations', '5000'));
const WARMUP = Number(flag('warmup', '500'));

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

  // Generate an invalid key with the same shape (exists-in-format but not in storage).
  const invalidKey = generateKey({ namespace: 'bench', environment: 'live' }).raw;

  // ── D) Service.verify() happy path ─────────────────────────────
  const happyStats = await measure(
    'D) ApiKeysService.verify()  — HAPPY path',
    async (i) => {
      await service.verify(validKeys[i % validKeys.length]);
    },
  );

  // ── E) Service.verify() invalid (not found) ────────────────────
  let caught = 0;
  const invalidStats = await measure(
    'E) ApiKeysService.verify()  — INVALID (not found)',
    async () => {
      try {
        await service.verify(invalidKey);
      } catch (err) {
        if (err instanceof ApiKeyError) caught += 1;
      }
    },
  );
  if (caught !== ITERATIONS + WARMUP) {
    console.error(`\n✗ expected ${ITERATIONS + WARMUP} ApiKeyError instances, got ${caught}`);
    process.exit(1);
  }

  // ── F) create() + verify() round-trip ──────────────────────────
  const roundTripStats = await measure(
    'F) create() + verify()  — round-trip',
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
  console.log(`  Service.verify() invalid-path (E, avg):           ~${fmt(invalidStats.avg)}`);
  console.log(`  Round-trip create+verify (F, avg):                ~${fmt(roundTripStats.avg)}`);
  console.log(`  Auth throughput (1/D.avg):                        ~${(1000 / happyStats.avg).toFixed(0)} verifications/sec per core`);

  // Timing-safe validation.
  const deltaP50 = Math.abs(happyStats.p50 - invalidStats.p50);
  const TIMING_THRESHOLD_MS = 0.05; // 50µs — tight enough to catch SHA-256 + one DB lookup worth of difference
  const deltaPct = (deltaP50 / happyStats.p50) * 100;

  console.log(`\n  Timing-safe check`);
  console.log(`  ──────────────────────────────────────────────────────`);
  console.log(`  |D − E| @ P50:                                   ${fmt(deltaP50)}  (${deltaPct.toFixed(1)}% of happy-path P50)`);
  console.log(`  Threshold:                                        ${fmt(TIMING_THRESHOLD_MS)}  (${((TIMING_THRESHOLD_MS / happyStats.p50) * 100).toFixed(1)}% of happy-path P50)`);

  if (deltaP50 > TIMING_THRESHOLD_MS) {
    console.error(`\n  ✗ FAIL — invalid-path latency diverges from happy-path by more than ${fmt(TIMING_THRESHOLD_MS)}.`);
    console.error(`       This suggests the dummyVerify() fallback is not compensating for the real hash.`);
    console.error(`       An attacker could distinguish "prefix exists" from "prefix missing" via timing.`);
    process.exit(1);
  }
  console.log(`  ✓ PASS — happy and invalid paths are within ${fmt(TIMING_THRESHOLD_MS)} at P50. Timing-safe property holds.`);

  console.log('\nDone.\n');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
