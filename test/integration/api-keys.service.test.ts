import { ApiKeysService } from '../../src/api-keys.service';
import { Sha256Hasher } from '../../src/hasher';
import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';

function svc() {
  const storage = new InMemoryApiKeyStorage();
  const hasher = new Sha256Hasher({ peppers: { 1: 'p'.repeat(32) }, currentVersion: 1 });
  const service = new ApiKeysService({
    storage,
    hasher,
    namespace: 'nk',
    idFactory: (() => {
      let counter = 0;
      return () => `key_${++counter}`;
    })(),
    clock: () => new Date('2026-01-01T00:00:00Z'),
    debounceMs: 60_000,
  });

  return { service, storage };
}

describe('ApiKeysService.create', () => {
  it('returns a key and stores a hashed record', async () => {
    const { service, storage } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'primary',
      scopes: [{ resource: 'invoices', level: 'write' }],
    });

    expect(result.key).toMatch(/^nk_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}$/);

    const stored = (await storage.listByTenant('t1'))[0];
    expect(stored.name).toBe('primary');
    expect(stored.hash).not.toContain(result.key);
    expect(stored.scopes).toEqual(['invoices:write']);
    expect(stored.environment).toBe('live');
  });

  it('defaults environment to live', async () => {
    const { service } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    expect(result.key.split('_')[1]).toBe('live');
  });

  it('supports test environment', async () => {
    const { service } = svc();

    const result = await service.create({
      tenantId: 't1',
      name: 'x',
      environment: 'test',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    expect(result.key.split('_')[1]).toBe('test');
  });

  it('rejects empty scopes', async () => {
    const { service } = svc();

    await expect(service.create({ tenantId: 't1', name: 'x', scopes: [] })).rejects.toThrow(
      /at least one scope/,
    );
  });
});

describe('ApiKeysService.verify', () => {
  it('returns context for a valid key', async () => {
    const { service } = svc();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'invoices', level: 'write' }],
    });

    const context = await service.verify(key);

    expect(context.tenantId).toBe('t1');
    expect(context.scopes).toEqual(['invoices:write']);
    expect(context.environment).toBe('live');
  });

  it('throws api_key_invalid for wrong secret', async () => {
    const { service } = svc();
    const { key } = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    const tampered = key.slice(0, -1) + (key.at(-1) === 'a' ? 'b' : 'a');

    await expect(service.verify(tampered)).rejects.toMatchObject({ code: 'api_key_invalid' });
  });

  it('throws api_key_invalid for unknown prefix', async () => {
    const { service } = svc();
    const fake = `nk_live_${'z'.repeat(12)}_${'z'.repeat(32)}`;

    await expect(service.verify(fake)).rejects.toMatchObject({ code: 'api_key_invalid' });
  });

  it('throws api_key_malformed for garbage input', async () => {
    const { service } = svc();

    await expect(service.verify('garbage')).rejects.toMatchObject({
      code: 'api_key_malformed',
    });
  });

  it('throws api_key_revoked for revoked keys', async () => {
    const { service } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.revoke(created.id);

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: 'api_key_revoked',
    });
  });

  it('throws api_key_expired for expired keys', async () => {
    const { service, storage } = svc();
    const created = await service.create({
      tenantId: 't1',
      name: 'x',
      scopes: [{ resource: 'r', level: 'read' }],
      expiresAt: new Date('2025-01-01T00:00:00Z'),
    });

    const record = (await storage.listByTenant('t1'))[0];
    expect(record.expiresAt?.getTime()).toBeLessThan(new Date('2026-01-01').getTime());

    await expect(service.verify(created.key)).rejects.toMatchObject({
      code: 'api_key_expired',
    });
  });
});

describe('ApiKeysService.list and revoke', () => {
  it('list excludes revoked by default', async () => {
    const { service } = svc();
    const first = await service.create({
      tenantId: 't1',
      name: 'a',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.create({
      tenantId: 't1',
      name: 'b',
      scopes: [{ resource: 'r', level: 'read' }],
    });

    await service.revoke(first.id);

    const listed = await service.list('t1');
    expect(listed.map((record) => record.name)).toEqual(['b']);
  });
});
